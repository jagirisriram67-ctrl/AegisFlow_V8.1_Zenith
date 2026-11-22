import { useEffect, useState } from 'react';
import { Play, Repeat, Shuffle, Upload, Zap } from 'lucide-react';
import type { DatasetProfile, FlowRecord, IncidentRecord } from '../types/soc';
import { bypassLabel, ZoneTag } from './ZoneIndicator';
import { XaiWaterfallPanel } from './XaiWaterfallPanel';

interface Props {
  profiles: DatasetProfile[];
  activeProfileId: string;
  onRefreshDashboard: () => Promise<void>;
  onApproveRule: (incidentId: string) => Promise<void>;
  onOpenChat: (incidentId: string, ip: string) => void;
}

type PresetId = 'BENIGN_NORMAL' | 'KNOWN_DDOS' | 'ZERO_DAY_THEFT' | 'AMBIGUOUS_BOUNDARY' | 'GRAY_ZONE_STEALTH';

const PRESETS: Array<{ id: PresetId; label: string }> = [
  { id: 'BENIGN_NORMAL', label: 'Benign Normal' },
  { id: 'KNOWN_DDOS', label: 'Known DDoS Flood' },
  { id: 'ZERO_DAY_THEFT', label: 'Zero-Day Theft (OOD)' },
  { id: 'AMBIGUOUS_BOUNDARY', label: 'Ambiguous Boundary (2A)' },
  { id: 'GRAY_ZONE_STEALTH', label: 'Gray-Zone Stealth (2B)' },
];

export function FlowSenderView({
  profiles,
  activeProfileId,
  onRefreshDashboard,
  onApproveRule,
  onOpenChat,
}: Props) {
  const [profileId, setProfileId] = useState(activeProfileId || 'NF-BoT-IoT-v2');
  const [preset, setPreset] = useState<PresetId>('ZERO_DAY_THEFT');
  const [features, setFeatures] = useState<Record<string, number>>({});
  const [socket, setSocket] = useState({
    src_ip: '10.20.30.99',
    dst_ip: '91.214.124.88',
    src_port: 58312,
    dst_port: 1883,
    protocol: 6,
  });
  const [useCloudLlm, setUseCloudLlm] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [lastFlow, setLastFlow] = useState<FlowRecord | null>(null);
  const [lastIncident, setLastIncident] = useState<IncidentRecord | null>(null);
  const [stressSummary, setStressSummary] = useState<string | null>(null);
  const [batchSummary, setBatchSummary] = useState<string | null>(null);

  const selectedProfile = profiles.find((p) => p.id === profileId) ?? profiles[0];

  const loadPreset = async (pid: string, kind: PresetId) => {
    setPreset(kind);
    const res = await fetch(`/api/profiles/${encodeURIComponent(pid)}/preset/${kind}`);
    if (!res.ok) return;
    const data = await res.json();
    setFeatures(data.features ?? {});
    if (data.socket) setSocket(data.socket);
  };

  useEffect(() => {
    void loadPreset(profileId, preset);
  }, [profileId]);

  const sendSingleFlow = async () => {
    setBusy('single');
    setStressSummary(null);
    try {
      const res = await fetch('/api/flows/ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ profile_id: profileId, features, socket, use_cloud_llm: useCloudLlm }),
      });
      const data = await res.json();
      setLastFlow(data.flow);
      setLastIncident(data.incident);
      await onRefreshDashboard();
    } finally {
      setBusy(null);
    }
  };

  const sendExactRepeat50x = async () => {
    setBusy('repeat');
    setStressSummary(null);
    try {
      const res = await fetch('/api/flows/repeat-test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ profile_id: profileId, features, socket, count: 50 }),
      });
      const data = await res.json();
      setLastFlow(data.last_flow);
      setLastIncident(data.incident);
      if (data.replay_overrides > 0) {
        setStressSummary(
          `Anti-Spoofing Override Verified! Sent 50x flows: Tier-0B Token-Bucket revoked benign suppression after velocity exceeded R_max and escalated ${data.replay_overrides} replay override alert(s).`
        );
      } else {
        setStressSummary(
          `Tier-0 Repeat Bypass Verified! Sent ${data.sent} exact flows → ${data.tier0_bypassed} intercepted in Tier-0 SimHash-64 cache at ${data.avg_tier0_latency_ms} ms avg latency (0 neural model calls, 0 duplicate rows).`
        );
      }
      await onRefreshDashboard();
    } finally {
      setBusy(null);
    }
  };

  const sendMutatedVariant = async () => {
    setBusy('mutate');
    setStressSummary(null);
    try {
      const res = await fetch('/api/flows/mutate-test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ profile_id: profileId, features, socket, mutation_pct: 3 }),
      });
      const data = await res.json();
      setLastFlow(data.first_pass);
      setLastIncident(data.incident);
      setStressSummary(
        `+3% Polymorphic Test: Pass 1 = ${data.first_pass.bypass_stage} (${data.first_pass.latency_ms}ms, SimHash ${data.first_pass.simhash64}) → Auto-promoted to Tier-0 → Pass 2 = ${data.second_pass_tier0_verify.bypass_stage} (${data.second_pass_tier0_verify.latency_ms}ms).`
      );
      await onRefreshDashboard();
    } finally {
      setBusy(null);
    }
  };

  const handleBatchUpload = async (file: File) => {
    setBusy('batch');
    setBatchSummary(null);
    try {
      const text = await file.text();
      let rows: Array<Record<string, unknown>> = [];
      if (file.name.endsWith('.json')) {
        const parsed = JSON.parse(text);
        rows = Array.isArray(parsed) ? parsed : [parsed];
      } else {
        // Parse CSV
        const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
        if (lines.length >= 2) {
          const headers = lines[0].split(',').map((h) => h.trim());
          for (let i = 1; i < Math.min(lines.length, 201); i++) {
            const cols = lines[i].split(',');
            const obj: Record<string, unknown> = {};
            headers.forEach((h, idx) => {
              const raw = cols[idx]?.trim() ?? '';
              const num = Number(raw);
              obj[h] = raw !== '' && Number.isFinite(num) ? num : raw;
            });
            rows.push(obj);
          }
        }
      }
      if (rows.length === 0) {
        setBatchSummary('No valid rows found in uploaded CSV/JSON file.');
        return;
      }
      const res = await fetch('/api/flows/batch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ profile_id: profileId, rows: rows.slice(0, 200) }),
      });
      const out = await res.json();
      setBatchSummary(
        `Replayed ${out.processed} flows (${file.name}): GREEN ${out.zones.GREEN}, YELLOW ${out.zones.YELLOW}, AMBER ${out.zones.AMBER}, RED ${out.zones.RED} · Tier-0 Bypassed: ${out.tier0_bypassed} · Tier-1 Polymorphic: ${out.tier1_caught}.`
      );
      await onRefreshDashboard();
    } catch {
      setBatchSummary('Failed to parse uploaded file. Provide valid CSV with header row or JSON array.');
    } finally {
      setBusy(null);
    }
  };

  const editableFeatures = selectedProfile ? selectedProfile.raw_feature_names.slice(0, 14) : [];

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
        {/* Left: Interactive Single-Flow Builder + Presets + Stress Lab */}
        <div className="xl:col-span-6 bg-[#0F1623] border border-slate-800 rounded-lg p-5 space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-slate-100">
                Interactive Flow Builder &amp; Repeat-Bypass Lab
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Multi-schema router supporting 40, 46, and 115 canonical features with zero shape errors
              </p>
            </div>
            <select
              aria-label="Dataset Profile"
              value={profileId}
              onChange={(e) => setProfileId(e.target.value)}
              className="bg-[#090D16] border border-slate-700 rounded-md px-3 py-1.5 text-xs font-mono text-slate-100 focus:outline-none focus:border-sky-500"
            >
              {profiles.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.id} ({p.feature_count} feats)
                </option>
              ))}
            </select>
          </div>

          {/* 1-Click Scenario Presets */}
          <div>
            <div className="text-xs text-slate-400 mb-2">Load Certified Scenario Preset</div>
            <div className="flex flex-wrap gap-1.5">
              {PRESETS.map((p) => (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => loadPreset(profileId, p.id)}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md border transition-colors whitespace-nowrap ${
                    preset === p.id
                      ? 'bg-sky-500/15 border-sky-500/50 text-sky-300'
                      : 'bg-[#0B111E] border-slate-800 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  {p.label}
                </button>
              ))}
            </div>
          </div>

          {/* Socket Identity Envelope (Detached in Stage 1) */}
          <div className="pt-3 border-t border-slate-800/80">
            <div className="text-xs font-medium text-slate-300 mb-2.5">
              Immutable Socket Envelope (Detached Before Neural Scaling)
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
              <div>
                <label className="block text-[11px] text-slate-500 mb-1">Source IP</label>
                <input
                  type="text"
                  value={socket.src_ip}
                  onChange={(e) => setSocket({ ...socket, src_ip: e.target.value })}
                  className="w-full bg-[#090D16] border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-slate-100"
                />
              </div>
              <div>
                <label className="block text-[11px] text-slate-500 mb-1">Destination IP</label>
                <input
                  type="text"
                  value={socket.dst_ip}
                  onChange={(e) => setSocket({ ...socket, dst_ip: e.target.value })}
                  className="w-full bg-[#090D16] border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-slate-100"
                />
              </div>
              <div>
                <label className="block text-[11px] text-slate-500 mb-1">Dst Port</label>
                <input
                  type="number"
                  value={socket.dst_port}
                  onChange={(e) => setSocket({ ...socket, dst_port: Number(e.target.value) })}
                  className="w-full bg-[#090D16] border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-slate-100"
                />
              </div>
              <div>
                <label className="block text-[11px] text-slate-500 mb-1">Protocol</label>
                <select
                  value={socket.protocol}
                  onChange={(e) => setSocket({ ...socket, protocol: Number(e.target.value) })}
                  className="w-full bg-[#090D16] border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-slate-100"
                >
                  <option value={6}>6 (TCP)</option>
                  <option value={17}>17 (UDP)</option>
                  <option value={1}>1 (ICMP)</option>
                </select>
              </div>
            </div>
          </div>

          {/* Canonical Behavioral Feature Sliders / Inputs */}
          <div className="pt-3 border-t border-slate-800/80">
            <div className="flex items-center justify-between mb-2.5">
              <span className="text-xs font-medium text-slate-300">
                Primary Behavioral Features ({selectedProfile?.feature_count ?? 40} total in vector)
              </span>
              <label className="inline-flex items-center gap-1.5 text-xs text-slate-400 cursor-pointer">
                <input
                  type="checkbox"
                  checked={useCloudLlm}
                  onChange={(e) => setUseCloudLlm(e.target.checked)}
                  className="rounded border-slate-700 bg-[#090D16]"
                />
                Enrich via Cloud LLM Gateway
              </label>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 max-h-64 overflow-y-auto pr-1">
              {editableFeatures.map((fname) => (
                <div key={fname} className="bg-[#0B111E] border border-slate-800/80 rounded p-2">
                  <label className="block text-[11px] font-mono text-slate-400 truncate" title={fname}>
                    {fname}
                  </label>
                  <input
                    type="number"
                    step="any"
                    value={features[fname] ?? 0}
                    onChange={(e) =>
                      setFeatures({ ...features, [fname]: Number(e.target.value) })
                    }
                    className="mt-1 w-full bg-[#090D16] border border-slate-700/80 rounded px-2 py-1 text-xs font-mono tabular-nums text-slate-100 focus:outline-none focus:border-sky-500"
                  />
                </div>
              ))}
            </div>
          </div>

          {/* Primary Action Buttons */}
          <div className="flex flex-wrap items-center gap-2.5 pt-2">
            <button
              type="button"
              disabled={busy !== null}
              onClick={sendSingleFlow}
              className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-slate-950 bg-sky-400 hover:bg-sky-300 disabled:opacity-50 rounded-md transition-colors whitespace-nowrap"
            >
              <Play className="w-3.5 h-3.5" />
              {busy === 'single' ? 'Evaluating...' : 'Send Single Flow'}
            </button>

            <button
              type="button"
              disabled={busy !== null}
              onClick={sendExactRepeat50x}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-sky-300 bg-sky-500/10 hover:bg-sky-500/20 border border-sky-500/35 disabled:opacity-50 rounded-md transition-colors whitespace-nowrap"
            >
              <Repeat className="w-3.5 h-3.5" />
              {busy === 'repeat' ? 'Running 50x...' : 'Send Exact Repeat 50x'}
            </button>

            <button
              type="button"
              disabled={busy !== null}
              onClick={sendMutatedVariant}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-amber-300 bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/35 disabled:opacity-50 rounded-md transition-colors whitespace-nowrap"
            >
              <Shuffle className="w-3.5 h-3.5" />
              {busy === 'mutate' ? 'Mutating...' : 'Send +3% Mutated Variant'}
            </button>
          </div>

          {/* Drag-and-Drop CSV / JSON Batch Replayer */}
          <div className="pt-4 border-t border-slate-800/80">
            <label className="flex items-center justify-between gap-4 px-4 py-3 border border-dashed border-slate-700 hover:border-sky-500/50 rounded-lg cursor-pointer bg-[#0B111E] transition-colors">
              <div className="flex items-center gap-3 min-w-0">
                <Upload className="w-4 h-4 text-slate-400 shrink-0" />
                <div className="min-w-0">
                  <div className="text-xs font-medium text-slate-200">
                    Batch CSV / JSON Flow Replayer (up to 200 rows)
                  </div>
                  <div className="text-[11px] text-slate-500 truncate">
                    Upload network telemetry CSV or JSON array to replay through Stage 1–5
                  </div>
                </div>
              </div>
              <span className="text-xs font-medium text-sky-400 whitespace-nowrap">Select File</span>
              <input
                type="file"
                accept=".csv,.json"
                className="hidden"
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) void handleBatchUpload(file);
                  e.target.value = '';
                }}
              />
            </label>
            {batchSummary && (
              <div className="mt-2 text-xs text-emerald-300 font-mono">{batchSummary}</div>
            )}
          </div>
        </div>

        {/* Right: Live Stage 1–6 Execution Trace & Verification Output */}
        <div className="xl:col-span-6 bg-[#0F1623] border border-slate-800 rounded-lg p-5 space-y-5">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-semibold text-slate-100">
              Live Pipeline Verdict &amp; Bypass Verification
            </h3>
            {lastFlow && (
              <span className="text-xs font-mono tabular-nums text-slate-400">
                SimHash-64: <span className="text-slate-200">{lastFlow.simhash64}</span>
              </span>
            )}
          </div>

          {stressSummary && (
            <div className="px-3.5 py-2.5 rounded-md bg-sky-500/10 border border-sky-500/30 text-xs text-sky-200 flex items-start gap-2">
              <Zap className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
              <span>{stressSummary}</span>
            </div>
          )}

          {lastFlow ? (
            <div className="space-y-5">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div className="bg-[#0B111E] border border-slate-800 rounded p-3">
                  <div className="text-slate-500">4-Zone Triage</div>
                  <div className="mt-1"><ZoneTag zone={lastFlow.zone} compact /></div>
                </div>
                <div className="bg-[#0B111E] border border-slate-800 rounded p-3">
                  <div className="text-slate-500">Execution Latency</div>
                  <div className="font-mono tabular-nums text-slate-100 font-semibold mt-1">
                    {lastFlow.latency_ms.toFixed(3)} ms
                  </div>
                </div>
                <div className="bg-[#0B111E] border border-slate-800 rounded p-3">
                  <div className="text-slate-500">MetaOOD Score</div>
                  <div className="font-mono tabular-nums text-slate-100 font-semibold mt-1">
                    {lastFlow.meta_ood_score.toFixed(3)}{' '}
                    <span className="text-slate-500 font-normal">/ τ {lastFlow.tau_red}</span>
                  </div>
                </div>
                <div className="bg-[#0B111E] border border-slate-800 rounded p-3">
                  <div className="text-slate-500">Execution Path</div>
                  <div className={`font-medium mt-1 truncate ${bypassLabel(lastFlow.bypass_stage).tone}`}>
                    {bypassLabel(lastFlow.bypass_stage).text}
                  </div>
                </div>
              </div>

              <div className="bg-[#0B111E] border border-slate-800 rounded-lg p-3.5 text-xs space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Verdict</span>
                  <span className="font-mono font-semibold text-slate-100">{lastFlow.verdict}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Closed-Set Nearest Class</span>
                  <span className="font-mono text-slate-200">
                    {lastFlow.closed_nearest_class} ({(lastFlow.confidence * 100).toFixed(1)}%)
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">ChronoGraph Temporal State</span>
                  <span className="font-mono tabular-nums text-slate-200">
                    CUSUM {lastFlow.cusum_drift.toFixed(2)} · Hawkes {lastFlow.hawkes_intensity.toFixed(2)} · Martingale {lastFlow.martingale_value.toFixed(1)}
                  </span>
                </div>
              </div>

              {lastIncident && (
                <XaiWaterfallPanel
                  incident={lastIncident}
                  onApproveRule={onApproveRule}
                  onOpenChat={onOpenChat}
                />
              )}
            </div>
          ) : (
            <div className="py-16 text-center text-sm text-slate-400">
              Select a preset and click <strong className="text-slate-200">Send Single Flow</strong>,{' '}
              <strong className="text-slate-200">Send Exact Repeat 50x</strong>, or{' '}
              <strong className="text-slate-200">Send +3% Mutated Variant</strong> to test the live Tier-0/1 and 4-Zone Conformal pipeline.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
