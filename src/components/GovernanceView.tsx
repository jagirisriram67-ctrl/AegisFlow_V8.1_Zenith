import { useEffect, useState } from 'react';
import {
  ArrowDown,
  ArrowUp,
  CheckCircle2,
  Database,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import type {
  AuditLogEntry,
  DatasetProfile,
  GateE9Audit,
  GatewaySettings,
  Tier0Entry,
  Tier1Prototype,
} from '../types/soc';

interface Props {
  profiles: DatasetProfile[];
  onSettingsUpdated: () => Promise<void>;
}

interface GovernanceResponse {
  settings: GatewaySettings;
  providers: Record<'GEMINI' | 'OPENROUTER' | 'HARBOR' | 'OFFLINE', boolean>;
  pytorch_health: { online: boolean; profiles: string[]; device?: string };
  semantic_cache: { entries: number; total_hits: number };
  tier0_entries: Tier0Entry[];
  tier1_prototypes: Tier1Prototype[];
  audit_log: AuditLogEntry[];
  audit_chain: { valid: boolean; total_entries: number; broken_at_id: number | null };
}

export function GovernanceView({ profiles, onSettingsUpdated }: Props) {
  const [data, setData] = useState<GovernanceResponse | null>(null);
  const [draft, setDraft] = useState<GatewaySettings | null>(null);
  const [saving, setSaving] = useState(false);
  const [syncingRag, setSyncingRag] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [e9Input, setE9Input] = useState(
    'nft add rule inet filter input ip saddr 185.220.101.44 tcp dport 80 drop'
  );
  const [e9Result, setE9Result] = useState<GateE9Audit | null>(null);

  const loadGovernance = async () => {
    const res = await fetch('/api/governance');
    if (!res.ok) return;
    const json = (await res.json()) as GovernanceResponse;
    setData(json);
    setDraft(json.settings);
  };

  useEffect(() => {
    void loadGovernance();
  }, []);

  const saveSettings = async () => {
    if (!draft) return;
    setSaving(true);
    setStatusMsg(null);
    try {
      const res = await fetch('/api/governance/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          inference_mode: draft.inference_mode,
          pytorch_engine_url: draft.pytorch_engine_url,
          active_profile: draft.active_profile,
          failover_order: draft.failover_order,
          gemini_fast_model: draft.gemini_fast_model,
          gemini_reasoning_model: draft.gemini_reasoning_model,
          openrouter_model: draft.openrouter_model,
          harbor_model: draft.harbor_model,
          daily_budget_usd: Number(draft.daily_budget_usd),
          auto_downgrade_pct: Number(draft.auto_downgrade_pct),
          semantic_cache_ttl_min: Number(draft.semantic_cache_ttl_min),
          report_auto_schedule: draft.report_auto_schedule,
        }),
      });
      if (res.ok) {
        setStatusMsg('Gateway configuration saved and recorded in SHA-256 audit log.');
        await loadGovernance();
        await onSettingsUpdated();
      } else {
        const err = await res.json();
        setStatusMsg(err.error || 'Failed to save configuration.');
      }
    } finally {
      setSaving(false);
    }
  };

  const moveProvider = (idx: number, dir: -1 | 1) => {
    if (!draft) return;
    const target = idx + dir;
    if (target < 0 || target >= draft.failover_order.length) return;
    const next = [...draft.failover_order];
    [next[idx], next[target]] = [next[target], next[idx]];
    setDraft({ ...draft, failover_order: next });
  };

  const toggleTier0 = async (hash: string, restore: boolean) => {
    await fetch(`/api/governance/tier0/${encodeURIComponent(hash)}/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ restore }),
    });
    await loadGovernance();
  };

  const toggleTier1 = async (id: string, restore: boolean) => {
    await fetch(`/api/governance/tier1/${encodeURIComponent(id)}/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ restore }),
    });
    await loadGovernance();
  };

  const syncRagFeed = async () => {
    setSyncingRag(true);
    setStatusMsg(null);
    try {
      const res = await fetch('/api/rag/sync', { method: 'POST' });
      const out = await res.json();
      setStatusMsg(`Hybrid RAG Threat-Intel Sync complete (${out.source}): ${out.synced} CISA KEV entries refreshed.`);
      await loadGovernance();
    } finally {
      setSyncingRag(false);
    }
  };

  const simulateGateE9 = async () => {
    const res = await fetch('/api/gate-e9/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ command: e9Input }),
    });
    if (res.ok) setE9Result(await res.json());
  };

  if (!data || !draft) {
    return (
      <div className="bg-[#0F1623] border border-slate-800 rounded-lg p-10 text-center text-sm text-slate-400">
        Loading API Gateway, Model Registry, and Cache Governance...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {statusMsg && (
        <div className="px-4 py-3 rounded-lg bg-sky-500/10 border border-sky-500/30 text-xs text-sky-200 flex items-center justify-between">
          <span>{statusMsg}</span>
          <button type="button" onClick={() => setStatusMsg(null)} className="text-slate-400 hover:text-white">
            Dismiss
          </button>
        </div>
      )}

      {/* Dual-Runtime Inference Bridge + Multi-Provider Failover */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
        <div className="xl:col-span-6 bg-[#0F1623] border border-slate-800 rounded-lg p-5 space-y-5">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">
              Dual-Runtime PyTorch Inference Bridge &amp; Active Profile
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Switch between built-in v8.1 calibration sandbox and live companion FastAPI PyTorch server (`/ml_engine/`)
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <button
              type="button"
              onClick={() => setDraft({ ...draft, inference_mode: 'BUILT_IN_SANDBOX_ENGINE' })}
              className={`text-left p-3.5 rounded-lg border transition-colors ${
                draft.inference_mode === 'BUILT_IN_SANDBOX_ENGINE'
                  ? 'bg-sky-500/10 border-sky-500/50 text-slate-100'
                  : 'bg-[#0B111E] border-slate-800 text-slate-400 hover:border-slate-700'
              }`}
            >
              <div className="text-xs font-semibold">Built-In v8.1 Sandbox Engine</div>
              <div className="text-[11px] text-slate-400 mt-1">
                Calibration-accurate 40/46/115 feature runtime with zero external GPU requirement
              </div>
            </button>

            <button
              type="button"
              onClick={() => setDraft({ ...draft, inference_mode: 'LIVE_PYTORCH_BRIDGE' })}
              className={`text-left p-3.5 rounded-lg border transition-colors ${
                draft.inference_mode === 'LIVE_PYTORCH_BRIDGE'
                  ? 'bg-sky-500/10 border-sky-500/50 text-slate-100'
                  : 'bg-[#0B111E] border-slate-800 text-slate-400 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold">Live PyTorch Bridge</span>
                <span className={`text-[11px] font-mono ${data.pytorch_health.online ? 'text-emerald-400' : 'text-amber-400'}`}>
                  {data.pytorch_health.online ? 'Connected' : 'Fallback Ready'}
                </span>
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                Calls `/ml_engine/server.py` loading exact `.pt`/`.pkl` checkpoints
              </div>
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div>
              <label className="block text-slate-400 mb-1">PYTORCH_ENGINE_URL</label>
              <input
                type="url"
                value={draft.pytorch_engine_url}
                onChange={(e) => setDraft({ ...draft, pytorch_engine_url: e.target.value })}
                className="w-full bg-[#090D16] border border-slate-700 rounded-md px-3 py-1.5 font-mono text-slate-100 focus:outline-none focus:border-sky-500"
              />
            </div>
            <div>
              <label className="block text-slate-400 mb-1">Active Sensor Dataset Profile</label>
              <select
                value={draft.active_profile}
                onChange={(e) => setDraft({ ...draft, active_profile: e.target.value })}
                className="w-full bg-[#090D16] border border-slate-700 rounded-md px-3 py-1.5 font-mono text-slate-100 focus:outline-none focus:border-sky-500"
              >
                {profiles.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.id} ({p.feature_count} feats)
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Budget Governor & Semantic Cache */}
          <div className="pt-4 border-t border-slate-800/80 space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="font-semibold text-slate-200">Daily USD / Token Budget Governor</span>
              <span className="font-mono tabular-nums text-slate-400">
                ${draft.daily_spend_usd.toFixed(3)} / ${draft.daily_budget_usd.toFixed(2)} · {draft.daily_tokens_used.toLocaleString()} tokens
              </span>
            </div>
            <div className="grid grid-cols-3 gap-2.5 text-xs">
              <div>
                <label className="block text-[11px] text-slate-500 mb-1">Daily Cap ($)</label>
                <input
                  type="number"
                  min={1}
                  max={5000}
                  value={draft.daily_budget_usd}
                  onChange={(e) => setDraft({ ...draft, daily_budget_usd: Number(e.target.value) })}
                  className="w-full bg-[#090D16] border border-slate-700 rounded px-2.5 py-1.5 font-mono text-slate-100"
                />
              </div>
              <div>
                <label className="block text-[11px] text-slate-500 mb-1">Downgrade At (%)</label>
                <input
                  type="number"
                  min={20}
                  max={99}
                  value={draft.auto_downgrade_pct}
                  onChange={(e) => setDraft({ ...draft, auto_downgrade_pct: Number(e.target.value) })}
                  className="w-full bg-[#090D16] border border-slate-700 rounded px-2.5 py-1.5 font-mono text-slate-100"
                />
              </div>
              <div>
                <label className="block text-[11px] text-slate-500 mb-1">Prompt Cache TTL (m)</label>
                <input
                  type="number"
                  min={1}
                  max={120}
                  value={draft.semantic_cache_ttl_min}
                  onChange={(e) => setDraft({ ...draft, semantic_cache_ttl_min: Number(e.target.value) })}
                  className="w-full bg-[#090D16] border border-slate-700 rounded px-2.5 py-1.5 font-mono text-slate-100"
                />
              </div>
            </div>
            <div className="text-[11px] text-slate-500 font-mono">
              Semantic Prompt Cache: {data.semantic_cache.entries} cached briefs · {data.semantic_cache.total_hits} zero-cost hits
            </div>
          </div>
        </div>

        {/* Right: Multi-Provider Cloud LLM Failover Chain */}
        <div className="xl:col-span-6 bg-[#0F1623] border border-slate-800 rounded-lg p-5 space-y-5">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-slate-100">
                4-Step Cloud LLM Circuit-Breaker Failover
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Provider secrets are read strictly server-side from environment / Settings &gt; Secrets
              </p>
            </div>
            <button
              type="button"
              disabled={syncingRag}
              onClick={syncRagFeed}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-md whitespace-nowrap"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${syncingRag ? 'animate-spin' : ''}`} />
              Sync CISA KEV RAG
            </button>
          </div>

          <div className="divide-y divide-slate-800 border border-slate-800 rounded-lg">
            {draft.failover_order.map((prov, idx) => {
              const configured = data.providers[prov];
              const envHint =
                prov === 'GEMINI'
                  ? 'Server Env: GEMINI_API_KEY'
                  : prov === 'OPENROUTER'
                  ? 'Server Env: OPENROUTER_API_KEY'
                  : prov === 'HARBOR'
                  ? 'Server Env: HARBOR_BASE_URL'
                  : 'Always Online (Deterministic Local)';
              return (
                <div key={prov} className="px-3.5 py-2.5 flex items-center justify-between gap-3 text-xs">
                  <div className="flex items-center gap-3 min-w-0">
                    <span className="font-mono text-slate-500 w-4">{idx + 1}.</span>
                    <div className="min-w-0">
                      <div className="font-medium text-slate-100">{prov}</div>
                      <div className="text-[11px] font-mono text-slate-500">{envHint}</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <span className={`font-mono text-[11px] ${configured ? 'text-emerald-400' : 'text-slate-500'}`}>
                      {configured ? 'Configured' : 'Standby'}
                    </span>
                    <div className="flex items-center gap-1">
                      <button
                        type="button"
                        aria-label={`Move ${prov} up`}
                        disabled={idx === 0}
                        onClick={() => moveProvider(idx, -1)}
                        className="p-1 text-slate-400 hover:text-slate-100 disabled:opacity-30"
                      >
                        <ArrowUp className="w-3.5 h-3.5" />
                      </button>
                      <button
                        type="button"
                        aria-label={`Move ${prov} down`}
                        disabled={idx === draft.failover_order.length - 1}
                        onClick={() => moveProvider(idx, 1)}
                        className="p-1 text-slate-400 hover:text-slate-100 disabled:opacity-30"
                      >
                        <ArrowDown className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div>
              <label className="block text-[11px] text-slate-500 mb-1">Gemini Fast Tier (Briefs)</label>
              <input
                type="text"
                value={draft.gemini_fast_model}
                onChange={(e) => setDraft({ ...draft, gemini_fast_model: e.target.value })}
                className="w-full bg-[#090D16] border border-slate-700 rounded px-2.5 py-1.5 font-mono text-slate-100"
              />
            </div>
            <div>
              <label className="block text-[11px] text-slate-500 mb-1">Gemini Reasoning Tier (Forensics/Chat)</label>
              <input
                type="text"
                value={draft.gemini_reasoning_model}
                onChange={(e) => setDraft({ ...draft, gemini_reasoning_model: e.target.value })}
                className="w-full bg-[#090D16] border border-slate-700 rounded px-2.5 py-1.5 font-mono text-slate-100"
              />
            </div>
            <div>
              <label className="block text-[11px] text-slate-500 mb-1">OpenRouter Model Slug</label>
              <input
                type="text"
                value={draft.openrouter_model}
                onChange={(e) => setDraft({ ...draft, openrouter_model: e.target.value })}
                className="w-full bg-[#090D16] border border-slate-700 rounded px-2.5 py-1.5 font-mono text-slate-100"
              />
            </div>
            <div>
              <label className="block text-[11px] text-slate-500 mb-1">Harbor / Custom Model ID</label>
              <input
                type="text"
                value={draft.harbor_model}
                onChange={(e) => setDraft({ ...draft, harbor_model: e.target.value })}
                className="w-full bg-[#090D16] border border-slate-700 rounded px-2.5 py-1.5 font-mono text-slate-100"
              />
            </div>
          </div>

          <div className="flex justify-end">
            <button
              type="button"
              disabled={saving}
              onClick={saveSettings}
              className="px-4 py-2 text-xs font-semibold text-slate-950 bg-sky-400 hover:bg-sky-300 disabled:opacity-50 rounded-md transition-colors"
            >
              {saving ? 'Saving...' : 'Save Gateway & Runtime Settings'}
            </button>
          </div>
        </div>
      </div>

      {/* Interactive Gate E9 Safety Auditor Sandbox */}
      <div className="bg-[#0F1623] border border-slate-800 rounded-lg p-5 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-semibold text-slate-100">
              Gate E9 Deterministic Safety Auditor &amp; Blast-Radius Simulator
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Test any firewall rule against strict regex allowlists, forbidden tokens (/0, 127.0.0.1, port 22, shell chaining), and live GREEN benign flows
            </p>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <button
              type="button"
              onClick={() => setE9Input('nft add rule inet filter input ip saddr 0.0.0.0/0 tcp dport 22 drop; rm -rf /')}
              className="text-rose-400 hover:text-rose-300 underline"
            >
              Load Unsafe Test
            </button>
            <span className="text-slate-600">·</span>
            <button
              type="button"
              onClick={() => setE9Input('nft add rule inet filter input ip saddr 185.220.101.44 tcp dport 80 drop')}
              className="text-emerald-400 hover:text-emerald-300 underline"
            >
              Load Safe Rule
            </button>
          </div>
        </div>
        <div className="flex flex-col sm:flex-row gap-2.5">
          <input
            type="text"
            value={e9Input}
            onChange={(e) => setE9Input(e.target.value)}
            className="flex-1 bg-[#090D16] border border-slate-700 rounded-md px-3 py-2 text-xs font-mono text-sky-300 focus:outline-none focus:border-sky-500"
          />
          <button
            type="button"
            onClick={simulateGateE9}
            className="px-4 py-2 text-xs font-medium text-slate-100 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-md whitespace-nowrap"
          >
            Run Gate E9 Dry-Run
          </button>
        </div>
        {e9Result && (
          <div
            className={`p-3 rounded-md border text-xs ${
              e9Result.passed
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-200'
                : 'bg-rose-500/10 border-rose-500/30 text-rose-200'
            }`}
          >
            <div className="flex items-center gap-2 font-medium">
              {e9Result.passed ? <ShieldCheck className="w-4 h-4" /> : <ShieldAlert className="w-4 h-4" />}
              {e9Result.verified_badge}
            </div>
            {e9Result.violations.length > 0 && (
              <ul className="mt-1.5 list-disc list-inside space-y-0.5 text-[11px]">
                {e9Result.violations.map((v, i) => (
                  <li key={i}>{v}</li>
                ))}
              </ul>
            )}
          </div>
        )}
      </div>

      {/* Tier-0 SimHash Cache & Tier-1 Prototype Bank Governance (1-Click Revoke/Undo) */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <div className="bg-[#0F1623] border border-slate-800 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-100">
              Tier-0 SimHash-64 Reflex Cache ({data.tier0_entries.length})
            </h3>
            <span className="text-xs text-slate-400">1-Click Revoke / Restore</span>
          </div>
          <div className="overflow-x-auto max-h-72 overflow-y-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead className="bg-[#0B111E] border-b border-slate-800 text-slate-400 sticky top-0">
                <tr>
                  <th className="py-2 px-3 font-medium">SimHash-64</th>
                  <th className="py-2 px-3 font-medium">Type &amp; Label</th>
                  <th className="py-2 px-3 font-medium text-right">Hits</th>
                  <th className="py-2 px-3 font-medium text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {data.tier0_entries.map((entry) => (
                  <tr key={entry.simhash64} className={entry.active ? '' : 'opacity-45'}>
                    <td className="py-2 px-3 font-mono text-slate-300">{entry.simhash64}</td>
                    <td className="py-2 px-3">
                      <span className={entry.entry_type === 'ATTACK' ? 'text-rose-400 font-medium' : 'text-emerald-400 font-medium'}>
                        {entry.entry_type}
                      </span>{' '}
                      · <span className="text-slate-200">{entry.label}</span>
                      <div className="text-[10px] text-slate-500 font-mono">
                        {entry.source} · R_max {entry.max_rate_per_min}/m
                      </div>
                    </td>
                    <td className="py-2 px-3 text-right font-mono tabular-nums text-sky-400">
                      {entry.hit_count}
                    </td>
                    <td className="py-2 px-3 text-right">
                      <button
                        type="button"
                        onClick={() => toggleTier0(entry.simhash64, !entry.active)}
                        className="inline-flex items-center gap-1 text-xs text-slate-300 hover:text-white"
                      >
                        {entry.active ? <Trash2 className="w-3.5 h-3.5 text-rose-400" /> : <RotateCcw className="w-3.5 h-3.5 text-emerald-400" />}
                        {entry.active ? 'Revoke' : 'Undo'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="bg-[#0F1623] border border-slate-800 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-100">
              Tier-1 192-D Hypersphere Prototype Bank ({data.tier1_prototypes.length})
            </h3>
            <span className="text-xs text-slate-400">B_threat &amp; B_benign_fp (σ=0.06)</span>
          </div>
          <div className="overflow-x-auto max-h-72 overflow-y-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead className="bg-[#0B111E] border-b border-slate-800 text-slate-400 sticky top-0">
                <tr>
                  <th className="py-2 px-3 font-medium">ID</th>
                  <th className="py-2 px-3 font-medium">Bank &amp; Label</th>
                  <th className="py-2 px-3 font-medium">Profile</th>
                  <th className="py-2 px-3 font-medium text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {data.tier1_prototypes.map((p) => (
                  <tr key={p.id} className={p.active ? '' : 'opacity-45'}>
                    <td className="py-2 px-3 font-mono text-slate-300">{p.id}</td>
                    <td className="py-2 px-3">
                      <span className={p.bank_type === 'THREAT' ? 'text-rose-400 font-medium' : 'text-emerald-400 font-medium'}>
                        {p.bank_type}
                      </span>{' '}
                      · <span className="text-slate-200">{p.label}</span>
                    </td>
                    <td className="py-2 px-3 font-mono text-slate-400">{p.profile_id}</td>
                    <td className="py-2 px-3 text-right">
                      <button
                        type="button"
                        onClick={() => toggleTier1(p.id, !p.active)}
                        className="inline-flex items-center gap-1 text-xs text-slate-300 hover:text-white"
                      >
                        {p.active ? <Trash2 className="w-3.5 h-3.5 text-rose-400" /> : <RotateCcw className="w-3.5 h-3.5 text-emerald-400" />}
                        {p.active ? 'Revoke' : 'Undo'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Certified 6-Dataset v8.1 Benchmark Registry */}
      <div className="bg-[#0F1623] border border-slate-800 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <Database className="w-4 h-4 text-sky-400" />
            Certified AegisFlow-Zenith v8.1 6-Dataset Model Registry (6.0M+ Unique Flows)
          </h3>
          <span className="text-xs font-mono text-slate-400">TabM-8 + DCN-v2 + 9-Primitive Fisher-Probit</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-[#0B111E] border-b border-slate-800 text-slate-400">
                <th className="py-2.5 px-3 font-medium">Dataset Profile</th>
                <th className="py-2.5 px-3 font-medium text-right">Features</th>
                <th className="py-2.5 px-3 font-medium text-right">Closed Acc</th>
                <th className="py-2.5 px-3 font-medium text-right">Macro-F1</th>
                <th className="py-2.5 px-3 font-medium text-right">OOD AUROC</th>
                <th className="py-2.5 px-3 font-medium text-right">Evasion Def.</th>
                <th className="py-2.5 px-3 font-medium text-right">ECE</th>
                <th className="py-2.5 px-3 font-medium text-right">Latency</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70 font-mono tabular-nums">
              {profiles.map((p) => (
                <tr key={p.id} className="hover:bg-slate-900/40">
                  <td className="py-2 px-3 font-sans text-slate-100 font-medium">{p.id}</td>
                  <td className="py-2 px-3 text-right text-slate-300">{p.feature_count}</td>
                  <td className="py-2 px-3 text-right text-emerald-400">{p.benchmark.closed_acc.toFixed(2)}%</td>
                  <td className="py-2 px-3 text-right text-slate-200">{p.benchmark.closed_macro_f1.toFixed(2)}%</td>
                  <td className="py-2 px-3 text-right text-sky-400">{p.benchmark.ood_auroc_known.toFixed(2)}%</td>
                  <td className="py-2 px-3 text-right text-emerald-300">{p.benchmark.evasion_auroc.toFixed(2)}%</td>
                  <td className="py-2 px-3 text-right text-slate-300">{p.benchmark.ece_pct.toFixed(2)}%</td>
                  <td className="py-2 px-3 text-right text-slate-300">{p.benchmark.single_flow_ms.toFixed(2)}ms</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Tamper-Evident SHA-256 Hash-Chained Audit Log */}
      <div className="bg-[#0F1623] border border-slate-800 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-sm font-semibold text-slate-100">
            Tamper-Evident SHA-256 Hash-Chained Audit Log ({data.audit_chain.total_entries} entries)
          </h3>
          <span className={`inline-flex items-center gap-1.5 text-xs font-mono ${data.audit_chain.valid ? 'text-emerald-400' : 'text-rose-400'}`}>
            <CheckCircle2 className="w-3.5 h-3.5" />
            {data.audit_chain.valid
              ? 'Cryptographic Hash Chain Verified (0 Tampered Blocks)'
              : `Chain Broken at Entry #${data.audit_chain.broken_at_id}`}
          </span>
        </div>
        <div className="overflow-x-auto max-h-72 overflow-y-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead className="bg-[#0B111E] border-b border-slate-800 text-slate-400 sticky top-0">
              <tr>
                <th className="py-2 px-3 font-medium">#</th>
                <th className="py-2 px-3 font-medium">Timestamp (UTC)</th>
                <th className="py-2 px-3 font-medium">Actor / Role</th>
                <th className="py-2 px-3 font-medium">Action</th>
                <th className="py-2 px-3 font-medium">Target</th>
                <th className="py-2 px-3 font-medium">Entry SHA-256</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {data.audit_log.map((entry) => (
                <tr key={entry.id} className="hover:bg-slate-900/40">
                  <td className="py-2 px-3 font-mono text-slate-500">{entry.id}</td>
                  <td className="py-2 px-3 font-mono tabular-nums text-slate-400 whitespace-nowrap">
                    {entry.timestamp_utc.slice(5, 19).replace('T', ' ')}
                  </td>
                  <td className="py-2 px-3 text-slate-200 whitespace-nowrap">
                    {entry.actor} <span className="text-slate-500">({entry.role})</span>
                  </td>
                  <td className="py-2 px-3 font-mono text-sky-300">{entry.action}</td>
                  <td className="py-2 px-3 font-mono text-slate-300">{entry.target_id}</td>
                  <td className="py-2 px-3 font-mono text-slate-500">{entry.entry_hash.slice(0, 18)}…</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
