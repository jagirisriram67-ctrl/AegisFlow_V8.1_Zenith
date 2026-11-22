import { useEffect, useState } from 'react';
import { AlertTriangle, CheckCircle2, MessageSquare, ShieldAlert } from 'lucide-react';
import type { IncidentRecord } from '../types/soc';
import { ZoneTag } from './ZoneIndicator';
import { XaiWaterfallPanel } from './XaiWaterfallPanel';

interface Props {
  focusIncidentId?: string | null;
  onRefreshDashboard: () => Promise<void>;
  onApproveRule: (incidentId: string) => Promise<void>;
  onOpenChat: (incidentId: string, ip: string) => void;
}

export function ClarificationInboxView({
  focusIncidentId,
  onRefreshDashboard,
  onApproveRule,
  onOpenChat,
}: Props) {
  const [pending, setPending] = useState<IncidentRecord[]>([]);
  const [resolved, setResolved] = useState<IncidentRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedId, setSelectedId] = useState<string | null>(focusIncidentId ?? null);
  const [customLabel, setCustomLabel] = useState('');
  const [maxRatePerMin, setMaxRatePerMin] = useState(25);
  const [submitting, setSubmitting] = useState(false);
  const [feedbackBanner, setFeedbackBanner] = useState<{ tone: 'ok' | 'warn'; text: string } | null>(null);
  const [poisonModal, setPoisonModal] = useState<{
    incidentId: string;
    similarity: number;
    matchedLabel: string;
    message: string;
  } | null>(null);

  const loadInbox = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/clarifications');
      const data = await res.json();
      setPending(data.pending ?? []);
      setResolved(data.resolved ?? []);
      if (!selectedId && data.pending?.[0]) {
        setSelectedId(data.pending[0].id);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadInbox();
  }, []);

  useEffect(() => {
    if (focusIncidentId) setSelectedId(focusIncidentId);
  }, [focusIncidentId]);

  const activeItem =
    pending.find((p) => p.id === selectedId) ??
    resolved.find((r) => r.id === selectedId) ??
    pending[0] ??
    resolved[0] ??
    null;

  const submitDecision = async (
    incidentId: string,
    decision: 'NORMAL' | 'ATTACK',
    supervisorOverride = false
  ) => {
    setSubmitting(true);
    setFeedbackBanner(null);
    try {
      const res = await fetch(`/api/incidents/${encodeURIComponent(incidentId)}/confirm`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          decision,
          custom_label: customLabel.trim() || undefined,
          supervisor_override: supervisorOverride,
          max_rate_per_min: maxRatePerMin,
        }),
      });
      const data = await res.json();
      if (data.status === 'ANTI_POISON_WARNING') {
        setPoisonModal({
          incidentId,
          similarity: data.max_threat_similarity,
          matchedLabel: data.matched_threat_label,
          message: data.message,
        });
        return;
      }
      setPoisonModal(null);
      setCustomLabel('');
      setFeedbackBanner({ tone: 'ok', text: data.message });
      await loadInbox();
      await onRefreshDashboard();
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-5">
      {feedbackBanner && (
        <div
          className={`px-4 py-3 rounded-lg border text-xs flex items-center justify-between gap-3 ${
            feedbackBanner.tone === 'ok'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-200'
              : 'bg-amber-500/10 border-amber-500/30 text-amber-200'
          }`}
        >
          <span>{feedbackBanner.text}</span>
          <button
            type="button"
            onClick={() => setFeedbackBanner(null)}
            className="text-slate-400 hover:text-slate-100"
          >
            Dismiss
          </button>
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
        {/* Left Queue: Pending YELLOW/AMBER Flows */}
        <div className="xl:col-span-4 bg-[#0F1623] border border-slate-800 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-100">
              Needs Clarification ({pending.length})
            </h2>
            <span className="text-xs text-slate-400">Zone 2A / 2B Queue</span>
          </div>

          <div className="divide-y divide-slate-800/70 max-h-[420px] overflow-y-auto">
            {loading ? (
              <div className="p-6 text-xs text-slate-400">Loading clarification queue...</div>
            ) : pending.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-400">
                All uncertain flows have been resolved. New Zone 2A/2B flows will appear automatically.
              </div>
            ) : (
              pending.map((item) => {
                const selected = activeItem?.id === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setSelectedId(item.id)}
                    className={`w-full text-left px-4 py-3.5 transition-colors block ${
                      selected ? 'bg-slate-800/65' : 'hover:bg-slate-900/50'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-xs text-slate-400">{item.id}</span>
                      <ZoneTag zone={item.zone} compact />
                    </div>
                    <div className="text-sm font-semibold text-slate-100 mt-1 truncate">
                      {item.label}
                    </div>
                    <div className="text-xs font-mono tabular-nums text-slate-400 mt-1">
                      {item.src_ip} → {item.dst_ip}:{item.dst_port}
                    </div>
                    <div className="flex items-center justify-between text-[11px] font-mono tabular-nums text-slate-500 mt-1.5">
                      <span>Entropy H(p) {item.shannon_entropy.toFixed(2)} · JSD {item.epistemic_jsd.toFixed(3)}</span>
                      <span>M_t {item.martingale_value.toFixed(1)}</span>
                    </div>
                  </button>
                );
              })
            )}
          </div>

          {/* Recently Resolved Audit Section */}
          {resolved.length > 0 && (
            <>
              <div className="px-4 py-2.5 border-y border-slate-800 bg-[#0B111E] text-xs font-medium text-slate-400">
                Recently Resolved ({resolved.length})
              </div>
              <div className="divide-y divide-slate-800/60 max-h-[200px] overflow-y-auto">
                {resolved.slice(0, 6).map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setSelectedId(item.id)}
                    className={`w-full text-left px-4 py-2.5 text-xs transition-colors block ${
                      activeItem?.id === item.id ? 'bg-slate-800/50' : 'hover:bg-slate-900/40'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-medium text-slate-200 truncate">{item.id} · {item.label}</span>
                      <span className={item.status === 'CONFIRMED_NORMAL' ? 'text-emerald-400' : 'text-rose-400'}>
                        {item.status === 'CONFIRMED_NORMAL' ? 'Normal' : 'Attack'}
                      </span>
                    </div>
                  </button>
                ))}
              </div>
            </>
          )}
        </div>

        {/* Right Detail Workspace: Uncertainty + XAI + 1-Click Poison-Resilient Confirmation */}
        <div className="xl:col-span-8 bg-[#0F1623] border border-slate-800 rounded-lg p-5">
          {activeItem ? (
            <div className="space-y-6">
              <div className="flex flex-wrap items-start justify-between gap-4 pb-4 border-b border-slate-800">
                <div>
                  <div className="flex items-center gap-2 text-xs text-slate-400">
                    <span className="font-mono text-slate-200">{activeItem.id}</span>
                    <span>·</span>
                    <ZoneTag zone={activeItem.zone} />
                    <span>·</span>
                    <span className="font-mono">{activeItem.profile_id}</span>
                  </div>
                  <h2 className="text-lg font-semibold text-slate-100 mt-1">{activeItem.label}</h2>
                  <div className="text-xs font-mono tabular-nums text-slate-400 mt-1">
                    {activeItem.src_ip} → {activeItem.dst_ip}:{activeItem.dst_port} · SimHash-64{' '}
                    <span className="text-slate-200">{activeItem.simhash64}</span> · Nearest Closed Class{' '}
                    <span className="text-slate-200">{activeItem.closed_nearest_class}</span>
                  </div>
                </div>
                <div className="text-right text-xs font-mono tabular-nums text-slate-400">
                  <div>Conformal Martingale M_t: <span className="text-amber-300 font-semibold">{activeItem.martingale_value.toFixed(1)}</span> / 100</div>
                  <div className="mt-0.5">CUSUM Drift: <span className="text-slate-200">{activeItem.cusum_drift.toFixed(2)}</span> · Hawkes λ(t): <span className="text-slate-200">{activeItem.hawkes_intensity.toFixed(2)}</span></div>
                </div>
              </div>

              {/* 1-Click Poison-Resilient Confirmation Bar */}
              {activeItem.status === 'NEEDS_CLARIFICATION' && (
                <div className="bg-[#0B111E] border border-slate-800 rounded-lg p-4 space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="text-sm font-semibold text-slate-100">
                      1-Click Manifold Confirmation (Zero Catastrophic Forgetting)
                    </h3>
                    <span className="text-xs text-slate-400">
                      Anti-Poison cos ≥ 0.96 check · 24h retroactive sweep on attack
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <div>
                      <label htmlFor="custom-attack-label" className="block text-xs text-slate-400 mb-1">
                        Custom Attack / Zero-Day Label (optional)
                      </label>
                      <input
                        id="custom-attack-label"
                        type="text"
                        value={customLabel}
                        onChange={(e) => setCustomLabel(e.target.value)}
                        placeholder={`e.g. ZeroDay_MQTT_Staging or ${activeItem.closed_nearest_class}`}
                        className="w-full bg-[#090D16] border border-slate-700 rounded-md px-3 py-1.5 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
                      />
                    </div>
                    <div>
                      <label htmlFor="rmax-rate" className="block text-xs text-slate-400 mb-1">
                        Benign Tier-0 Anti-Spoofing Rate Cap R_max (flows/min)
                      </label>
                      <input
                        id="rmax-rate"
                        type="number"
                        min={5}
                        max={500}
                        value={maxRatePerMin}
                        onChange={(e) => setMaxRatePerMin(Number(e.target.value))}
                        className="w-full bg-[#090D16] border border-slate-700 rounded-md px-3 py-1.5 text-xs font-mono text-slate-100 focus:outline-none focus:border-sky-500"
                      />
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-2.5 pt-1">
                    <button
                      type="button"
                      disabled={submitting}
                      onClick={() => submitDecision(activeItem.id, 'NORMAL')}
                      className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-slate-950 bg-emerald-400 hover:bg-emerald-300 disabled:opacity-50 rounded-md transition-colors whitespace-nowrap"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      Confirm Normal (Benign FP)
                    </button>

                    <button
                      type="button"
                      disabled={submitting}
                      onClick={() => submitDecision(activeItem.id, 'ATTACK')}
                      className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-white bg-rose-600 hover:bg-rose-500 disabled:opacity-50 rounded-md transition-colors whitespace-nowrap"
                    >
                      <ShieldAlert className="w-3.5 h-3.5" />
                      Confirm Attack + 24h Sweep
                    </button>

                    <button
                      type="button"
                      onClick={() => onOpenChat(activeItem.id, activeItem.src_ip)}
                      className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-md transition-colors whitespace-nowrap"
                    >
                      <MessageSquare className="w-3.5 h-3.5" />
                      Investigate in AI Chat
                    </button>
                  </div>
                </div>
              )}

              <XaiWaterfallPanel
                incident={activeItem}
                onApproveRule={onApproveRule}
                onOpenChat={onOpenChat}
              />
            </div>
          ) : (
            <div className="py-16 text-center text-sm text-slate-400">
              Select a flow from the Clarification Inbox to inspect uncertainty evidence and confirm its disposition.
            </div>
          )}
        </div>
      </div>

      {/* Riemannian Anti-Poison Supervisor Warning Modal */}
      {poisonModal && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <div className="bg-[#0F1623] border border-rose-500/40 rounded-lg max-w-lg w-full p-6 space-y-4">
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
              <div>
                <h3 className="text-base font-semibold text-slate-100">
                  Anti-Poison Supervisor Warning
                </h3>
                <p className="text-xs text-slate-300 mt-1.5 leading-relaxed">
                  {poisonModal.message}
                </p>
              </div>
            </div>
            <div className="bg-[#090D16] border border-slate-800 rounded-md p-3 text-xs font-mono tabular-nums space-y-1">
              <div className="text-slate-400">
                Max Cosine Similarity to B_threat: <span className="text-rose-400 font-semibold">{(poisonModal.similarity * 100).toFixed(2)}%</span>
              </div>
              <div className="text-slate-400">
                Matched Confirmed Threat: <span className="text-slate-100">{poisonModal.matchedLabel}</span>
              </div>
            </div>
            <div className="flex items-center justify-end gap-2.5 pt-2">
              <button
                type="button"
                onClick={() => setPoisonModal(null)}
                className="px-4 py-2 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 rounded-md transition-colors"
              >
                Cancel Whitelist
              </button>
              <button
                type="button"
                disabled={submitting}
                onClick={() => submitDecision(poisonModal.incidentId, 'NORMAL', true)}
                className="px-4 py-2 text-xs font-semibold text-white bg-rose-600 hover:bg-rose-500 rounded-md transition-colors"
              >
                Tier-3 Supervisor Override
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
