import { useState } from 'react';
import { ShieldCheck, ShieldAlert, Check, ExternalLink } from 'lucide-react';
import type { IncidentRecord } from '../types/soc';

interface Props {
  incident: IncidentRecord;
  onApproveRule?: (incidentId: string) => Promise<void>;
  onOpenChat?: (incidentId: string, ip: string) => void;
}

const PRIMITIVE_LABELS: Record<string, string> = {
  energy: 'Energy',
  maha: 'Mahalanobis',
  vim: 'ViM Residual',
  knn: '192-D kNN',
  inv_viol: 'Invariant Viol.',
  fdbd_nci: 'fDBD / NCI',
  tabm_epist: 'TabM-8 Epist.',
  x_knn: 'Input kNN',
  msp: 'MSP Entropy',
};

export function XaiWaterfallPanel({ incident, onApproveRule, onOpenChat }: Props) {
  const [approving, setApproving] = useState(false);
  const xai = incident.xai;
  const maxAbsShap = Math.max(
    0.1,
    ...(xai?.top_features.map((f) => Math.abs(f.ig_shap)) ?? [0.5])
  );

  const handleApprove = async () => {
    if (!onApproveRule || approving) return;
    setApproving(true);
    try {
      await onApproveRule(incident.id);
    } finally {
      setApproving(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Uncertainty & Causal Summary */}
      {xai && (
        <div>
          <div className="flex items-center justify-between gap-4 mb-2">
            <h4 className="text-sm font-semibold text-slate-100">
              Class-Locked IG-SHAP &amp; GPU-LIME Causal Attribution
            </h4>
            <div className="text-xs font-mono tabular-nums text-slate-400">
              Agreement {xai.shap_lime_agreement}% · Deletion Faithfulness {xai.deletion_faithfulness} · {xai.tabm_heads_flagging}/8 TabM Heads
            </div>
          </div>
          <p className="text-sm text-slate-300 leading-relaxed mb-4">
            {xai.uncertainty_summary}
          </p>

          {/* Top-5 Canonical Features Table */}
          <div className="border border-slate-800 rounded-lg overflow-hidden">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-[#0B111E] border-b border-slate-800 text-xs text-slate-400">
                  <th className="py-2.5 px-3 font-medium">Canonical Feature</th>
                  <th className="py-2.5 px-3 font-medium text-right">Observed</th>
                  <th className="py-2.5 px-3 font-medium text-right">Normal Target (Δx*)</th>
                  <th className="py-2.5 px-3 font-medium">IG-SHAP / LIME</th>
                  <th className="py-2.5 px-3 font-medium text-right">LFG Gate</th>
                  <th className="py-2.5 px-3 font-medium text-right">Recon MSE</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70 text-xs">
                {xai.top_features.map((f) => {
                  const pct = Math.min(100, Math.round((Math.abs(f.ig_shap) / maxAbsShap) * 100));
                  const positive = f.ig_shap >= 0;
                  return (
                    <tr key={f.feature} className="hover:bg-slate-900/40">
                      <td className="py-2.5 px-3">
                        <div className="font-mono text-slate-100 font-medium">{f.feature}</div>
                        <div className="text-[11px] text-slate-500 mt-0.5 max-w-xs truncate" title={f.semantics}>
                          {f.semantics}
                        </div>
                      </td>
                      <td className="py-2.5 px-3 text-right font-mono tabular-nums">
                        <div className="text-slate-100">{f.value.toLocaleString()}</div>
                        <div className={`text-[11px] ${Math.abs(f.z_deviation) >= 2.5 ? 'text-rose-400' : 'text-amber-400'}`}>
                          {f.z_deviation >= 0 ? '+' : ''}{f.z_deviation}σ
                        </div>
                      </td>
                      <td className="py-2.5 px-3 text-right font-mono tabular-nums text-slate-300">
                        <div>{f.baseline_normal.toLocaleString()}</div>
                        <div className="text-[11px] text-slate-500">
                          Δ {f.counterfactual_delta >= 0 ? '+' : ''}{f.counterfactual_delta.toLocaleString()}
                        </div>
                      </td>
                      <td className="py-2.5 px-3 min-w-[160px]">
                        <div className="flex items-center gap-2">
                          <div className="flex-1 h-2 bg-slate-800 rounded-sm overflow-hidden">
                            <div
                              className={`h-full ${positive ? 'bg-rose-500' : 'bg-sky-500'}`}
                              style={{ width: `${pct}%` }}
                            />
                          </div>
                          <span className="font-mono tabular-nums text-slate-200 w-12 text-right">
                            {f.ig_shap >= 0 ? '+' : ''}{f.ig_shap.toFixed(2)}
                          </span>
                        </div>
                        <div className="text-[11px] font-mono tabular-nums text-slate-500 mt-0.5">
                          LIME: {f.gpu_lime >= 0 ? '+' : ''}{f.gpu_lime.toFixed(3)}
                        </div>
                      </td>
                      <td className="py-2.5 px-3 text-right font-mono tabular-nums text-slate-300">
                        {f.lfg_gate.toFixed(3)}
                      </td>
                      <td className="py-2.5 px-3 text-right font-mono tabular-nums text-slate-300">
                        {f.recon_mse.toFixed(3)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* 9-Primitive One-Sided Fisher-Probit MetaOOD Breakdown */}
          <div className="mt-4 pt-4 border-t border-slate-800/80">
            <div className="flex items-center justify-between mb-2.5">
              <span className="text-xs font-medium text-slate-300">
                9-Primitive Fisher-Probit MetaOOD Evidence Breakdown
              </span>
              <span className="text-xs font-mono tabular-nums text-slate-400">
                MetaOOD {incident.meta_ood_score.toFixed(3)} · {xai.anomaly_percentile}th pct
              </span>
            </div>
            <div className="grid grid-cols-3 sm:grid-cols-9 gap-2">
              {Object.entries(xai.ood_primitives).map(([key, val]) => (
                <div key={key} className="bg-[#0B111E] border border-slate-800/80 rounded px-2 py-1.5">
                  <div className="text-[10px] text-slate-500 truncate">{PRIMITIVE_LABELS[key] ?? key}</div>
                  <div className={`text-xs font-mono tabular-nums font-semibold mt-0.5 ${val > 2.2 ? 'text-rose-400' : val > 1.4 ? 'text-amber-400' : 'text-slate-200'}`}>
                    {val.toFixed(2)}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Cloud AI Brief + Pros/Cons Evidence */}
      {incident.llm_brief && (
        <div className="pt-4 border-t border-slate-800/80">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
            <h4 className="text-sm font-semibold text-slate-100">
              Autonomous SOC Forensic Brief
            </h4>
            <div className="text-xs text-slate-400 font-mono">
              {incident.llm_brief.provider} · {incident.llm_brief.model}
              {incident.llm_brief.cached ? ' · Semantic Cache Hit ($0.00)' : ''}
              {incident.llm_brief.privacy_tokens_masked > 0
                ? ` · Privacy Proxy Masked ${incident.llm_brief.privacy_tokens_masked} IP(s)`
                : ''}
            </div>
          </div>
          <p className="text-sm text-slate-300 leading-relaxed mb-3">
            {incident.llm_brief.summary}
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div className="bg-[#0B111E] border border-slate-800 rounded-lg p-3">
              <div className="font-medium text-emerald-400 mb-1.5">Evidence for Benign</div>
              <ul className="space-y-1 text-slate-300 list-disc list-inside">
                {incident.llm_brief.evidence_benign.map((item, idx) => (
                  <li key={idx}>{item}</li>
                ))}
              </ul>
            </div>
            <div className="bg-[#0B111E] border border-slate-800 rounded-lg p-3">
              <div className="font-medium text-rose-400 mb-1.5">Evidence for Malicious</div>
              <ul className="space-y-1 text-slate-300 list-disc list-inside">
                {incident.llm_brief.evidence_malicious.map((item, idx) => (
                  <li key={idx}>{item}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Hybrid RAG Grounding */}
      {incident.rag_matches.length > 0 && (
        <div className="pt-4 border-t border-slate-800/80">
          <h4 className="text-sm font-semibold text-slate-100 mb-2.5">
            Hybrid RAG Threat Intelligence (MITRE v20.1 · NIST 800-61r3 · CISA KEV · SOC Memory)
          </h4>
          <div className="divide-y divide-slate-800/70 border border-slate-800 rounded-lg">
            {incident.rag_matches.map((doc) => (
              <div key={doc.id} className="px-3 py-2.5 flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 text-xs">
                    <span className="font-mono font-semibold text-sky-400">{doc.ref_id}</span>
                    <span className="text-slate-600">·</span>
                    <span className="text-slate-400">{doc.source_type.replace(/_/g, ' ')}</span>
                  </div>
                  <div className="text-xs font-medium text-slate-100 mt-0.5">{doc.title}</div>
                  <div className="text-xs text-slate-400 mt-0.5">{doc.summary}</div>
                </div>
                {doc.relevance_score && (
                  <span className="text-xs font-mono tabular-nums text-slate-400 shrink-0">
                    {(doc.relevance_score * 100).toFixed(0)}%
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Gate E9 Deterministic Safety Auditor + Blast-Radius Dry-Run */}
      {incident.gate_e9 && (
        <div className="pt-4 border-t border-slate-800/80">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
            <h4 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              {incident.gate_e9.passed ? (
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
              ) : (
                <ShieldAlert className="w-4 h-4 text-rose-400" />
              )}
              Gate E9 Containment Rule &amp; Blast-Radius Dry-Run
            </h4>
            <span
              className={`text-xs font-mono ${incident.gate_e9.passed ? 'text-emerald-400' : 'text-rose-400'}`}
            >
              {incident.gate_e9.verified_badge}
            </span>
          </div>
          <div className="bg-[#070B12] border border-slate-800 rounded-lg px-3 py-2.5 font-mono text-xs text-sky-300 overflow-x-auto">
            {incident.containment_rule}
          </div>
          {incident.gate_e9.violations.length > 0 && (
            <ul className="mt-2 space-y-1 text-xs text-rose-400 list-disc list-inside">
              {incident.gate_e9.violations.map((v, idx) => (
                <li key={idx}>{v}</li>
              ))}
            </ul>
          )}
          <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
            <div className="text-xs text-slate-400">
              {incident.rule_approved
                ? `Approved by ${incident.approved_by ?? 'SOC Supervisor'} at ${incident.approved_utc?.slice(0, 19).replace('T', ' ')} UTC`
                : 'Human-in-the-loop authorization required. Commands are never auto-executed.'}
            </div>
            <div className="flex items-center gap-2">
              {onOpenChat && (
                <button
                  type="button"
                  onClick={() => onOpenChat(incident.id, incident.src_ip)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800/90 hover:bg-slate-700 border border-slate-700 rounded-md transition-colors whitespace-nowrap"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                  Investigate in AI Chat
                </button>
              )}
              {onApproveRule && incident.gate_e9.passed && !incident.rule_approved && (
                <button
                  type="button"
                  disabled={approving}
                  onClick={handleApprove}
                  className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium text-slate-950 bg-emerald-400 hover:bg-emerald-300 disabled:opacity-50 rounded-md transition-colors whitespace-nowrap"
                >
                  <Check className="w-3.5 h-3.5" />
                  {approving ? 'Approving...' : 'Approve Containment Rule'}
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
