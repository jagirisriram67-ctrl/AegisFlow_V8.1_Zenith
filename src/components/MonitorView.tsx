import { useState } from 'react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { ChevronRight, Pause, Play, SlidersHorizontal, Zap } from 'lucide-react';
import type { DashboardMetrics, FlowRecord, IncidentRecord } from '../types/soc';
import { bypassLabel, ZoneTag } from './ZoneIndicator';
import { XaiWaterfallPanel } from './XaiWaterfallPanel';

interface Props {
  metrics: DashboardMetrics;
  incidents: IncidentRecord[];
  recentFlows: FlowRecord[];
  onToggleSensor: (running: boolean, rate?: number) => Promise<void>;
  onApproveRule: (incidentId: string) => Promise<void>;
  onNavigateModule: (mod: string, opts?: { incidentId?: string; ip?: string }) => void;
}

export function MonitorView({
  metrics,
  incidents,
  recentFlows,
  onToggleSensor,
  onApproveRule,
  onNavigateModule,
}: Props) {
  const [selectedId, setSelectedId] = useState<string | null>(incidents[0]?.id ?? null);
  const selectedIncident = incidents.find((i) => i.id === selectedId) ?? incidents[0] ?? null;

  return (
    <div className="space-y-6">
      {/* Live KPI Strip */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-px bg-slate-800 border border-slate-800 rounded-lg overflow-hidden">
        <div className="bg-[#0F1623] px-4 py-3.5">
          <div className="text-xs text-slate-400">Live Throughput</div>
          <div className="text-xl font-semibold font-mono tabular-nums text-slate-100 mt-1">
            {metrics.flows_per_sec.toFixed(1)} <span className="text-xs font-normal text-slate-400">flows/s</span>
          </div>
          <div className="text-xs text-slate-500 font-mono tabular-nums mt-1">
            {metrics.total_flows.toLocaleString()} total stored
          </div>
        </div>

        <div className="bg-[#0F1623] px-4 py-3.5">
          <div className="text-xs text-slate-400">Active P1/P2 Campaigns</div>
          <div className="text-xl font-semibold font-mono tabular-nums text-rose-400 mt-1">
            {metrics.active_p1_p2}
          </div>
          <div className="text-xs text-slate-500 font-mono tabular-nums mt-1">
            {metrics.zone_counts.RED.toLocaleString()} Zone 3 flows
          </div>
        </div>

        <button
          type="button"
          onClick={() => onNavigateModule('clarify')}
          className="bg-[#0F1623] hover:bg-[#141D2E] text-left px-4 py-3.5 transition-colors"
        >
          <div className="text-xs text-slate-400">Pending Clarifications</div>
          <div className="text-xl font-semibold font-mono tabular-nums text-amber-400 mt-1">
            {metrics.pending_clarifications}
          </div>
          <div className="text-xs text-slate-500 mt-1">
            Zone 2A/2B · Open Inbox →
          </div>
        </button>

        <div className="bg-[#0F1623] px-4 py-3.5">
          <div className="text-xs text-slate-400">Tier-0 Repeat Savings</div>
          <div className="text-xl font-semibold font-mono tabular-nums text-sky-400 mt-1">
            {metrics.tier0_savings_pct.toFixed(1)}%
          </div>
          <div className="text-xs text-slate-500 font-mono tabular-nums mt-1">
            {metrics.tier0_hits.toLocaleString()} T0 ({metrics.avg_tier0_latency_ms}ms) · {metrics.tier1_hits} T1 poly
          </div>
        </div>

        <div className="bg-[#0F1623] px-4 py-3.5">
          <div className="text-xs text-slate-400">Benign FPR &amp; API Saved</div>
          <div className="text-xl font-semibold font-mono tabular-nums text-emerald-400 mt-1">
            {metrics.benign_fpr_pct.toFixed(2)}%
          </div>
          <div className="text-xs text-slate-500 font-mono tabular-nums mt-1">
            ${metrics.estimated_api_dollars_saved.toFixed(3)} LLM saved
          </div>
        </div>
      </div>

      {/* Real-Time Throughput Chart & 24/7 Sensor Controls */}
      <div className="bg-[#0F1623] border border-slate-800 rounded-lg p-5">
        <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">
              24/7 Real-Time Conformal Zone Stream &amp; Tier-0 Short-Circuit Rate
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Active profile: <span className="font-mono text-slate-200">{metrics.active_profile}</span> · Stage 3 avg{' '}
              <span className="font-mono tabular-nums text-slate-200">{metrics.avg_model_latency_ms}ms</span> vs Tier-0{' '}
              <span className="font-mono tabular-nums text-sky-400">{metrics.avg_tier0_latency_ms}ms</span>
            </p>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <SlidersHorizontal className="w-3.5 h-3.5" />
              <label htmlFor="sensor-rate" className="whitespace-nowrap">Rate</label>
              <select
                id="sensor-rate"
                value={metrics.sensor_rate_fps}
                onChange={(e) => onToggleSensor(metrics.sensor_running, Number(e.target.value))}
                className="bg-[#090D16] border border-slate-700 rounded px-2 py-1 text-xs font-mono text-slate-200 focus:outline-none focus:border-sky-500"
              >
                <option value={0.5}>0.5 /s</option>
                <option value={1}>1.0 /s</option>
                <option value={1.5}>1.5 /s</option>
                <option value={3}>3.0 /s</option>
              </select>
            </div>
            <button
              type="button"
              onClick={() => onToggleSensor(!metrics.sensor_running)}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors whitespace-nowrap ${
                metrics.sensor_running
                  ? 'bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700'
                  : 'bg-sky-500 hover:bg-sky-400 text-slate-950'
              }`}
            >
              {metrics.sensor_running ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
              {metrics.sensor_running ? 'Pause Sensor' : 'Start 24/7 Sensor'}
            </button>
          </div>
        </div>

        <div className="h-52 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={metrics.throughput_series} margin={{ top: 6, right: 12, left: -18, bottom: 0 }}>
              <CartesianGrid stroke="#1E293B" strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="time" stroke="#64748B" tick={{ fontSize: 11, fontFamily: 'JetBrains Mono' }} />
              <YAxis stroke="#64748B" tick={{ fontSize: 11, fontFamily: 'JetBrains Mono' }} />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#0B111E',
                  borderColor: '#334155',
                  borderRadius: '6px',
                  fontSize: '12px',
                  fontFamily: 'JetBrains Mono',
                }}
              />
              <Area type="monotone" dataKey="green" name="Zone 1 Benign" stroke="#10B981" fill="#10B981" fillOpacity={0.14} strokeWidth={1.75} />
              <Area type="monotone" dataKey="tier0_bypass" name="Tier-0 Bypass (<0.05ms)" stroke="#38BDF8" fill="#38BDF8" fillOpacity={0.18} strokeWidth={1.75} />
              <Area type="monotone" dataKey="yellow" name="Zone 2A Boundary" stroke="#EAB308" fill="#EAB308" fillOpacity={0.14} strokeWidth={1.75} />
              <Area type="monotone" dataKey="amber" name="Zone 2B Gray-Zone" stroke="#F59E0B" fill="#F59E0B" fillOpacity={0.14} strokeWidth={1.75} />
              <Area type="monotone" dataKey="red" name="Zone 3 Critical/ZD" stroke="#EF4444" fill="#EF4444" fillOpacity={0.2} strokeWidth={1.75} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Deduplicated Live Campaign Stream + Deep Inspection Workspace */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
        {/* Left: Deduplicated Campaign Cards (Zero Row Spam) */}
        <div className="xl:col-span-5 bg-[#0F1623] border border-slate-800 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-100">
              Deduplicated Campaign Feed ({incidents.length})
            </h3>
            <span className="text-xs text-slate-400">Zero duplicate alert rows</span>
          </div>
          <div className="divide-y divide-slate-800/80 max-h-[600px] overflow-y-auto">
            {incidents.length === 0 ? (
              <div className="p-8 text-center text-sm text-slate-400">
                No active campaigns detected yet. Send a test flow in Flow Sender Lab.
              </div>
            ) : (
              incidents.map((inc) => {
                const active = selectedIncident?.id === inc.id;
                return (
                  <button
                    key={inc.id}
                    type="button"
                    onClick={() => setSelectedId(inc.id)}
                    className={`w-full text-left px-4 py-3.5 transition-colors block ${
                      active ? 'bg-slate-800/60' : 'hover:bg-slate-900/50'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="font-mono text-xs text-slate-400 shrink-0">{inc.id}</span>
                        <span className="text-sm font-semibold text-slate-100 truncate">{inc.label}</span>
                      </div>
                      <ChevronRight className={`w-4 h-4 shrink-0 ${active ? 'text-sky-400' : 'text-slate-600'}`} />
                    </div>

                    <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-slate-400 mt-1.5">
                      <ZoneTag zone={inc.zone} compact />
                      <span>·</span>
                      <span className="font-mono tabular-nums text-slate-300">
                        {inc.src_ip} → {inc.dst_ip}:{inc.dst_port}
                      </span>
                    </div>

                    <div className="flex flex-wrap items-center justify-between gap-2 mt-2 text-xs font-mono tabular-nums">
                      <span className="inline-flex items-center gap-1 text-sky-400">
                        <Zap className="w-3.5 h-3.5" />
                        x{inc.repeat_hit_count.toLocaleString()} hits
                        {inc.polymorphic_count > 0 ? ` (+${inc.polymorphic_count} poly)` : ''}
                      </span>
                      <span className="text-slate-500">
                        MetaOOD {inc.meta_ood_score.toFixed(2)} · {inc.last_seen_utc.slice(11, 19)}Z
                      </span>
                    </div>
                  </button>
                );
              })
            )}
          </div>
        </div>

        {/* Right: Active Incident XAI + RAG + Gate E9 Inspector */}
        <div className="xl:col-span-7 bg-[#0F1623] border border-slate-800 rounded-lg p-5">
          {selectedIncident ? (
            <div>
              <div className="flex flex-wrap items-start justify-between gap-4 pb-4 mb-5 border-b border-slate-800">
                <div>
                  <div className="flex items-center gap-2 text-xs text-slate-400">
                    <span className="font-mono text-slate-300">{selectedIncident.id}</span>
                    <span>·</span>
                    <ZoneTag zone={selectedIncident.zone} />
                    <span>·</span>
                    <span>Status: {selectedIncident.status.replace(/_/g, ' ')}</span>
                  </div>
                  <h3 className="text-lg font-semibold text-slate-100 mt-1">
                    {selectedIncident.label}
                  </h3>
                  <div className="text-xs font-mono tabular-nums text-slate-400 mt-1">
                    {selectedIncident.src_ip} → {selectedIncident.dst_ip}:{selectedIncident.dst_port} · SimHash-64{' '}
                    <span className="text-slate-200">{selectedIncident.simhash64}</span> · Nearest Closed Class{' '}
                    <span className="text-slate-200">{selectedIncident.closed_nearest_class}</span>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => onNavigateModule('forensics', { ip: selectedIncident.src_ip })}
                    className="px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-md transition-colors whitespace-nowrap"
                  >
                    Host ChronoGraph
                  </button>
                  {selectedIncident.status === 'NEEDS_CLARIFICATION' && (
                    <button
                      type="button"
                      onClick={() => onNavigateModule('clarify', { incidentId: selectedIncident.id })}
                      className="px-3 py-1.5 text-xs font-medium text-slate-950 bg-amber-400 hover:bg-amber-300 rounded-md transition-colors whitespace-nowrap"
                    >
                      Resolve in Inbox
                    </button>
                  )}
                </div>
              </div>

              <XaiWaterfallPanel
                incident={selectedIncident}
                onApproveRule={onApproveRule}
                onOpenChat={(id, ip) => onNavigateModule('chat', { incidentId: id, ip })}
              />
            </div>
          ) : (
            <div className="py-16 text-center text-sm text-slate-400">
              Select a campaign card on the left to inspect IG-SHAP, GPU-LIME, Hybrid RAG, and Gate E9 containment verification.
            </div>
          )}
        </div>
      </div>

      {/* Live Wire Flow Tail */}
      <div className="bg-[#0F1623] border border-slate-800 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-100">Latest Processed Wire Flows</h3>
          <button
            type="button"
            onClick={() => onNavigateModule('forensics')}
            className="text-xs text-sky-400 hover:text-sky-300 transition-colors"
          >
            Open Full Forensics Ledger →
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-[#0B111E] border-b border-slate-800 text-slate-400">
                <th className="py-2.5 px-3 font-medium">Time (UTC)</th>
                <th className="py-2.5 px-3 font-medium">Zone</th>
                <th className="py-2.5 px-3 font-medium">Verdict</th>
                <th className="py-2.5 px-3 font-medium">Source → Target</th>
                <th className="py-2.5 px-3 font-medium">Execution Path</th>
                <th className="py-2.5 px-3 font-medium text-right">Latency</th>
                <th className="py-2.5 px-3 font-medium text-right">MetaOOD</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {recentFlows.slice(0, 10).map((f) => {
                const bp = bypassLabel(f.bypass_stage);
                return (
                  <tr key={f.id} className="hover:bg-slate-900/40">
                    <td className="py-2 px-3 font-mono tabular-nums text-slate-400">
                      {f.timestamp_utc.slice(11, 19)}
                    </td>
                    <td className="py-2 px-3">
                      <ZoneTag zone={f.zone} compact />
                    </td>
                    <td className="py-2 px-3 text-slate-200 font-medium max-w-[240px] truncate" title={f.verdict}>
                      {f.verdict}
                    </td>
                    <td className="py-2 px-3 font-mono tabular-nums text-slate-300">
                      {f.src_ip} → {f.dst_ip}:{f.dst_port}
                    </td>
                    <td className={`py-2 px-3 font-medium ${bp.tone}`}>{bp.text}</td>
                    <td className="py-2 px-3 text-right font-mono tabular-nums text-slate-200">
                      {f.latency_ms.toFixed(3)} ms
                    </td>
                    <td className="py-2 px-3 text-right font-mono tabular-nums text-slate-300">
                      {f.meta_ood_score.toFixed(2)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
