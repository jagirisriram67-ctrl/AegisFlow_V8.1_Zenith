import { useEffect, useState } from 'react';
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { Search } from 'lucide-react';
import type { ChronoGraphHostData, FlowRecord } from '../types/soc';
import { bypassLabel, ZoneTag } from './ZoneIndicator';

interface Props {
  focusIp?: string | null;
}

export function ForensicsLedgerView({ focusIp }: Props) {
  const [flows, setFlows] = useState<FlowRecord[]>([]);
  const [hosts, setHosts] = useState<Array<{ src_ip: string; flow_count: number; max_martingale: number; max_cusum: number }>>([]);
  const [ipFilter, setIpFilter] = useState(focusIp ?? '');
  const [zoneFilter, setZoneFilter] = useState('');
  const [labelFilter, setLabelFilter] = useState('');
  const [simhashFilter, setSimhashFilter] = useState('');
  const [selectedHostIp, setSelectedHostIp] = useState(focusIp || '10.20.30.99');
  const [selectedFlow, setSelectedFlow] = useState<FlowRecord | null>(null);
  const [chrono, setChrono] = useState<ChronoGraphHostData | null>(null);
  const [loading, setLoading] = useState(true);

  const loadFlows = async () => {
    setLoading(true);
    try {
      const qs = new URLSearchParams();
      if (ipFilter) qs.set('ip', ipFilter);
      if (zoneFilter) qs.set('zone', zoneFilter);
      if (labelFilter) qs.set('label', labelFilter);
      if (simhashFilter) qs.set('simhash', simhashFilter);
      qs.set('limit', '120');
      const res = await fetch(`/api/flows?${qs.toString()}`);
      const data = await res.json();
      setFlows(data.flows ?? []);
      setHosts(data.hosts ?? []);
      if (!selectedHostIp && data.hosts?.[0]?.src_ip) {
        setSelectedHostIp(data.hosts[0].src_ip);
      }
    } finally {
      setLoading(false);
    }
  };

  const loadChrono = async (ip: string) => {
    if (!ip) return;
    const res = await fetch(`/api/chronograph/${encodeURIComponent(ip)}`);
    if (res.ok) setChrono(await res.json());
  };

  useEffect(() => {
    void loadFlows();
  }, [ipFilter, zoneFilter, labelFilter, simhashFilter]);

  useEffect(() => {
    if (focusIp) {
      setSelectedHostIp(focusIp);
      setIpFilter(focusIp);
    }
  }, [focusIp]);

  useEffect(() => {
    void loadChrono(selectedHostIp);
  }, [selectedHostIp]);

  return (
    <div className="space-y-6">
      {/* ChronoGraph Stateful Temporal Correlation & Kill-Chain Timeline */}
      <div className="bg-[#0F1623] border border-slate-800 rounded-lg p-5 space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">
              Stage 4 ChronoGraph Temporal Correlation &amp; Kill-Chain Timeline
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Page-Hinkley CUSUM Drift · Self-Exciting Hawkes Intensity λ(t) · Vovk Conformal Martingale M_t (auto-escalates ≥ 100)
            </p>
          </div>
          <div className="flex items-center gap-2">
            <label htmlFor="chrono-host-select" className="text-xs text-slate-400">Inspect Host</label>
            <select
              id="chrono-host-select"
              value={selectedHostIp}
              onChange={(e) => setSelectedHostIp(e.target.value)}
              className="bg-[#090D16] border border-slate-700 rounded-md px-3 py-1.5 text-xs font-mono text-slate-100 focus:outline-none focus:border-sky-500"
            >
              {hosts.map((h) => (
                <option key={h.src_ip} value={h.src_ip}>
                  {h.src_ip} ({h.flow_count} flows · M_t {Number(h.max_martingale).toFixed(0)})
                </option>
              ))}
            </select>
          </div>
        </div>

        {chrono && (
          <>
            <div className="grid grid-cols-2 lg:grid-cols-5 gap-3 text-xs">
              <div className="bg-[#0B111E] border border-slate-800 rounded p-3">
                <div className="text-slate-500">Host &amp; Subnet</div>
                <div className="font-mono text-slate-100 font-semibold mt-1">{chrono.src_ip}</div>
                <div className="font-mono text-[11px] text-slate-500">{chrono.subnet}</div>
              </div>
              <div className="bg-[#0B111E] border border-slate-800 rounded p-3">
                <div className="text-slate-500">CUSUM Drift D(t)</div>
                <div className="font-mono tabular-nums text-sky-400 text-base font-semibold mt-1">
                  {chrono.current_cusum.toFixed(2)}
                </div>
              </div>
              <div className="bg-[#0B111E] border border-slate-800 rounded p-3">
                <div className="text-slate-500">Hawkes Intensity λ(t)</div>
                <div className="font-mono tabular-nums text-amber-400 text-base font-semibold mt-1">
                  {chrono.current_hawkes.toFixed(2)}
                </div>
              </div>
              <div className="bg-[#0B111E] border border-slate-800 rounded p-3">
                <div className="text-slate-500">Conformal Martingale M_t</div>
                <div className={`font-mono tabular-nums text-base font-semibold mt-1 ${chrono.current_martingale >= 100 ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {chrono.current_martingale.toFixed(1)}
                </div>
              </div>
              <div className="bg-[#0B111E] border border-slate-800 rounded p-3">
                <div className="text-slate-500">Assessment</div>
                <div className="text-slate-100 font-medium mt-1">{chrono.risk_stage}</div>
              </div>
            </div>

            <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-start">
              <div className="xl:col-span-8 h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={chrono.timeline} margin={{ top: 8, right: 16, left: -12, bottom: 0 }}>
                    <CartesianGrid stroke="#1E293B" strokeDasharray="3 3" vertical={false} />
                    <XAxis dataKey="time" stroke="#64748B" tick={{ fontSize: 11, fontFamily: 'JetBrains Mono' }} />
                    <YAxis yAxisId="left" stroke="#64748B" tick={{ fontSize: 11, fontFamily: 'JetBrains Mono' }} />
                    <YAxis yAxisId="right" orientation="right" stroke="#64748B" tick={{ fontSize: 11, fontFamily: 'JetBrains Mono' }} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0B111E',
                        borderColor: '#334155',
                        borderRadius: '6px',
                        fontSize: '12px',
                        fontFamily: 'JetBrains Mono',
                      }}
                    />
                    <Legend wrapperStyle={{ fontSize: '11px' }} />
                    <ReferenceLine yAxisId="right" y={100} stroke="#EF4444" strokeDasharray="4 4" label={{ value: 'M_t=100 Escalation', fill: '#F87171', fontSize: 10 }} />
                    <Line yAxisId="left" type="monotone" dataKey="cusum" name="CUSUM Drift" stroke="#38BDF8" strokeWidth={2} dot={false} />
                    <Line yAxisId="left" type="monotone" dataKey="hawkes" name="Hawkes λ(t)" stroke="#F59E0B" strokeWidth={2} dot={false} />
                    <Line yAxisId="right" type="monotone" dataKey="martingale" name="Martingale M_t" stroke="#EF4444" strokeWidth={2} dot={false} />
                  </LineChart>
                </ResponsiveContainer>
              </div>

              {/* Multi-Stage Kill-Chain Progression */}
              <div className="xl:col-span-4 border border-slate-800 rounded-lg p-3.5 bg-[#0B111E]">
                <div className="text-xs font-semibold text-slate-200 mb-3">
                  Correlated Kill-Chain Progression
                </div>
                {chrono.kill_chain_stages.length === 0 ? (
                  <div className="text-xs text-slate-500">No suspicious multi-stage transitions recorded for {chrono.src_ip}.</div>
                ) : (
                  <ol className="space-y-3">
                    {chrono.kill_chain_stages.map((st, idx) => (
                      <li key={idx} className="text-xs border-b border-slate-800/70 pb-2.5 last:border-none last:pb-0">
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-semibold text-slate-100">{idx + 1}. {st.stage}</span>
                          <ZoneTag zone={st.zone} compact />
                        </div>
                        <div className="font-mono tabular-nums text-[11px] text-slate-400 mt-1">
                          {st.timestamp_utc.slice(11, 19)}Z · {st.label} → {st.dst_ip}:{st.dst_port}
                        </div>
                      </li>
                    ))}
                  </ol>
                )}
              </div>
            </div>
          </>
        )}
      </div>

      {/* Persistent 24/7 Historical Flow Ledger */}
      <div className="bg-[#0F1623] border border-slate-800 rounded-lg overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <h3 className="text-sm font-semibold text-slate-100">
            24/7 Historical Flow &amp; Attack Forensics Ledger ({flows.length} shown)
          </h3>
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={ipFilter}
                onChange={(e) => setIpFilter(e.target.value)}
                placeholder="Filter IP..."
                className="bg-[#090D16] border border-slate-700 rounded-md pl-8 pr-2.5 py-1.5 text-xs font-mono text-slate-100 placeholder:text-slate-500 w-36 focus:outline-none focus:border-sky-500"
              />
            </div>
            <select
              aria-label="Filter Zone"
              value={zoneFilter}
              onChange={(e) => setZoneFilter(e.target.value)}
              className="bg-[#090D16] border border-slate-700 rounded-md px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
            >
              <option value="">All Zones</option>
              <option value="RED">Zone 3 · RED</option>
              <option value="AMBER">Zone 2B · AMBER</option>
              <option value="YELLOW">Zone 2A · YELLOW</option>
              <option value="GREEN">Zone 1 · GREEN</option>
            </select>
            <input
              type="text"
              value={labelFilter}
              onChange={(e) => setLabelFilter(e.target.value)}
              placeholder="Attack label..."
              className="bg-[#090D16] border border-slate-700 rounded-md px-2.5 py-1.5 text-xs text-slate-100 placeholder:text-slate-500 w-36 focus:outline-none focus:border-sky-500"
            />
            <input
              type="text"
              value={simhashFilter}
              onChange={(e) => setSimhashFilter(e.target.value)}
              placeholder="SimHash-64..."
              className="bg-[#090D16] border border-slate-700 rounded-md px-2.5 py-1.5 text-xs font-mono text-slate-100 placeholder:text-slate-500 w-32 focus:outline-none focus:border-sky-500"
            />
          </div>
        </div>

        <div className="overflow-x-auto max-h-[520px] overflow-y-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead className="sticky top-0 bg-[#0B111E] border-b border-slate-800 text-slate-400">
              <tr>
                <th className="py-2.5 px-3 font-medium">Timestamp (UTC)</th>
                <th className="py-2.5 px-3 font-medium">Zone</th>
                <th className="py-2.5 px-3 font-medium">Label / Verdict</th>
                <th className="py-2.5 px-3 font-medium">Source → Target</th>
                <th className="py-2.5 px-3 font-medium">SimHash-64</th>
                <th className="py-2.5 px-3 font-medium">Path</th>
                <th className="py-2.5 px-3 font-medium text-right">MetaOOD</th>
                <th className="py-2.5 px-3 font-medium text-right">CUSUM / M_t</th>
                <th className="py-2.5 px-3 font-medium text-right">Latency</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {loading ? (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-slate-400">
                    Querying persistent SQLite flow ledger...
                  </td>
                </tr>
              ) : flows.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-slate-400">
                    No flows match the active filter criteria.
                  </td>
                </tr>
              ) : (
                flows.map((f) => {
                  const bp = bypassLabel(f.bypass_stage);
                  return (
                    <tr
                      key={f.id}
                      onClick={() => {
                        setSelectedHostIp(f.src_ip);
                        setSelectedFlow(f);
                      }}
                      className={`hover:bg-slate-900/50 cursor-pointer ${
                        selectedFlow?.id === f.id ? 'bg-slate-800/60' : ''
                      }`}
                    >
                      <td className="py-2 px-3 font-mono tabular-nums text-slate-400 whitespace-nowrap">
                        {f.timestamp_utc.slice(5, 19).replace('T', ' ')}
                      </td>
                      <td className="py-2 px-3">
                        <ZoneTag zone={f.zone} compact />
                      </td>
                      <td className="py-2 px-3">
                        <div className="text-slate-100 font-medium max-w-[220px] truncate" title={f.verdict}>
                          {f.label}
                        </div>
                        <div className="text-[11px] text-slate-500 max-w-[220px] truncate">{f.verdict}</div>
                      </td>
                      <td className="py-2 px-3 font-mono tabular-nums text-slate-300 whitespace-nowrap">
                        {f.src_ip} → {f.dst_ip}:{f.dst_port}
                      </td>
                      <td className="py-2 px-3 font-mono text-slate-400">{f.simhash64}</td>
                      <td className={`py-2 px-3 whitespace-nowrap ${bp.tone}`}>{bp.text}</td>
                      <td className="py-2 px-3 text-right font-mono tabular-nums text-slate-200">
                        {f.meta_ood_score.toFixed(2)}
                      </td>
                      <td className="py-2 px-3 text-right font-mono tabular-nums text-slate-300 whitespace-nowrap">
                        {f.cusum_drift.toFixed(1)} / {f.martingale_value.toFixed(0)}
                      </td>
                      <td className="py-2 px-3 text-right font-mono tabular-nums text-slate-200 whitespace-nowrap">
                        {f.latency_ms.toFixed(3)}ms
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Inline Historical Flow Deep Forensic Drawer */}
        {selectedFlow && (
          <div className="border-t border-slate-800 bg-[#0B111E] p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2.5 text-xs">
                <ZoneTag zone={selectedFlow.zone} compact />
                <span className="font-semibold text-slate-100">{selectedFlow.verdict}</span>
                <span className="font-mono text-slate-400">
                  SimHash-64: {selectedFlow.simhash64} · Profile: {selectedFlow.profile_id}
                </span>
              </div>
              <button
                type="button"
                onClick={() => setSelectedFlow(null)}
                className="text-xs text-slate-400 hover:text-slate-100"
              >
                Close Inspector
              </button>
            </div>

            {selectedFlow.xai && selectedFlow.xai.top_features.length > 0 && (
              <div className="grid grid-cols-1 md:grid-cols-5 gap-2 text-xs">
                {selectedFlow.xai.top_features.map((feat) => (
                  <div key={feat.feature} className="bg-[#090D16] border border-slate-800 rounded p-2.5">
                    <div className="font-mono text-[11px] text-sky-400 truncate" title={feat.feature}>
                      {feat.feature}
                    </div>
                    <div className="font-mono tabular-nums text-slate-100 mt-1">
                      val {feat.value} <span className="text-slate-500">({feat.z_deviation >= 0 ? '+' : ''}{feat.z_deviation}σ)</span>
                    </div>
                    <div className="font-mono text-[10px] text-slate-400 mt-0.5">
                      SHAP {feat.ig_shap.toFixed(3)} · LFG {feat.lfg_gate.toFixed(2)}
                    </div>
                  </div>
                ))}
              </div>
            )}

            <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-2 text-[11px] font-mono tabular-nums">
              {Object.entries(selectedFlow.raw_features).slice(0, 12).map(([k, v]) => (
                <div key={k} className="bg-[#090D16] border border-slate-800/80 rounded px-2.5 py-1.5">
                  <div className="text-slate-500 truncate" title={k}>{k}</div>
                  <div className="text-slate-200 mt-0.5">{Number(v).toLocaleString()}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

