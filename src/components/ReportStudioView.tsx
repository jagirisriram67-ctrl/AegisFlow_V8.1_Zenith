import { useEffect, useState } from 'react';
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { CalendarClock, Download, FileCode2, FileSpreadsheet, FileText, Play, Shield } from 'lucide-react';
import type { GatewaySettings, PeriodReportData, ScheduledReportEntry } from '../types/soc';
import { ZoneTag } from './ZoneIndicator';

interface Props {
  autoSchedule: GatewaySettings['report_auto_schedule'];
  onUpdateAutoSchedule: (schedule: GatewaySettings['report_auto_schedule']) => Promise<void>;
}

const WINDOWS = [
  { id: '1h', label: 'Last 1 Hour' },
  { id: '8h', label: 'Last 8 Hours (Shift)' },
  { id: '24h', label: 'Last 24 Hours' },
  { id: '7d', label: 'Last 7 Days' },
  { id: 'custom', label: 'Custom Range' },
];

export function ReportStudioView({ autoSchedule, onUpdateAutoSchedule }: Props) {
  const [windowPreset, setWindowPreset] = useState('24h');
  const [customStart, setCustomStart] = useState(() =>
    new Date(Date.now() - 24 * 3600_000).toISOString().slice(0, 16)
  );
  const [customEnd, setCustomEnd] = useState(() => new Date().toISOString().slice(0, 16));
  const [report, setReport] = useState<PeriodReportData | null>(null);
  const [scheduledReports, setScheduledReports] = useState<ScheduledReportEntry[]>([]);
  const [capturingDigest, setCapturingDigest] = useState(false);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState<string | null>(null);

  const buildQuery = () => {
    const qs = new URLSearchParams({ window: windowPreset });
    if (windowPreset === 'custom') {
      qs.set('start', new Date(customStart).toISOString());
      qs.set('end', new Date(customEnd).toISOString());
    }
    return qs.toString();
  };

  const loadPreview = async () => {
    setLoading(true);
    try {
      const res = await fetch(`/api/reports/preview?${buildQuery()}`);
      if (res.ok) setReport(await res.json());
    } finally {
      setLoading(false);
    }
  };

  const loadScheduled = async () => {
    const res = await fetch('/api/reports/scheduled');
    if (res.ok) {
      const data = await res.json();
      setScheduledReports(data.reports ?? []);
    }
  };

  const runScheduledSnapshot = async () => {
    setCapturingDigest(true);
    try {
      const res = await fetch('/api/reports/scheduled/run', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setScheduledReports(data.reports ?? []);
      }
    } finally {
      setCapturingDigest(false);
    }
  };

  useEffect(() => {
    void loadPreview();
  }, [windowPreset, customStart, customEnd]);

  useEffect(() => {
    void loadScheduled();
  }, [autoSchedule]);

  const downloadFormat = async (
    format: 'pdf' | 'docx' | 'html' | 'csv' | 'stix',
    overrideQuery?: string
  ) => {
    setDownloading(format);
    try {
      const res = await fetch(`/api/reports/export/${format}?${overrideQuery ?? buildQuery()}`);
      if (!res.ok) return;
      const blob = await res.blob();
      const disp = res.headers.get('content-disposition') ?? '';
      const match = disp.match(/filename="([^"]+)"/);
      const filename = match?.[1] ?? `AegisFlow_Report_${windowPreset}.${format === 'stix' ? 'json' : format}`;
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } finally {
      setDownloading(null);
    }
  };

  const chartData = report
    ? [
        { name: 'Zone 1 Benign', count: report.zone_breakdown.GREEN, color: '#10B981' },
        { name: 'Zone 2A Boundary', count: report.zone_breakdown.YELLOW, color: '#EAB308' },
        { name: 'Zone 2B Gray-Zone', count: report.zone_breakdown.AMBER, color: '#F59E0B' },
        { name: 'Zone 3 Critical', count: report.zone_breakdown.RED, color: '#EF4444' },
      ]
    : [];

  return (
    <div className="space-y-6">
      {/* Controls & Export Strip */}
      <div className="bg-[#0F1623] border border-slate-800 rounded-lg p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">
              Automated Period Report Studio (PDF · DOCX · HTML · CSV · STIX 2.1)
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Select any reporting window or configure scheduled shift digests with embedded charts and Gate E9 logs
            </p>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <CalendarClock className="w-4 h-4 text-slate-400" />
            <label htmlFor="auto-sched" className="text-slate-400 whitespace-nowrap">Auto-Schedule</label>
            <select
              id="auto-sched"
              value={autoSchedule}
              onChange={(e) => onUpdateAutoSchedule(e.target.value as GatewaySettings['report_auto_schedule'])}
              className="bg-[#090D16] border border-slate-700 rounded-md px-2.5 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-sky-500"
            >
              <option value="OFF">Manual Only</option>
              <option value="HOURLY">Every 1 Hour</option>
              <option value="SHIFT_8H">Every 8-Hour Shift</option>
              <option value="DAILY_24H">Daily (24h UTC)</option>
              <option value="WEEKLY_7D">Weekly (7d)</option>
            </select>
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-4 pt-3 border-t border-slate-800/80">
          <div className="flex flex-wrap items-center gap-1.5">
            {WINDOWS.map((w) => (
              <button
                key={w.id}
                type="button"
                onClick={() => setWindowPreset(w.id)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md border transition-colors whitespace-nowrap ${
                  windowPreset === w.id
                    ? 'bg-sky-500/15 border-sky-500/50 text-sky-300'
                    : 'bg-[#0B111E] border-slate-800 text-slate-300 hover:border-slate-700'
                }`}
              >
                {w.label}
              </button>
            ))}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              disabled={downloading !== null}
              onClick={() => downloadFormat('pdf')}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold text-slate-950 bg-sky-400 hover:bg-sky-300 disabled:opacity-50 rounded-md transition-colors whitespace-nowrap"
            >
              <Download className="w-3.5 h-3.5" />
              {downloading === 'pdf' ? 'Building PDF...' : 'Download PDF'}
            </button>
            <button
              type="button"
              disabled={downloading !== null}
              onClick={() => downloadFormat('docx')}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-100 bg-slate-800 hover:bg-slate-700 border border-slate-700 disabled:opacity-50 rounded-md transition-colors whitespace-nowrap"
            >
              <FileText className="w-3.5 h-3.5" />
              {downloading === 'docx' ? 'Building DOCX...' : 'DOCX'}
            </button>
            <button
              type="button"
              disabled={downloading !== null}
              onClick={() => downloadFormat('html')}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-[#0B111E] hover:bg-slate-800 border border-slate-800 rounded-md transition-colors whitespace-nowrap"
            >
              <FileCode2 className="w-3.5 h-3.5" />
              HTML
            </button>
            <button
              type="button"
              disabled={downloading !== null}
              onClick={() => downloadFormat('csv')}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-[#0B111E] hover:bg-slate-800 border border-slate-800 rounded-md transition-colors whitespace-nowrap"
            >
              <FileSpreadsheet className="w-3.5 h-3.5" />
              CSV Ledger
            </button>
            <button
              type="button"
              disabled={downloading !== null}
              onClick={() => downloadFormat('stix')}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-[#0B111E] hover:bg-slate-800 border border-slate-800 rounded-md transition-colors whitespace-nowrap"
            >
              <Shield className="w-3.5 h-3.5" />
              STIX 2.1
            </button>
          </div>
        </div>

        {windowPreset === 'custom' && (
          <div className="flex flex-wrap items-center gap-3 pt-2 text-xs">
            <label className="flex items-center gap-2 text-slate-400">
              Start (UTC)
              <input
                type="datetime-local"
                value={customStart}
                onChange={(e) => setCustomStart(e.target.value)}
                className="bg-[#090D16] border border-slate-700 rounded px-2.5 py-1 font-mono text-slate-100"
              />
            </label>
            <label className="flex items-center gap-2 text-slate-400">
              End (UTC)
              <input
                type="datetime-local"
                value={customEnd}
                onChange={(e) => setCustomEnd(e.target.value)}
                className="bg-[#090D16] border border-slate-700 rounded px-2.5 py-1 font-mono text-slate-100"
              />
            </label>
          </div>
        )}
      </div>

      {/* Live 7-Section Executive Report Preview */}
      {loading || !report ? (
        <div className="bg-[#0F1623] border border-slate-800 rounded-lg p-12 text-center text-sm text-slate-400">
          Aggregating persistent flow ledger and forensic metrics for selected period...
        </div>
      ) : (
        <div className="bg-[#0F1623] border border-slate-800 rounded-lg p-6 space-y-7">
          <div className="border-b border-slate-800 pb-4 flex flex-wrap items-baseline justify-between gap-2">
            <div>
              <h3 className="text-base font-semibold text-slate-100">
                1. Executive Security Posture &amp; Risk Delta — {report.window_label}
              </h3>
              <div className="text-xs font-mono text-slate-400 mt-1">
                {report.start_utc.slice(0, 19)}Z → {report.end_utc.slice(0, 19)}Z
              </div>
            </div>
            <div className="text-xs font-mono tabular-nums text-emerald-400">
              Posture Index: {report.posture_score}/100
            </div>
          </div>

          <p className="text-sm text-slate-300 leading-relaxed">{report.executive_summary}</p>

          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
            <div className="bg-[#0B111E] border border-slate-800 rounded p-3.5">
              <div className="text-slate-400">Flows Inspected</div>
              <div className="text-lg font-mono tabular-nums font-semibold text-slate-100 mt-1">
                {report.total_flows.toLocaleString()}
              </div>
            </div>
            <div className="bg-[#0B111E] border border-slate-800 rounded p-3.5">
              <div className="text-slate-400">Tier-0 Bypassed (&lt;0.05ms)</div>
              <div className="text-lg font-mono tabular-nums font-semibold text-sky-400 mt-1">
                {report.tier0_blocked.toLocaleString()} ({report.tier0_savings_pct}%)
              </div>
            </div>
            <div className="bg-[#0B111E] border border-slate-800 rounded p-3.5">
              <div className="text-slate-400">GPU Compute Saved</div>
              <div className="text-lg font-mono tabular-nums font-semibold text-emerald-400 mt-1">
                {report.gpu_ms_saved.toLocaleString()} ms
              </div>
            </div>
            <div className="bg-[#0B111E] border border-slate-800 rounded p-3.5">
              <div className="text-slate-400">Est. Cloud API Saved</div>
              <div className="text-lg font-mono tabular-nums font-semibold text-slate-100 mt-1">
                ${report.api_dollars_saved.toFixed(3)}
              </div>
            </div>
          </div>

          {/* Section 2 & 3: 4-Zone Breakdown Chart */}
          <div className="pt-4 border-t border-slate-800/80">
            <h4 className="text-sm font-semibold text-slate-100 mb-3">
              2. 4-Zone Conformal Distribution &amp; 3. Tier-0/1 Immunological Savings
            </h4>
            <div className="h-48">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} layout="vertical" margin={{ top: 4, right: 24, left: 20, bottom: 4 }}>
                  <CartesianGrid stroke="#1E293B" strokeDasharray="3 3" horizontal={false} />
                  <XAxis type="number" stroke="#64748B" tick={{ fontSize: 11, fontFamily: 'JetBrains Mono' }} />
                  <YAxis dataKey="name" type="category" stroke="#94A3B8" tick={{ fontSize: 11 }} width={125} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0B111E',
                      borderColor: '#334155',
                      borderRadius: '6px',
                      fontSize: '12px',
                      fontFamily: 'JetBrains Mono',
                    }}
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {chartData.map((entry, idx) => (
                      <Cell key={idx} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Section 4: Critical Incidents */}
          <div className="pt-4 border-t border-slate-800/80">
            <h4 className="text-sm font-semibold text-slate-100 mb-3">
              4. Critical Incidents &amp; Zero-Day Forensics ({report.top_incidents.length})
            </h4>
            <div className="border border-slate-800 rounded-lg overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-[#0B111E] border-b border-slate-800 text-slate-400">
                    <th className="py-2 px-3 font-medium">ID</th>
                    <th className="py-2 px-3 font-medium">Zone</th>
                    <th className="py-2 px-3 font-medium">Classification</th>
                    <th className="py-2 px-3 font-medium">Source → Target</th>
                    <th className="py-2 px-3 font-medium text-right">Repeats</th>
                    <th className="py-2 px-3 font-medium text-right">MetaOOD</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {report.top_incidents.map((inc) => (
                    <tr key={inc.id}>
                      <td className="py-2 px-3 font-mono text-slate-300">{inc.id}</td>
                      <td className="py-2 px-3"><ZoneTag zone={inc.zone} compact /></td>
                      <td className="py-2 px-3 text-slate-100 font-medium">{inc.label}</td>
                      <td className="py-2 px-3 font-mono tabular-nums text-slate-300">
                        {inc.src_ip} → {inc.dst_ip}:{inc.dst_port}
                      </td>
                      <td className="py-2 px-3 text-right font-mono tabular-nums text-sky-400">
                        x{inc.repeat_hit_count}
                      </td>
                      <td className="py-2 px-3 text-right font-mono tabular-nums text-slate-200">
                        {inc.meta_ood_score.toFixed(2)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Section 5 & 6: Gate E9 + Clarification Audit */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 pt-4 border-t border-slate-800/80">
            <div>
              <h4 className="text-sm font-semibold text-slate-100 mb-2.5">
                5. Gate E9 Containment Verification Log
              </h4>
              <div className="space-y-2">
                {report.gate_e9_log.slice(0, 5).map((g) => (
                  <div key={g.incident_id} className="bg-[#0B111E] border border-slate-800 rounded p-2.5 text-xs">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-slate-200">{g.incident_id} · {g.label}</span>
                      <span className={g.approved ? 'text-emerald-400' : g.passed ? 'text-sky-400' : 'text-rose-400'}>
                        {g.approved ? 'Approved' : g.passed ? `0.00% Verified` : 'Blocked'}
                      </span>
                    </div>
                    <code className="block text-[11px] text-slate-400 mt-1 truncate">{g.command}</code>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <h4 className="text-sm font-semibold text-slate-100 mb-2.5">
                6. Prioritized Hardening Roadmap (NIST SP 800-61r3)
              </h4>
              <div className="space-y-2">
                {report.hardening_roadmap.map((item, idx) => (
                  <div key={idx} className="bg-[#0B111E] border border-slate-800 rounded p-2.5 text-xs">
                    <div className="font-medium text-slate-100">
                      <span className="font-mono text-amber-400 mr-1.5">[{item.priority} · {item.nist_stage}]</span>
                      {item.title}
                    </div>
                    <div className="text-slate-400 mt-0.5">{item.rationale}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Automated Scheduled Shift Digest Archive */}
      <div className="bg-[#0F1623] border border-slate-800 rounded-lg overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-slate-100">
              Scheduled Shift Digest Archive ({scheduledReports.length})
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Persisted automated digests generated by the backend scheduler ({autoSchedule.replace(/_/g, ' ')})
            </p>
          </div>
          <button
            type="button"
            disabled={capturingDigest}
            onClick={runScheduledSnapshot}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-100 bg-slate-800 hover:bg-slate-700 border border-slate-700 disabled:opacity-50 rounded-md transition-colors whitespace-nowrap"
          >
            <Play className="w-3.5 h-3.5 text-sky-400" />
            {capturingDigest ? 'Capturing...' : 'Capture Shift Digest Now'}
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-[#0B111E] border-b border-slate-800 text-slate-400">
                <th className="py-2.5 px-4 font-medium">Digest ID</th>
                <th className="py-2.5 px-4 font-medium">Generated (UTC)</th>
                <th className="py-2.5 px-4 font-medium">Window &amp; Trigger</th>
                <th className="py-2.5 px-4 font-medium text-right">Posture</th>
                <th className="py-2.5 px-4 font-medium text-right">Flows / RED</th>
                <th className="py-2.5 px-4 font-medium text-right">Export</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {scheduledReports.map((item) => {
                const q = new URLSearchParams({
                  window: 'custom',
                  start: item.start_utc,
                  end: item.end_utc,
                }).toString();
                return (
                  <tr key={item.id} className="hover:bg-slate-900/40">
                    <td className="py-2.5 px-4 font-mono text-slate-200">{item.id}</td>
                    <td className="py-2.5 px-4 font-mono tabular-nums text-slate-400">
                      {item.generated_utc.slice(0, 19).replace('T', ' ')}Z
                    </td>
                    <td className="py-2.5 px-4 text-slate-300">
                      {item.window_label}{' '}
                      <span className="text-[11px] font-mono text-slate-500">
                        ({item.trigger_source === 'AUTO_SCHEDULER' ? 'Scheduled' : 'Manual'})
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-right font-mono tabular-nums text-emerald-400">
                      {item.posture_score}/100
                    </td>
                    <td className="py-2.5 px-4 text-right font-mono tabular-nums text-slate-300">
                      {item.total_flows.toLocaleString()} / <span className="text-rose-400">{item.red_flows}</span>
                    </td>
                    <td className="py-2.5 px-4 text-right whitespace-nowrap space-x-2">
                      <button
                        type="button"
                        onClick={() => downloadFormat('pdf', q)}
                        className="text-sky-400 hover:text-sky-300 font-medium"
                      >
                        PDF
                      </button>
                      <button
                        type="button"
                        onClick={() => downloadFormat('docx', q)}
                        className="text-slate-300 hover:text-white font-medium"
                      >
                        DOCX
                      </button>
                      <button
                        type="button"
                        onClick={() => downloadFormat('stix', q)}
                        className="text-slate-400 hover:text-white font-medium"
                      >
                        STIX
                      </button>
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

