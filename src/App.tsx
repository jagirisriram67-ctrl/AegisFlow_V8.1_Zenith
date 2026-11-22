import { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  FileBarChart2,
  FlaskConical,
  HelpCircle,
  MessageSquare,
  Search,
  Settings,
  Shield,
  SlidersHorizontal,
  Sparkles,
} from 'lucide-react';
import type {
  DashboardMetrics,
  DatasetProfile,
  FlowRecord,
  GatewaySettings,
  IncidentRecord,
} from './types/soc';
import { MonitorView } from './components/MonitorView';
import { ClarificationInboxView } from './components/ClarificationInboxView';
import { FlowSenderView } from './components/FlowSenderView';
import { ForensicsLedgerView } from './components/ForensicsLedgerView';
import { AiCopilotView } from './components/AiCopilotView';
import { AiAssistantView } from './components/AiAssistantView';
import { ReportStudioView } from './components/ReportStudioView';
import { GovernanceView } from './components/GovernanceView';
import { SettingsView } from './components/SettingsView';

type ModuleId =
  | 'monitor'
  | 'clarify'
  | 'sender'
  | 'forensics'
  | 'chat'
  | 'assistant'
  | 'reports'
  | 'governance'
  | 'settings';

const NAV_ITEMS: Array<{ id: ModuleId; label: string; icon: typeof Activity }> = [
  { id: 'monitor', label: '24/7 Live Monitor', icon: Activity },
  { id: 'clarify', label: 'Clarification Inbox', icon: HelpCircle },
  { id: 'sender', label: 'Flow Sender Lab', icon: FlaskConical },
  { id: 'forensics', label: 'Forensics & ChronoGraph', icon: Search },
  { id: 'chat', label: 'Cloud AI Co-Pilot', icon: MessageSquare },
  { id: 'assistant', label: 'AI Assistant', icon: Sparkles },
  { id: 'reports', label: 'Period Report Studio', icon: FileBarChart2 },
  { id: 'governance', label: 'API & Cache Governance', icon: SlidersHorizontal },
];

export default function App() {
  const [activeModule, setActiveModule] = useState<ModuleId>('monitor');
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [incidents, setIncidents] = useState<IncidentRecord[]>([]);
  const [recentFlows, setRecentFlows] = useState<FlowRecord[]>([]);
  const [profiles, setProfiles] = useState<DatasetProfile[]>([]);
  const [autoSchedule, setAutoSchedule] = useState<GatewaySettings['report_auto_schedule']>('SHIFT_8H');
  const [wsConnected, setWsConnected] = useState(false);

  const [focusIncidentId, setFocusIncidentId] = useState<string | null>(null);
  const [focusIp, setFocusIp] = useState<string | null>(null);

  const fetchDashboard = useCallback(async () => {
    const res = await fetch('/api/dashboard');
    if (!res.ok) return;
    const data = await res.json();
    setMetrics(data.metrics);
    setIncidents(data.incidents ?? []);
    setRecentFlows(data.recent_flows ?? []);
  }, []);

  const fetchProfilesAndSchedule = useCallback(async () => {
    const [pRes, gRes] = await Promise.all([fetch('/api/profiles'), fetch('/api/governance')]);
    if (pRes.ok) {
      const pData = await pRes.json();
      setProfiles(pData.profiles ?? []);
    }
    if (gRes.ok) {
      const gData = await gRes.json();
      if (gData.settings?.report_auto_schedule) {
        setAutoSchedule(gData.settings.report_auto_schedule);
      }
    }
  }, []);

  useEffect(() => {
    void fetchDashboard();
    void fetchProfilesAndSchedule();
  }, [fetchDashboard, fetchProfilesAndSchedule]);

  // Real-time WebSocket stream from Express server
  useEffect(() => {
    let ws: WebSocket | null = null;
    let reconnectTimer: number | null = null;
    let disposed = false;

    const connect = () => {
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      ws = new WebSocket(`${proto}//${window.location.host}/ws`);
      ws.onopen = () => setWsConnected(true);
      ws.onclose = () => {
        setWsConnected(false);
        if (!disposed) {
          reconnectTimer = window.setTimeout(connect, 2500);
        }
      };
      ws.onmessage = (evt) => {
        try {
          const msg = JSON.parse(evt.data);
          if (msg.type === 'metrics:tick' && msg.payload) {
            setMetrics(msg.payload);
          } else if (msg.type === 'flow:ingested' && msg.payload) {
            const { flow, incident } = msg.payload as {
              flow: FlowRecord;
              incident: IncidentRecord | null;
            };
            setRecentFlows((prev) => [flow, ...prev.filter((f) => f.id !== flow.id)].slice(0, 25));
            if (incident) {
              setIncidents((prev) => [incident, ...prev.filter((i) => i.id !== incident.id)].slice(0, 30));
            }
          } else if (msg.type === 'incident:updated') {
            void fetchDashboard();
          }
        } catch {
          // Ignore malformed frame
        }
      };
    };

    connect();
    return () => {
      disposed = true;
      if (reconnectTimer) window.clearTimeout(reconnectTimer);
      ws?.close();
    };
  }, [fetchDashboard]);

  const handleToggleSensor = async (running: boolean, rate?: number) => {
    const res = await fetch('/api/sensor/toggle', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ running, rate_fps: rate }),
    });
    if (res.ok) setMetrics(await res.json());
  };

  const handleApproveRule = async (incidentId: string) => {
    const res = await fetch(`/api/incidents/${encodeURIComponent(incidentId)}/approve-rule`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ actor: 'Tier-3 SOC Supervisor' }),
    });
    if (res.ok) {
      await fetchDashboard();
    }
  };

  const handleUpdateAutoSchedule = async (schedule: GatewaySettings['report_auto_schedule']) => {
    setAutoSchedule(schedule);
    await fetch('/api/governance/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ report_auto_schedule: schedule }),
    });
  };

  const handleNavigate = (mod: string, opts?: { incidentId?: string; ip?: string }) => {
    if (opts?.incidentId) setFocusIncidentId(opts.incidentId);
    if (opts?.ip) setFocusIp(opts.ip);
    setActiveModule(mod as ModuleId);
  };

  const currentNav =
    activeModule === 'settings'
      ? { id: 'settings' as ModuleId, label: 'Settings & API Keys', icon: Settings }
      : NAV_ITEMS.find((n) => n.id === activeModule) ?? NAV_ITEMS[0];

  return (
    <div className="min-h-screen bg-[#090D16] text-slate-100 flex">
      {/* Left Navigation Rail (256px) */}
      <aside className="w-64 shrink-0 bg-[#0B111E] border-r border-slate-800/90 flex flex-col">
        <div className="h-14 px-5 flex items-center gap-2.5 border-b border-slate-800/90">
          <Shield className="w-5 h-5 text-sky-400 shrink-0" />
          <span className="font-semibold tracking-tight text-slate-100 whitespace-nowrap">
            AegisFlow-OmniSOC
          </span>
        </div>

        <nav className="flex-1 p-3 space-y-1">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const active = activeModule === item.id;
            const count =
              item.id === 'clarify' ? metrics?.pending_clarifications ?? 0 : 0;

            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setActiveModule(item.id)}
                className={`w-full flex items-center justify-between gap-2 px-3 py-2.5 rounded-md text-xs font-medium transition-colors whitespace-nowrap ${
                  active
                    ? 'bg-slate-800/90 text-slate-50'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-slate-900/70'
                }`}
              >
                <span className="flex items-center gap-2.5 min-w-0 truncate">
                  <Icon className={`w-4 h-4 shrink-0 ${active ? 'text-sky-400' : 'text-slate-500'}`} />
                  <span className="truncate">{item.label}</span>
                </span>
                {count > 0 && (
                  <span className="font-mono tabular-nums text-[11px] font-semibold text-amber-400 shrink-0">
                    {count}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        <div className="p-4 border-t border-slate-800/90 text-[11px] text-slate-400 space-y-1.5">
          <div className="flex items-center justify-between">
            <span>Telemetry Stream</span>
            <span className={`font-mono ${wsConnected && metrics?.sensor_running ? 'text-emerald-400' : 'text-slate-500'}`}>
              {wsConnected ? (metrics?.sensor_running ? 'Live' : 'Paused') : 'Connecting'}
            </span>
          </div>
          <div className="flex items-center justify-between">
            <span>Engine</span>
            <span className="font-mono text-slate-300">
              {metrics?.inference_mode === 'LIVE_PYTORCH_BRIDGE' ? 'PyTorch Bridge' : 'v8.1 Sandbox'}
            </span>
          </div>
          <div className="flex items-center justify-between">
            <span>RAG Corpus</span>
            <span className="font-mono text-slate-300">ATT&amp;CK v20.1 · KEV</span>
          </div>
          <div className="pt-2.5 mt-2 border-t border-slate-800/80">
            <button
              type="button"
              onClick={() => setActiveModule('settings')}
              className={`w-full flex items-center justify-between gap-2 px-3 py-2 rounded-md text-xs font-medium transition-colors ${
                activeModule === 'settings'
                  ? 'bg-slate-800 text-sky-300 border border-slate-700'
                  : 'bg-[#090D16] text-slate-300 hover:text-white hover:bg-slate-800/70 border border-slate-800'
              }`}
            >
              <span className="flex items-center gap-2">
                <Settings className={`w-4 h-4 ${activeModule === 'settings' ? 'text-sky-400' : 'text-slate-400'}`} />
                <span>Settings · API Keys</span>
              </span>
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 min-w-0 flex flex-col">
        {/* Clean Contextual Top Bar */}
        <header className="h-14 px-6 bg-[#0B111E] border-b border-slate-800/90 flex items-center justify-between gap-8 shrink-0">
          <div className="flex items-center gap-2 text-sm min-w-0">
            <span className="text-slate-500 whitespace-nowrap">SOC Command</span>
            <span className="text-slate-700">/</span>
            <h1 className="font-semibold text-slate-100 truncate">{currentNav.label}</h1>
          </div>

          <div className="flex items-center gap-5 text-xs shrink-0">
            {metrics && (
              <div className="hidden lg:flex items-center gap-3 text-slate-400 font-mono tabular-nums whitespace-nowrap">
                <span>Profile: <span className="text-slate-200">{metrics.active_profile}</span></span>
                <span className="text-slate-700">·</span>
                <span>Tier-0 Saved: <span className="text-sky-400">{metrics.tier0_savings_pct.toFixed(1)}%</span></span>
              </div>
            )}
            <button
              type="button"
              onClick={() => handleToggleSensor(!(metrics?.sensor_running ?? true))}
              className={`px-3.5 py-1.5 rounded-md text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                metrics?.sensor_running
                  ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/35 hover:bg-emerald-500/20'
                  : 'bg-sky-400 text-slate-950 hover:bg-sky-300'
              }`}
            >
              {metrics?.sensor_running ? '24/7 Sensor: Active' : 'Start 24/7 Sensor'}
            </button>
          </div>
        </header>

        {/* Active Module Viewport */}
        <main className="flex-1 p-6 max-w-[1600px] w-full mx-auto">
          {!metrics ? (
            <div className="py-20 text-center text-sm text-slate-400">
              Initializing AegisFlow-OmniSOC v8.1 stateful engine...
            </div>
          ) : (
            <>
              {activeModule === 'monitor' && (
                <MonitorView
                  metrics={metrics}
                  incidents={incidents}
                  recentFlows={recentFlows}
                  onToggleSensor={handleToggleSensor}
                  onApproveRule={handleApproveRule}
                  onNavigateModule={handleNavigate}
                />
              )}
              {activeModule === 'clarify' && (
                <ClarificationInboxView
                  focusIncidentId={focusIncidentId}
                  onRefreshDashboard={fetchDashboard}
                  onApproveRule={handleApproveRule}
                  onOpenChat={(id, ip) => handleNavigate('chat', { incidentId: id, ip })}
                />
              )}
              {activeModule === 'sender' && (
                <FlowSenderView
                  profiles={profiles}
                  activeProfileId={metrics.active_profile}
                  onRefreshDashboard={fetchDashboard}
                  onApproveRule={handleApproveRule}
                  onOpenChat={(id, ip) => handleNavigate('chat', { incidentId: id, ip })}
                />
              )}
              {activeModule === 'forensics' && <ForensicsLedgerView focusIp={focusIp} />}
              {activeModule === 'chat' && (
                <AiCopilotView
                  incidents={incidents}
                  initialIncidentId={focusIncidentId}
                  initialIp={focusIp}
                />
              )}
              {activeModule === 'assistant' && <AiAssistantView />}
              {activeModule === 'reports' && (
                <ReportStudioView
                  autoSchedule={autoSchedule}
                  onUpdateAutoSchedule={handleUpdateAutoSchedule}
                />
              )}
              {activeModule === 'governance' && (
                <GovernanceView profiles={profiles} onSettingsUpdated={fetchDashboard} />
              )}
              {activeModule === 'settings' && (
                <SettingsView onRefreshDashboard={fetchDashboard} />
              )}
            </>
          )}
        </main>
      </div>
    </div>
  );
}
