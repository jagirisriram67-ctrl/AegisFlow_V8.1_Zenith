import { useEffect, useState } from 'react';
import {
  CheckCircle2,
  Database,
  Globe,
  KeyRound,
  Play,
  Plus,
  RefreshCw,
  ShieldCheck,
  Star,
  Trash2,
  XCircle,
} from 'lucide-react';

interface ProviderEndpoint {
  id: string;
  name: string;
  provider_type: 'GEMINI' | 'OPENROUTER' | 'OPENAI_COMPATIBLE' | 'PYTORCH_ENGINE';
  base_url: string;
  model_id: string;
  env_var_name: string;
  priority: number;
  enabled: boolean;
  is_primary: boolean;
  last_test_status: string | null;
  last_test_latency_ms: number | null;
  last_test_utc: string | null;
  env_configured: boolean;
  masked_key_label: string;
}

interface EnvVarInfo {
  name: string;
  configured: boolean;
  provider: string;
}

interface DatabaseDiag {
  engine: string;
  file_name: string;
  size_kb: number;
  journal_mode: string;
  integrity_check: string;
  audit_chain: { valid: boolean; total_entries: number; broken_at_id: number | null };
  tables: Array<{ name: string; rows: number }>;
}

interface E2ECheck {
  id: string;
  name: string;
  passed: boolean;
  latency_ms: number;
  detail: string;
}

type SettingsTab = 'api-keys' | 'verification' | 'database';

export function SettingsView({ onRefreshDashboard }: { onRefreshDashboard: () => Promise<void> }) {
  const [activeTab, setActiveTab] = useState<SettingsTab>('api-keys');
  const [endpoints, setEndpoints] = useState<ProviderEndpoint[]>([]);
  const [envVars, setEnvVars] = useState<EnvVarInfo[]>([]);
  const [dbDiag, setDbDiag] = useState<DatabaseDiag | null>(null);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [banner, setBanner] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  // Add Provider Endpoint form state (strictly server-side env var reference — zero raw secrets in UI)
  const [name, setName] = useState('');
  const [providerType, setProviderType] = useState<ProviderEndpoint['provider_type']>('OPENAI_COMPATIBLE');
  const [baseUrl, setBaseUrl] = useState('https://openrouter.ai/api/v1');
  const [modelId, setModelId] = useState('anthropic/claude-3.7-sonnet');
  const [envVarName, setEnvVarName] = useState('OPENROUTER_API_KEY');
  const [priority, setPriority] = useState(5);
  const [makePrimary, setMakePrimary] = useState(false);

  // E2E Production Verification state
  const [runningE2E, setRunningE2E] = useState(false);
  const [e2eResult, setE2eResult] = useState<{
    all_passed: boolean;
    verified_utc: string;
    checks: E2ECheck[];
  } | null>(null);

  const loadAll = async () => {
    const [epRes, dbRes] = await Promise.all([
      fetch('/api/settings/endpoints'),
      fetch('/api/settings/database'),
    ]);
    if (epRes.ok) {
      const d = await epRes.json();
      setEndpoints(d.endpoints ?? []);
      setEnvVars(d.available_env_vars ?? []);
    }
    if (dbRes.ok) {
      setDbDiag(await dbRes.json());
    }
  };

  useEffect(() => {
    void loadAll();
  }, []);

  const handleProviderPreset = (type: ProviderEndpoint['provider_type']) => {
    setProviderType(type);
    if (type === 'GEMINI') {
      setBaseUrl('https://generativelanguage.googleapis.com');
      setModelId('gemini-4-hydrogen');
      setEnvVarName('GEMINI_API_KEY');
    } else if (type === 'OPENROUTER') {
      setBaseUrl('https://openrouter.ai/api/v1');
      setModelId('anthropic/claude-3.7-sonnet');
      setEnvVarName('OPENROUTER_API_KEY');
    } else if (type === 'OPENAI_COMPATIBLE') {
      setBaseUrl('https://api.openai.com/v1');
      setModelId('gpt-4o-mini');
      setEnvVarName('CUSTOM_LLM_API_KEY');
    } else {
      setBaseUrl('http://127.0.0.1:8001');
      setModelId('aegisflow-zenith-v8.1');
      setEnvVarName('PYTORCH_ENGINE_URL');
    }
  };

  const handleAddEndpoint = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !baseUrl.trim() || !modelId.trim() || !envVarName.trim()) return;
    setSaving(true);
    setBanner(null);
    try {
      const res = await fetch('/api/settings/endpoints', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: name.trim(),
          provider_type: providerType,
          base_url: baseUrl.trim(),
          model_id: modelId.trim(),
          env_var_name: envVarName.trim().toUpperCase(),
          priority: Number(priority),
          enabled: true,
          is_primary: makePrimary,
        }),
      });
      const data = await res.json();
      if (res.ok) {
        setEndpoints(data.endpoints ?? []);
        setName('');
        setMakePrimary(false);
        setBanner({ kind: 'ok', text: `Saved endpoint "${data.endpoint?.name}" to SQLite and SHA-256 audit log.` });
        await loadAll();
      } else {
        setBanner({ kind: 'err', text: data.error || 'Failed to save endpoint.' });
      }
    } finally {
      setSaving(false);
    }
  };

  const handleTest = async (id: string) => {
    setTestingId(id);
    setBanner(null);
    try {
      const res = await fetch(`/api/settings/endpoints/${encodeURIComponent(id)}/test`, { method: 'POST' });
      const data = await res.json();
      if (data.endpoints) setEndpoints(data.endpoints);
      if (data.result) {
        setBanner({
          kind: data.result.ok ? 'ok' : 'err',
          text: `Endpoint Probe: ${data.result.status_text} (${data.result.latency_ms} ms)`,
        });
      }
    } finally {
      setTestingId(null);
    }
  };

  const handleSetPrimary = async (id: string) => {
    const res = await fetch(`/api/settings/endpoints/${encodeURIComponent(id)}/primary`, { method: 'POST' });
    if (res.ok) {
      const data = await res.json();
      setEndpoints(data.endpoints ?? []);
      setBanner({ kind: 'ok', text: 'Updated primary LLM provider route in SQLite.' });
    }
  };

  const handleToggle = async (id: string, enabled: boolean) => {
    const res = await fetch(`/api/settings/endpoints/${encodeURIComponent(id)}/toggle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled }),
    });
    if (res.ok) {
      const data = await res.json();
      setEndpoints(data.endpoints ?? []);
    }
  };

  const handleDelete = async (id: string) => {
    const res = await fetch(`/api/settings/endpoints/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (res.ok) {
      const data = await res.json();
      setEndpoints(data.endpoints ?? []);
      setBanner({ kind: 'ok', text: 'Endpoint removed from provider registry.' });
      await loadAll();
    }
  };

  const runProductionVerification = async () => {
    setRunningE2E(true);
    setBanner(null);
    try {
      const res = await fetch('/api/diagnostics/run-e2e', { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        setE2eResult(data);
        await loadAll();
        await onRefreshDashboard();
      } else {
        setBanner({ kind: 'err', text: data.error || 'Production verification failed.' });
      }
    } finally {
      setRunningE2E(false);
    }
  };

  const connectedCount = endpoints.filter((e) => e.env_configured && e.enabled).length;
  const primaryEp = endpoints.find((e) => e.is_primary) ?? endpoints[0];

  return (
    <div className="space-y-6">
      {/* Settings Header & Sub-Navigation */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-base font-semibold text-slate-100">
            Settings · API Keys, Endpoints &amp; Production Diagnostics
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Manage Base URLs, model routes, server-side secret bindings, SQLite WAL persistence, and live end-to-end model verification
          </p>
        </div>

        <div className="inline-flex items-center rounded-lg bg-[#0B111E] border border-slate-800 p-1 text-xs">
          <button
            type="button"
            onClick={() => setActiveTab('api-keys')}
            className={`px-3 py-1.5 rounded-md font-medium transition-colors inline-flex items-center gap-1.5 ${
              activeTab === 'api-keys' ? 'bg-slate-800 text-sky-300' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <KeyRound className="w-3.5 h-3.5" />
            API Keys &amp; Endpoints
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('verification')}
            className={`px-3 py-1.5 rounded-md font-medium transition-colors inline-flex items-center gap-1.5 ${
              activeTab === 'verification' ? 'bg-slate-800 text-sky-300' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            Model &amp; Bypass Verification
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('database')}
            className={`px-3 py-1.5 rounded-md font-medium transition-colors inline-flex items-center gap-1.5 ${
              activeTab === 'database' ? 'bg-slate-800 text-sky-300' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Database className="w-3.5 h-3.5" />
            Database &amp; Storage
          </button>
        </div>
      </div>

      {banner && (
        <div
          className={`px-4 py-3 rounded-lg border text-xs flex items-center justify-between gap-3 ${
            banner.kind === 'ok'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-200'
              : 'bg-rose-500/10 border-rose-500/30 text-rose-200'
          }`}
        >
          <span>{banner.text}</span>
          <button type="button" onClick={() => setBanner(null)} className="text-slate-400 hover:text-white">
            Dismiss
          </button>
        </div>
      )}

      {/* TAB 1: API KEYS & PROVIDER ENDPOINTS */}
      {activeTab === 'api-keys' && (
        <div className="space-y-6">
          {/* Top KPI Strip */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-[#0F1623] border border-slate-800 rounded-lg p-4">
              <div className="text-[11px] uppercase tracking-wider text-slate-500">Registered Endpoints</div>
              <div className="text-xl font-semibold font-mono tabular-nums text-slate-100 mt-1">
                {endpoints.length}
              </div>
              <div className="text-[11px] text-slate-400 mt-0.5">Persisted in SQLite WAL</div>
            </div>
            <div className="bg-[#0F1623] border border-slate-800 rounded-lg p-4">
              <div className="text-[11px] uppercase tracking-wider text-slate-500">Active Server Secrets</div>
              <div className="text-xl font-semibold font-mono tabular-nums text-emerald-400 mt-1">
                {connectedCount} / {endpoints.length}
              </div>
              <div className="text-[11px] text-slate-400 mt-0.5">Resolved strictly in server process.env</div>
            </div>
            <div className="bg-[#0F1623] border border-slate-800 rounded-lg p-4">
              <div className="text-[11px] uppercase tracking-wider text-slate-500">Primary Route</div>
              <div className="text-sm font-semibold text-sky-300 mt-1.5 truncate">
                {primaryEp?.name ?? 'Google Gemini'}
              </div>
              <div className="text-[11px] font-mono text-slate-400 mt-0.5 truncate">
                {primaryEp?.model_id ?? 'gemini-4-hydrogen'}
              </div>
            </div>
            <div className="bg-[#0F1623] border border-slate-800 rounded-lg p-4">
              <div className="text-[11px] uppercase tracking-wider text-slate-500">Secret Boundary</div>
              <div className="text-sm font-semibold text-emerald-300 mt-1.5">Zero-Browser Exposure</div>
              <div className="text-[11px] text-slate-400 mt-0.5">Keys stay server-side + Privacy Proxy active</div>
            </div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
            {/* Added API Keys & Provider Endpoints Table */}
            <div className="xl:col-span-8 bg-[#0F1623] border border-slate-800 rounded-lg overflow-hidden">
              <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-slate-100">Added API Keys &amp; Base URLs</h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Used in priority order by Cloud AI Co-Pilot, AI Assistant, and Incident Briefs
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => void loadAll()}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs text-slate-300 hover:text-white bg-[#0B111E] border border-slate-800 rounded-md"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  Refresh
                </button>
              </div>

              <div className="divide-y divide-slate-800/80">
                {endpoints.map((ep) => (
                  <div key={ep.id} className="p-4 hover:bg-slate-900/40 transition-colors space-y-2.5">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div className="space-y-1 min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-sm font-semibold text-slate-100">{ep.name}</span>
                          {ep.is_primary && (
                            <span className="inline-flex items-center gap-1 text-[10px] font-mono uppercase tracking-wider text-sky-300 border border-sky-500/35 bg-sky-500/10 px-1.5 py-0.5 rounded">
                              <Star className="w-2.5 h-2.5" />
                              Primary
                            </span>
                          )}
                          <span className="text-[10px] font-mono text-slate-400 border border-slate-800 bg-[#090D16] px-1.5 py-0.5 rounded">
                            {ep.provider_type} · P{ep.priority}
                          </span>
                          {!ep.enabled && (
                            <span className="text-[10px] font-mono text-slate-500 uppercase">Disabled</span>
                          )}
                        </div>

                        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs font-mono text-slate-400">
                          <span className="inline-flex items-center gap-1.5 text-slate-300">
                            <Globe className="w-3.5 h-3.5 text-slate-500" />
                            {ep.base_url}
                          </span>
                          <span>Model: <span className="text-sky-300">{ep.model_id}</span></span>
                        </div>

                        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] font-mono">
                          <span className={ep.env_configured ? 'text-emerald-400' : 'text-amber-400'}>
                            <KeyRound className="w-3 h-3 inline mr-1" />
                            {ep.masked_key_label}
                          </span>
                          {ep.last_test_status && (
                            <span className="text-slate-400">
                              Last probe: <span className="text-slate-200">{ep.last_test_status}</span>
                              {ep.last_test_latency_ms ? ` (${ep.last_test_latency_ms} ms)` : ''}
                            </span>
                          )}
                        </div>
                      </div>

                      <div className="flex flex-wrap items-center gap-1.5 shrink-0">
                        <button
                          type="button"
                          disabled={testingId === ep.id}
                          onClick={() => void handleTest(ep.id)}
                          className="px-2.5 py-1.5 rounded-md text-[11px] font-medium bg-[#0B111E] hover:bg-slate-800 border border-slate-700 text-slate-200 disabled:opacity-50"
                        >
                          {testingId === ep.id ? 'Testing...' : 'Test'}
                        </button>
                        {!ep.is_primary && (
                          <button
                            type="button"
                            onClick={() => void handleSetPrimary(ep.id)}
                            className="px-2.5 py-1.5 rounded-md text-[11px] font-medium bg-[#0B111E] hover:bg-slate-800 border border-slate-700 text-sky-300"
                          >
                            Set Primary
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => void handleToggle(ep.id, !ep.enabled)}
                          className="px-2.5 py-1.5 rounded-md text-[11px] font-medium bg-[#0B111E] hover:bg-slate-800 border border-slate-700 text-slate-300"
                        >
                          {ep.enabled ? 'Disable' : 'Enable'}
                        </button>
                        <button
                          type="button"
                          onClick={() => void handleDelete(ep.id)}
                          title="Delete endpoint"
                          className="p-1.5 rounded-md bg-[#0B111E] hover:bg-rose-500/15 border border-slate-800 hover:border-rose-500/35 text-slate-400 hover:text-rose-400"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Right: Add Provider Endpoint Form + Server Secrets Status */}
            <div className="xl:col-span-4 space-y-5">
              <form
                onSubmit={handleAddEndpoint}
                className="bg-[#0F1623] border border-slate-800 rounded-lg p-5 space-y-3.5"
              >
                <div className="flex items-center gap-2">
                  <Plus className="w-4 h-4 text-sky-400" />
                  <h3 className="text-sm font-semibold text-slate-100">Add Provider Endpoint</h3>
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  Register a Base URL, model, and server-side secret variable name. Store the actual key value safely in{' '}
                  <span className="text-slate-200 font-medium">AI Studio Secrets</span> or{' '}
                  <code className="font-mono text-sky-300">.env</code> — raw secrets never enter the browser.
                </p>

                <div className="space-y-1">
                  <label className="block text-[11px] text-slate-400">Provider Type</label>
                  <select
                    value={providerType}
                    onChange={(e) => handleProviderPreset(e.target.value as ProviderEndpoint['provider_type'])}
                    className="w-full bg-[#090D16] border border-slate-700 rounded-md px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-sky-500"
                  >
                    <option value="OPENAI_COMPATIBLE">Custom OpenAI-Compatible (Harbor / vLLM / OpenAI)</option>
                    <option value="OPENROUTER">OpenRouter Gateway</option>
                    <option value="GEMINI">Google Gemini API</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="block text-[11px] text-slate-400">Display Name</label>
                  <input
                    type="text"
                    required
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="e.g. Enterprise OpenRouter Claude"
                    className="w-full bg-[#090D16] border border-slate-700 rounded-md px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
                  />
                </div>

                <div className="space-y-1">
                  <label className="block text-[11px] text-slate-400">Base URL (HTTPS)</label>
                  <input
                    type="url"
                    required
                    value={baseUrl}
                    onChange={(e) => setBaseUrl(e.target.value)}
                    placeholder="https://openrouter.ai/api/v1"
                    className="w-full bg-[#090D16] border border-slate-700 rounded-md px-3 py-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-sky-500"
                  />
                </div>

                <div className="space-y-1">
                  <label className="block text-[11px] text-slate-400">Model ID</label>
                  <input
                    type="text"
                    required
                    value={modelId}
                    onChange={(e) => setModelId(e.target.value)}
                    placeholder="anthropic/claude-3.7-sonnet"
                    className="w-full bg-[#090D16] border border-slate-700 rounded-md px-3 py-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-sky-500"
                  />
                </div>

                <div className="grid grid-cols-3 gap-2.5">
                  <div className="col-span-2 space-y-1">
                    <label className="block text-[11px] text-slate-400">Server Secret Env Var</label>
                    <input
                      type="text"
                      required
                      value={envVarName}
                      onChange={(e) => setEnvVarName(e.target.value.toUpperCase().replace(/[^A-Z0-9_]/g, ''))}
                      placeholder="CUSTOM_LLM_API_KEY"
                      className="w-full bg-[#090D16] border border-slate-700 rounded-md px-3 py-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-sky-500"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="block text-[11px] text-slate-400">Priority</label>
                    <input
                      type="number"
                      min={1}
                      max={99}
                      value={priority}
                      onChange={(e) => setPriority(Number(e.target.value))}
                      className="w-full bg-[#090D16] border border-slate-700 rounded-md px-2.5 py-2 text-xs font-mono text-slate-100"
                    />
                  </div>
                </div>

                <label className="flex items-center gap-2 text-xs text-slate-300 pt-1">
                  <input
                    type="checkbox"
                    checked={makePrimary}
                    onChange={(e) => setMakePrimary(e.target.checked)}
                    className="rounded border-slate-700 bg-[#090D16]"
                  />
                  Set as primary default route
                </label>

                <button
                  type="submit"
                  disabled={saving}
                  className="w-full py-2.5 rounded-lg bg-sky-400 hover:bg-sky-300 text-slate-950 font-semibold text-xs transition-colors disabled:opacity-50"
                >
                  {saving ? 'Saving to SQLite...' : 'Save Endpoint Configuration'}
                </button>
              </form>

              {/* Detected Server Environment Secrets */}
              <div className="bg-[#0F1623] border border-slate-800 rounded-lg p-4 space-y-2.5">
                <div className="text-xs font-semibold text-slate-200">Server Environment Secret Bindings</div>
                <div className="space-y-1.5">
                  {envVars.map((ev) => (
                    <div
                      key={ev.name}
                      className="flex items-center justify-between text-[11px] font-mono bg-[#0B111E] border border-slate-800/80 rounded px-2.5 py-1.5"
                    >
                      <span className="text-slate-300">{ev.name}</span>
                      <span className={ev.configured ? 'text-emerald-400' : 'text-slate-500'}>
                        {ev.configured ? 'Connected' : 'Unset'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: END-TO-END MODEL & REPEAT-FLOW BYPASS VERIFICATION */}
      {activeTab === 'verification' && (
        <div className="bg-[#0F1623] border border-slate-800 rounded-lg p-5 space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-100">
                Live Production Self-Test · AegisFlow-Zenith v8.1 &amp; Tier-0 Repeat Bypass
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Runs live ingestion tests across all 6 dataset schemas, verifies exact repeat attacks &amp; benign flows bypass the neural model in &lt;0.05 ms, tests Tier-1 polymorphic promotion, Gate E9 safety, and SQLite WAL integrity
              </p>
            </div>
            <button
              type="button"
              disabled={runningE2E}
              onClick={() => void runProductionVerification()}
              className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-sky-400 hover:bg-sky-300 text-slate-950 font-semibold text-xs transition-colors disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5" />
              {runningE2E ? 'Running Live Checks...' : 'Run Full Production Self-Test'}
            </button>
          </div>

          {!e2eResult ? (
            <div className="rounded-lg border border-slate-800 bg-[#0B111E] p-8 text-center text-xs text-slate-400">
              Click <span className="text-slate-200 font-medium">Run Full Production Self-Test</span> to execute live verification against the running SQLite database and AegisFlow-Zenith v8.1 engine.
            </div>
          ) : (
            <div className="space-y-3">
              <div
                className={`px-4 py-3 rounded-lg border flex items-center justify-between text-xs ${
                  e2eResult.all_passed
                    ? 'bg-emerald-500/10 border-emerald-500/35 text-emerald-300'
                    : 'bg-rose-500/10 border-rose-500/35 text-rose-300'
                }`}
              >
                <span className="font-semibold inline-flex items-center gap-2">
                  {e2eResult.all_passed ? (
                    <CheckCircle2 className="w-4 h-4" />
                  ) : (
                    <XCircle className="w-4 h-4" />
                  )}
                  {e2eResult.all_passed
                    ? `All ${e2eResult.checks.length}/${e2eResult.checks.length} Production Systems Verified`
                    : 'One or more checks need attention'}
                </span>
                <span className="font-mono text-[11px] opacity-80">
                  {new Date(e2eResult.verified_utc).toLocaleTimeString()}
                </span>
              </div>

              <div className="divide-y divide-slate-800/80 border border-slate-800 rounded-lg overflow-hidden bg-[#0B111E]">
                {e2eResult.checks.map((c) => (
                  <div key={c.id} className="p-4 flex items-start justify-between gap-4">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 text-xs font-semibold text-slate-100">
                        {c.passed ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                        ) : (
                          <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
                        )}
                        <span>{c.name}</span>
                      </div>
                      <div className="text-[11.5px] font-mono text-slate-400 pl-6">{c.detail}</div>
                    </div>
                    <span className="text-[11px] font-mono tabular-nums text-slate-500 shrink-0">
                      {c.latency_ms} ms
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: DATABASE & STORAGE HEALTH */}
      {activeTab === 'database' && dbDiag && (
        <div className="space-y-5">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-[#0F1623] border border-slate-800 rounded-lg p-4">
              <div className="text-[11px] uppercase tracking-wider text-slate-500">Database File</div>
              <div className="text-sm font-mono font-semibold text-slate-100 mt-1">{dbDiag.file_name}</div>
              <div className="text-[11px] text-slate-400 mt-0.5">{dbDiag.engine}</div>
            </div>
            <div className="bg-[#0F1623] border border-slate-800 rounded-lg p-4">
              <div className="text-[11px] uppercase tracking-wider text-slate-500">Storage Size &amp; Mode</div>
              <div className="text-lg font-mono font-semibold tabular-nums text-sky-300 mt-1">
                {dbDiag.size_kb} KB
              </div>
              <div className="text-[11px] text-slate-400 mt-0.5">Journal: {dbDiag.journal_mode} · Self-Healing</div>
            </div>
            <div className="bg-[#0F1623] border border-slate-800 rounded-lg p-4">
              <div className="text-[11px] uppercase tracking-wider text-slate-500">PRAGMA quick_check</div>
              <div className="text-lg font-mono font-semibold text-emerald-400 mt-1 uppercase">
                {dbDiag.integrity_check}
              </div>
              <div className="text-[11px] text-slate-400 mt-0.5">Zero corrupt pages</div>
            </div>
            <div className="bg-[#0F1623] border border-slate-800 rounded-lg p-4">
              <div className="text-[11px] uppercase tracking-wider text-slate-500">SHA-256 Audit Chain</div>
              <div className="text-lg font-mono font-semibold text-emerald-400 mt-1">
                {dbDiag.audit_chain.valid ? 'VERIFIED' : 'ALERT'}
              </div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                {dbDiag.audit_chain.total_entries} immutable ledger rows
              </div>
            </div>
          </div>

          <div className="bg-[#0F1623] border border-slate-800 rounded-lg p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-slate-100">Persistent SQLite Tables</h3>
              <button
                type="button"
                onClick={() => void loadAll()}
                className="inline-flex items-center gap-1.5 text-xs text-sky-400 hover:text-sky-300"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                Refresh Counts
              </button>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
              {dbDiag.tables.map((t) => (
                <div key={t.name} className="rounded-lg bg-[#0B111E] border border-slate-800 p-3.5">
                  <div className="text-[11px] font-mono text-slate-400 truncate">{t.name}</div>
                  <div className="text-lg font-mono font-semibold tabular-nums text-slate-100 mt-1">
                    {t.rows.toLocaleString()}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
