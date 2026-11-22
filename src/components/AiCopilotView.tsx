import { useEffect, useState } from 'react';
import { BookOpen, RefreshCw, Search, Send, ShieldCheck, Wrench } from 'lucide-react';
import type { GateE9Audit, IncidentRecord, RagDocument } from '../types/soc';

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  meta?: {
    provider: string;
    model: string;
    privacy_tokens_masked: number;
    tools_invoked: Array<{ tool: string; summary: string }>;
    suggested_rule?: string;
    gate_e9?: GateE9Audit;
  };
}

interface Props {
  incidents: IncidentRecord[];
  initialIncidentId?: string | null;
  initialIp?: string | null;
}

const QUICK_PROMPTS = [
  'Analyze host history and multi-stage kill-chain drift',
  'Compare this incident with past campaigns and MITRE v20.1 / CISA KEV',
  'Draft a Gate E9 verified nftables containment rule and confirm 0.00% blast radius',
  'Summarize why TabM-8 and MetaOOD flagged this flow and recommend next steps',
];

export function AiCopilotView({ incidents, initialIncidentId, initialIp }: Props) {
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>(
    initialIncidentId || incidents[0]?.id || ''
  );
  const [focusIp, setFocusIp] = useState<string>(initialIp || incidents[0]?.src_ip || '');
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [ragQuery, setRagQuery] = useState('');
  const [ragDocs, setRagDocs] = useState<RagDocument[]>([]);
  const [syncingRag, setSyncingRag] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: 'assistant',
      content:
        'AegisFlow Cloud AI Co-Pilot is grounded in your live SQLite flow ledger, selected incident XAI card, and Hybrid RAG Knowledge Base (MITRE ATT&CK v20.1, NIST SP 800-61r3, CISA KEV, and Closed-Loop SOC Memory). All internal RFC1918 IP addresses are pseudonymized through the Reversible Privacy Proxy before any external LLM API call.',
    },
  ]);

  useEffect(() => {
    if (initialIncidentId) setSelectedIncidentId(initialIncidentId);
    if (initialIp) setFocusIp(initialIp);
  }, [initialIncidentId, initialIp]);

  const loadRag = async (q = ragQuery) => {
    const qs = q.trim() ? `?q=${encodeURIComponent(q.trim())}` : '';
    const res = await fetch(`/api/rag${qs}`);
    if (res.ok) {
      const data = await res.json();
      setRagDocs(data.documents ?? []);
    }
  };

  useEffect(() => {
    void loadRag('');
  }, []);

  const syncRag = async () => {
    setSyncingRag(true);
    try {
      await fetch('/api/rag/sync', { method: 'POST' });
      await loadRag(ragQuery);
    } finally {
      setSyncingRag(false);
    }
  };

  const sendMessage = async (textOverride?: string) => {
    const prompt = (textOverride ?? input).trim();
    if (!prompt || sending) return;
    const nextHistory = [...messages, { role: 'user' as const, content: prompt }];
    setMessages(nextHistory);
    setInput('');
    setSending(true);

    try {
      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: prompt,
          history: nextHistory.slice(-8).map((m) => ({ role: m.role, content: m.content })),
          incident_id: selectedIncidentId || null,
          focus_ip: focusIp || null,
        }),
      });
      const data = await res.json();
      setMessages([
        ...nextHistory,
        {
          role: 'assistant',
          content: data.reply || data.error || 'No response received.',
          meta: data.provider
            ? {
                provider: data.provider,
                model: data.model,
                privacy_tokens_masked: data.privacy_tokens_masked ?? 0,
                tools_invoked: data.tools_invoked ?? [],
                suggested_rule: data.suggested_rule,
                gate_e9: data.gate_e9,
              }
            : undefined,
        },
      ]);
    } catch {
      setMessages([
        ...nextHistory,
        { role: 'assistant', content: 'Unable to reach SOC Co-Pilot backend route.' },
      ]);
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
      {/* Left: Grounding Scope Selector */}
      <div className="xl:col-span-4 bg-[#0F1623] border border-slate-800 rounded-lg p-4 space-y-4">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">Co-Pilot Grounding Context</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Read-only structured tools query SQLite ledger &amp; Hybrid RAG safely
          </p>
        </div>

        <div>
          <label htmlFor="chat-inc-select" className="block text-xs text-slate-400 mb-1">
            Focus Incident XAI Card
          </label>
          <select
            id="chat-inc-select"
            value={selectedIncidentId}
            onChange={(e) => {
              const id = e.target.value;
              setSelectedIncidentId(id);
              const found = incidents.find((i) => i.id === id);
              if (found) setFocusIp(found.src_ip);
            }}
            className="w-full bg-[#090D16] border border-slate-700 rounded-md px-2.5 py-2 text-xs text-slate-100 focus:outline-none focus:border-sky-500"
          >
            <option value="">Global Ledger Scope</option>
            {incidents.map((inc) => (
              <option key={inc.id} value={inc.id}>
                {inc.id} · {inc.label} ({inc.src_ip})
              </option>
            ))}
          </select>
        </div>

        <div>
          <label htmlFor="chat-ip-input" className="block text-xs text-slate-400 mb-1">
            Focus Source IP (for ChronoGraph History)
          </label>
          <input
            id="chat-ip-input"
            type="text"
            value={focusIp}
            onChange={(e) => setFocusIp(e.target.value)}
            placeholder="e.g. 10.20.30.99"
            className="w-full bg-[#090D16] border border-slate-700 rounded-md px-2.5 py-1.5 text-xs font-mono text-slate-100 focus:outline-none focus:border-sky-500"
          />
        </div>

        <div className="pt-3 border-t border-slate-800/80 space-y-2">
          <div className="text-xs font-medium text-slate-300">Quick-Action Prompts</div>
          {QUICK_PROMPTS.map((qp) => (
            <button
              key={qp}
              type="button"
              disabled={sending}
              onClick={() => sendMessage(qp)}
              className="w-full text-left px-3 py-2 text-xs text-slate-300 bg-[#0B111E] hover:bg-slate-800/70 border border-slate-800 rounded-md transition-colors"
            >
              {qp}
            </button>
          ))}
        </div>

        {/* Live Hybrid RAG Knowledge Base Explorer */}
        <div className="pt-3 border-t border-slate-800/80 space-y-2.5">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-1.5 text-xs font-medium text-slate-200">
              <BookOpen className="w-3.5 h-3.5 text-sky-400" />
              Hybrid RAG Knowledge ({ragDocs.length})
            </div>
            <button
              type="button"
              disabled={syncingRag}
              onClick={syncRag}
              className="inline-flex items-center gap-1 text-[11px] text-sky-400 hover:text-sky-300 disabled:opacity-50"
            >
              <RefreshCw className={`w-3 h-3 ${syncingRag ? 'animate-spin' : ''}`} />
              Sync KEV
            </button>
          </div>
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={ragQuery}
              onChange={(e) => {
                setRagQuery(e.target.value);
                void loadRag(e.target.value);
              }}
              placeholder="Search MITRE, NIST, CISA KEV, SOC Memory..."
              className="w-full bg-[#090D16] border border-slate-700 rounded-md pl-8 pr-2.5 py-1.5 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
            />
          </div>
          <div className="space-y-1.5 max-h-52 overflow-y-auto pr-0.5">
            {ragDocs.slice(0, 8).map((doc) => (
              <button
                key={doc.id}
                type="button"
                disabled={sending}
                onClick={() =>
                  sendMessage(`Correlate ${doc.ref_id} (${doc.title}) against the active incident and outline containment steps.`)
                }
                className="w-full text-left p-2.5 rounded-md bg-[#0B111E] hover:bg-slate-800/70 border border-slate-800/90 transition-colors"
              >
                <div className="flex items-center justify-between gap-2 text-[10px] font-mono">
                  <span className="text-sky-400">{doc.ref_id}</span>
                  <span className="text-slate-500">{doc.source_type.replace(/_/g, ' ')}</span>
                </div>
                <div className="text-xs font-medium text-slate-200 mt-0.5 line-clamp-1">{doc.title}</div>
                <div className="text-[11px] text-slate-400 mt-0.5 line-clamp-2">{doc.summary}</div>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Right: Conversation Thread */}
      <div className="xl:col-span-8 bg-[#0F1623] border border-slate-800 rounded-lg flex flex-col h-[680px]">
        <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-100">Cloud AI SOC Co-Pilot</h3>
            <div className="text-xs text-slate-400">
              Reversible Privacy Proxy active · 4-Step Failover (Gemini → OpenRouter → Harbor → Offline)
            </div>
          </div>
          {selectedIncidentId && (
            <span className="text-xs font-mono text-sky-400">{selectedIncidentId}</span>
          )}
        </div>

        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          {messages.map((m, idx) => (
            <div
              key={idx}
              className={`rounded-lg p-4 text-sm leading-relaxed ${
                m.role === 'user'
                  ? 'bg-sky-500/10 border border-sky-500/25 ml-10 text-slate-100'
                  : 'bg-[#0B111E] border border-slate-800 mr-4 text-slate-200'
              }`}
            >
              <div className="text-[11px] font-medium text-slate-400 mb-1.5 flex flex-wrap items-center justify-between gap-2">
                <span>{m.role === 'user' ? 'SOC Analyst' : 'AegisFlow Co-Pilot'}</span>
                {m.meta && (
                  <span className="font-mono text-slate-500">
                    {m.meta.provider} · {m.meta.model} · Masked {m.meta.privacy_tokens_masked} internal token(s)
                  </span>
                )}
              </div>

              <div className="whitespace-pre-wrap text-xs sm:text-sm">{m.content}</div>

              {m.meta && m.meta.tools_invoked.length > 0 && (
                <div className="mt-3 pt-2.5 border-t border-slate-800/80 space-y-1">
                  <div className="flex items-center gap-1.5 text-[11px] text-slate-400 font-medium">
                    <Wrench className="w-3 h-3" />
                    Read-Only Tools Executed
                  </div>
                  <div className="flex flex-wrap gap-x-3 gap-y-1 text-[11px] font-mono text-slate-400">
                    {m.meta.tools_invoked.map((t, i) => (
                      <span key={i}>
                        <span className="text-sky-400">{t.tool}</span>: {t.summary}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {m.meta?.gate_e9 && (
                <div className="mt-3 pt-2.5 border-t border-slate-800/80 text-xs">
                  <div className="flex items-center gap-1.5 text-emerald-400 font-medium mb-1">
                    <ShieldCheck className="w-3.5 h-3.5" />
                    {m.meta.gate_e9.verified_badge}
                  </div>
                  <code className="block bg-[#070B12] border border-slate-800 rounded px-2.5 py-1.5 text-[11px] text-sky-300 overflow-x-auto">
                    {m.meta.gate_e9.command}
                  </code>
                </div>
              )}
            </div>
          ))}
          {sending && (
            <div className="text-xs text-slate-400 font-mono px-2">
              Sanitizing IPs through Privacy Proxy &amp; invoking multi-provider gateway...
            </div>
          )}
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            void sendMessage();
          }}
          className="p-3.5 border-t border-slate-800 flex items-center gap-2.5"
        >
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask about host history, zero-day root cause, MITRE mapping, or safe nftables containment..."
            className="flex-1 bg-[#090D16] border border-slate-700 rounded-md px-3.5 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
          />
          <button
            type="submit"
            disabled={sending || !input.trim()}
            className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-slate-950 bg-sky-400 hover:bg-sky-300 disabled:opacity-50 rounded-md transition-colors whitespace-nowrap"
          >
            <Send className="w-3.5 h-3.5" />
            Send
          </button>
        </form>
      </div>
    </div>
  );
}
