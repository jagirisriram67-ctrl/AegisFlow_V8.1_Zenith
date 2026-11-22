import { useEffect, useRef, useState } from 'react';
import {
  BrainCircuit,
  CheckCircle2,
  Database,
  KeyRound,
  MessageSquarePlus,
  Send,
  Sparkles,
  Trash2,
  Zap,
} from 'lucide-react';
import { RichMarkdownRenderer } from './RichMarkdownRenderer';
import { AiOutputInspector, type AiTurnMetadata } from './AiOutputInspector';

type AssistantMode = 'FAST' | 'THINKING' | 'DEEP';

interface AssistantMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  createdAt: string;
  meta?: AiTurnMetadata & {
    tools_invoked?: Array<{ tool: string; summary: string }>;
  };
}

interface AssistantThread {
  id: string;
  title: string;
  updatedAt: string;
  messages: AssistantMessage[];
}

interface DiagnosticsPayload {
  engine: string;
  inference_mode: string;
  active_profile: string;
  profiles_verified: number;
  profiles: Array<{
    id: string;
    feature_count: number;
    closed_acc: number;
    ood_auroc_known: number;
    status: string;
  }>;
  llm_gateway: {
    active_provider: string;
    fast_model: string;
    reasoning_model: string;
    providers: Record<string, boolean>;
  };
}

const STORAGE_KEY = 'aegisflow_ai_assistant_threads_v1';

const STARTER_CARDS = [
  {
    title: 'Explain AegisFlow-Zenith v8.1',
    subtitle: 'TabM-8, DCN-v2, 9-Primitive MetaOOD & Tier-0 SimHash',
    prompt:
      'Explain how AegisFlow-Zenith v8.1 detects known attacks and zero-day threats end-to-end, including a comparison table of Tier-0, Tier-1, and the 4-Zone Conformal Gate.',
  },
  {
    title: 'Live SOC Shift Summary',
    subtitle: 'Synthesize active incidents & posture from live telemetry',
    prompt:
      'Give me an executive shift briefing of our current live SOC status, active threats, Tier-0 bypass efficiency, and top 3 priorities.',
  },
  {
    title: 'MITRE ATT&CK Playbook Matrix',
    subtitle: 'Structured detection & response table for IoT / Lateral threats',
    prompt:
      'Build a structured Markdown table comparing MITRE ATT&CK techniques for DDoS, Lateral Movement, and Data Exfiltration with detection signals and safe nftables containment examples.',
  },
  {
    title: 'Write a Security Automation Script',
    subtitle: 'Clean Python or bash helper with syntax highlighting',
    prompt:
      'Write a clean Python script that queries our AegisFlow /api/model/diagnostics and /api/dashboard endpoints, prints a health summary, and alerts if RED incidents exceed a threshold.',
  },
];

const MODE_OPTIONS: Array<{
  id: AssistantMode;
  label: string;
  hint: string;
}> = [
  { id: 'FAST', label: 'Fast', hint: 'Flash Lite' },
  { id: 'THINKING', label: 'Thinking', hint: 'Hydrogen' },
  { id: 'DEEP', label: 'Deep', hint: 'High Reasoning' },
];

function createEmptyThread(): AssistantThread {
  return {
    id: `thr-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
    title: 'New Conversation',
    updatedAt: new Date().toISOString(),
    messages: [],
  };
}

function loadSavedThreads(): AssistantThread[] {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [createEmptyThread()];
    const parsed = JSON.parse(raw) as AssistantThread[];
    if (!Array.isArray(parsed) || parsed.length === 0) return [createEmptyThread()];
    return parsed.slice(0, 25);
  } catch {
    return [createEmptyThread()];
  }
}

export function AiAssistantView() {
  const [threads, setThreads] = useState<AssistantThread[]>(() => loadSavedThreads());
  const [activeThreadId, setActiveThreadId] = useState<string>(() => loadSavedThreads()[0].id);
  const [mode, setMode] = useState<AssistantMode>('THINKING');
  const [includeSocContext, setIncludeSocContext] = useState<boolean>(true);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [diagnostics, setDiagnostics] = useState<DiagnosticsPayload | null>(null);
  const endRef = useRef<HTMLDivElement | null>(null);

  const activeThread = threads.find((t) => t.id === activeThreadId) ?? threads[0];

  useEffect(() => {
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(threads.slice(0, 25)));
    } catch {
      // Ignore storage quota issues
    }
  }, [threads]);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [activeThread?.messages.length, sending]);

  useEffect(() => {
    fetch('/api/model/diagnostics')
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d) setDiagnostics(d);
      })
      .catch(() => {});
  }, []);

  const handleNewChat = () => {
    const fresh = createEmptyThread();
    setThreads((prev) => [fresh, ...prev].slice(0, 25));
    setActiveThreadId(fresh.id);
    setInput('');
  };

  const handleDeleteThread = (id: string) => {
    setThreads((prev) => {
      const remaining = prev.filter((t) => t.id !== id);
      if (remaining.length === 0) {
        const fresh = createEmptyThread();
        setActiveThreadId(fresh.id);
        return [fresh];
      }
      if (activeThreadId === id) {
        setActiveThreadId(remaining[0].id);
      }
      return remaining;
    });
  };

  const sendMessage = async (overrideText?: string) => {
    const prompt = (overrideText ?? input).trim();
    if (!prompt || sending || !activeThread) return;

    const userMsg: AssistantMessage = {
      id: `m-${Date.now()}-u`,
      role: 'user',
      content: prompt,
      createdAt: new Date().toISOString(),
    };

    const currentThreadId = activeThread.id;
    const priorHistory = activeThread.messages.map((m) => ({
      role: m.role,
      content: m.content,
    }));

    const nextTitle =
      activeThread.messages.length === 0
        ? prompt.slice(0, 44) + (prompt.length > 44 ? '…' : '')
        : activeThread.title;

    setThreads((prev) =>
      prev.map((t) =>
        t.id === currentThreadId
          ? {
              ...t,
              title: nextTitle,
              updatedAt: userMsg.createdAt,
              messages: [...t.messages, userMsg],
            }
          : t
      )
    );
    setInput('');
    setSending(true);

    try {
      const res = await fetch('/api/assistant/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: prompt,
          history: priorHistory.slice(-10),
          mode,
          include_soc_context: includeSocContext,
        }),
      });
      const data = await res.json();
      const assistantMsg: AssistantMessage = {
        id: `m-${Date.now()}-a`,
        role: 'assistant',
        content: data.reply || data.error || 'No response received.',
        createdAt: new Date().toISOString(),
        meta: data.provider
          ? {
              provider: data.provider,
              model: data.model,
              api_key_source: data.api_key_source,
              api_key_status: data.api_key_status,
              thinking: data.thinking,
              thinking_level: data.thinking_level,
              latency_ms: data.latency_ms,
              tokens_estimated: data.tokens_estimated,
              privacy_tokens_masked: data.privacy_tokens_masked ?? 0,
              soc_grounded: data.soc_grounded,
              tools_invoked: data.tools_invoked ?? [],
            }
          : undefined,
      };

      setThreads((prev) =>
        prev.map((t) =>
          t.id === currentThreadId
            ? {
                ...t,
                updatedAt: assistantMsg.createdAt,
                messages: [...t.messages, assistantMsg],
              }
            : t
        )
      );
    } catch {
      const errMsg: AssistantMessage = {
        id: `m-${Date.now()}-e`,
        role: 'assistant',
        content: 'Unable to connect to `/api/assistant/chat`. Please verify the server is running.',
        createdAt: new Date().toISOString(),
      };
      setThreads((prev) =>
        prev.map((t) =>
          t.id === currentThreadId
            ? { ...t, messages: [...t.messages, errMsg] }
            : t
        )
      );
    } finally {
      setSending(false);
    }
  };

  const activeModelName =
    mode === 'FAST'
      ? diagnostics?.llm_gateway.fast_model ?? 'gemini-3.1-flash-lite'
      : diagnostics?.llm_gateway.reasoning_model ?? 'gemini-4-hydrogen';

  const geminiConnected = diagnostics?.llm_gateway.providers?.GEMINI;

  return (
    <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-stretch min-h-[720px]">
      {/* Left Conversation History Sidebar */}
      <aside className="xl:col-span-3 bg-[#0F1623] border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between gap-4">
        <div className="space-y-3 min-h-0 flex-1 flex flex-col">
          <button
            type="button"
            onClick={handleNewChat}
            className="w-full inline-flex items-center justify-center gap-2 px-3.5 py-2.5 rounded-lg bg-sky-400 hover:bg-sky-300 text-slate-950 font-semibold text-xs transition-colors"
          >
            <MessageSquarePlus className="w-4 h-4" />
            New Chat
          </button>

          <div className="text-[11px] font-medium uppercase tracking-wider text-slate-500 px-1 pt-1">
            Recent Conversations
          </div>

          <div className="flex-1 overflow-y-auto space-y-1 pr-0.5 max-h-[430px]">
            {threads.map((thr) => {
              const isSelected = thr.id === activeThread?.id;
              return (
                <div
                  key={thr.id}
                  className={`group flex items-center justify-between gap-1.5 rounded-lg px-2.5 py-2 text-xs transition-colors ${
                    isSelected
                      ? 'bg-slate-800/90 text-slate-100 border border-slate-700/80'
                      : 'text-slate-400 hover:bg-slate-900/70 hover:text-slate-200 border border-transparent'
                  }`}
                >
                  <button
                    type="button"
                    onClick={() => setActiveThreadId(thr.id)}
                    className="flex-1 text-left truncate"
                  >
                    {thr.title}
                  </button>
                  <button
                    type="button"
                    onClick={() => handleDeleteThread(thr.id)}
                    title="Delete conversation"
                    className="opacity-60 hover:opacity-100 text-slate-400 hover:text-rose-400 p-0.5 transition-colors"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              );
            })}
          </div>
        </div>

        {/* Live Engine & Server API Key Status Card */}
        <div className="rounded-lg bg-[#0A101C] border border-slate-800/90 p-3 space-y-2 text-[11px]">
          <div className="flex items-center justify-between text-slate-200 font-medium">
            <span className="inline-flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              AegisFlow-Zenith v8.1
            </span>
            <span className="font-mono text-emerald-400">
              {diagnostics ? `${diagnostics.profiles_verified}/6 Ready` : 'Ready'}
            </span>
          </div>
          <div className="flex items-center justify-between text-slate-400">
            <span className="inline-flex items-center gap-1">
              <KeyRound className={`w-3 h-3 ${geminiConnected ? 'text-emerald-400' : 'text-amber-400'}`} />
              API Key
            </span>
            <span className={`font-mono ${geminiConnected ? 'text-emerald-400' : 'text-amber-300'}`}>
              {geminiConnected ? 'GEMINI_API_KEY · Live' : 'Fallback Mode'}
            </span>
          </div>
          <div className="flex items-center justify-between text-slate-400">
            <span>Active Model</span>
            <span className="font-mono text-sky-300 truncate max-w-[140px]">{activeModelName}</span>
          </div>
        </div>
      </aside>

      {/* Main ChatGPT / Gemini / Claude Workspace */}
      <section className="xl:col-span-9 bg-[#0F1623] border border-slate-800 rounded-xl flex flex-col h-[740px] overflow-hidden">
        {/* Top Controls Bar */}
        <div className="px-5 py-3 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 bg-[#0C1220]">
          <div className="flex items-center gap-2.5">
            <Sparkles className="w-4 h-4 text-sky-400" />
            <div>
              <h2 className="text-sm font-semibold text-slate-100">AI Assistant</h2>
              <p className="text-[11px] text-slate-400">
                Conversational help, coding, threat analysis &amp; structured documentation
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {/* Mode Switcher */}
            <div className="inline-flex items-center rounded-lg bg-[#090D16] border border-slate-800 p-0.5">
              {MODE_OPTIONS.map((opt) => (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => setMode(opt.id)}
                  className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-colors inline-flex items-center gap-1.5 ${
                    mode === opt.id
                      ? 'bg-slate-800 text-sky-300'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {opt.id === 'FAST' ? (
                    <Zap className="w-3 h-3" />
                  ) : (
                    <BrainCircuit className="w-3 h-3 text-violet-400" />
                  )}
                  <span>{opt.label}</span>
                  <span className="hidden sm:inline text-[10px] text-slate-500">· {opt.hint}</span>
                </button>
              ))}
            </div>

            {/* Live SOC Context Toggle */}
            <button
              type="button"
              onClick={() => setIncludeSocContext((v) => !v)}
              className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-medium border transition-colors ${
                includeSocContext
                  ? 'bg-emerald-500/10 border-emerald-500/35 text-emerald-300'
                  : 'bg-[#090D16] border-slate-800 text-slate-400 hover:text-slate-200'
              }`}
              title="Attach live AegisFlow telemetry & Hybrid RAG context to answers"
            >
              <Database className="w-3.5 h-3.5" />
              Live SOC Context: {includeSocContext ? 'ON' : 'OFF'}
            </button>
          </div>
        </div>

        {/* Message Feed or Clean Consumer Welcome Screen */}
        <div className="flex-1 overflow-y-auto px-5 py-6">
          {!activeThread || activeThread.messages.length === 0 ? (
            <div className="max-w-3xl mx-auto pt-8 pb-4 space-y-8">
              <div className="text-center space-y-2.5">
                <div className="inline-flex items-center justify-center w-11 h-11 rounded-xl bg-sky-500/10 border border-sky-500/25 text-sky-400">
                  <Sparkles className="w-5 h-5" />
                </div>
                <h3 className="text-xl font-semibold text-slate-50 tracking-tight">
                  How can I help you today?
                </h3>
                <p className="text-xs sm:text-sm text-slate-400 max-w-xl mx-auto">
                  Ask anything — from general engineering, scripting, and cybersecurity playbooks to live{' '}
                  <span className="text-slate-200 font-medium">AegisFlow-Zenith v8.1</span> telemetry insights.
                  Every response shows the active model, API key status, expandable thinking trace, and clean formatted output.
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {STARTER_CARDS.map((card) => (
                  <button
                    key={card.title}
                    type="button"
                    disabled={sending}
                    onClick={() => void sendMessage(card.prompt)}
                    className="text-left p-4 rounded-xl bg-[#0B111E] hover:bg-slate-800/70 border border-slate-800 hover:border-slate-700 transition-colors space-y-1"
                  >
                    <div className="text-xs font-semibold text-slate-100">{card.title}</div>
                    <div className="text-[11.5px] text-slate-400 leading-relaxed">{card.subtitle}</div>
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <div className="max-w-4xl mx-auto space-y-5">
              {activeThread.messages.map((msg) => (
                <div
                  key={msg.id}
                  className={
                    msg.role === 'user'
                      ? 'flex justify-end'
                      : 'flex justify-start'
                  }
                >
                  {msg.role === 'user' ? (
                    <div className="max-w-[82%] rounded-2xl rounded-tr-sm px-4 py-3 bg-sky-500/15 border border-sky-500/30 text-[13.5px] leading-relaxed text-slate-100 whitespace-pre-wrap">
                      {msg.content}
                    </div>
                  ) : (
                    <div className="w-full rounded-xl p-4 sm:p-5 bg-[#0B111E] border border-slate-800">
                      {msg.meta && (
                        <AiOutputInspector meta={msg.meta} replyContent={msg.content} />
                      )}
                      <RichMarkdownRenderer content={msg.content} />
                    </div>
                  )}
                </div>
              ))}

              {sending && (
                <div className="w-full rounded-xl p-4 bg-[#0B111E] border border-slate-800/90 space-y-1.5">
                  <div className="flex items-center gap-2 text-xs font-medium text-sky-300">
                    <BrainCircuit className="w-4 h-4 animate-pulse text-violet-400" />
                    Generating response with {activeModelName} ({mode})...
                  </div>
                  <div className="text-[11px] font-mono text-slate-500">
                    {includeSocContext
                      ? 'Attaching live SOC snapshot & Privacy Proxy protection'
                      : 'Running general conversational reasoning'}
                  </div>
                </div>
              )}
              <div ref={endRef} />
            </div>
          )}
        </div>

        {/* Multiline Composer (Enter sends, Shift+Enter inserts newline) */}
        <div className="p-4 border-t border-slate-800 bg-[#0C1220]">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void sendMessage();
            }}
            className="max-w-4xl mx-auto flex items-end gap-2.5"
          >
            <textarea
              rows={2}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  void sendMessage();
                }
              }}
              placeholder="Message AegisFlow AI Assistant… (Enter to send, Shift+Enter for new line)"
              className="flex-1 resize-none bg-[#090D16] border border-slate-700 rounded-xl px-4 py-2.5 text-xs sm:text-[13.5px] text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
            />
            <button
              type="submit"
              disabled={sending || !input.trim()}
              className="inline-flex items-center gap-1.5 px-4 py-3 text-xs font-semibold text-slate-950 bg-sky-400 hover:bg-sky-300 disabled:opacity-50 rounded-xl transition-colors whitespace-nowrap"
            >
              <Send className="w-3.5 h-3.5" />
              Send
            </button>
          </form>
        </div>
      </section>
    </div>
  );
}
