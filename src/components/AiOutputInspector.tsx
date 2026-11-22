import { useState } from 'react';
import {
  BrainCircuit,
  Check,
  ChevronDown,
  ChevronRight,
  Clock,
  Copy,
  Cpu,
  KeyRound,
  Lock,
} from 'lucide-react';
import { RichMarkdownRenderer } from './RichMarkdownRenderer';

export interface AiTurnMetadata {
  provider: string;
  model: string;
  api_key_source?: string;
  api_key_status?: string;
  thinking?: string;
  thinking_level?: string;
  latency_ms?: number;
  tokens_estimated?: number;
  privacy_tokens_masked?: number;
  soc_grounded?: boolean;
}

interface AiOutputInspectorProps {
  meta: AiTurnMetadata;
  replyContent: string;
}

function formatLatency(ms?: number): string {
  if (!ms || ms <= 0) return '—';
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)}s`;
  return `${Math.round(ms)} ms`;
}

export function AiOutputInspector({ meta, replyContent }: AiOutputInspectorProps) {
  const [thinkingOpen, setThinkingOpen] = useState(false);
  const [copiedReply, setCopiedReply] = useState(false);

  const isKeyConnected =
    meta.api_key_status?.toLowerCase().includes('connected') ||
    meta.api_key_status?.toLowerCase().includes('configured');

  const handleCopyReply = async () => {
    try {
      await navigator.clipboard.writeText(replyContent);
      setCopiedReply(true);
      window.setTimeout(() => setCopiedReply(false), 1800);
    } catch {
      // Clipboard unavailable
    }
  };

  return (
    <div className="space-y-2.5 mb-3">
      {/* Execution & API Key Metadata Strip */}
      <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-slate-800/80 text-[11px]">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-slate-400">
          <span className="inline-flex items-center gap-1.5 text-slate-200 font-medium">
            <Cpu className="w-3.5 h-3.5 text-sky-400 shrink-0" />
            <span>{meta.provider}</span>
            <span className="text-slate-600">·</span>
            <span className="font-mono text-sky-300">{meta.model}</span>
          </span>

          {(meta.api_key_source || meta.api_key_status) && (
            <span className="inline-flex items-center gap-1.5 font-mono">
              <KeyRound
                className={`w-3 h-3 shrink-0 ${
                  isKeyConnected ? 'text-emerald-400' : 'text-amber-400'
                }`}
              />
              <span className="text-slate-400">{meta.api_key_source || 'Server Key'}:</span>
              <span className={isKeyConnected ? 'text-emerald-400' : 'text-amber-300'}>
                {meta.api_key_status || 'Checked'}
              </span>
            </span>
          )}

          {typeof meta.latency_ms === 'number' && meta.latency_ms > 0 && (
            <span className="inline-flex items-center gap-1 font-mono tabular-nums text-slate-400">
              <Clock className="w-3 h-3 text-slate-500" />
              {formatLatency(meta.latency_ms)}
            </span>
          )}

          {typeof meta.tokens_estimated === 'number' && meta.tokens_estimated > 0 && (
            <span className="font-mono tabular-nums text-slate-500">
              ~{meta.tokens_estimated} tok
            </span>
          )}

          {typeof meta.privacy_tokens_masked === 'number' && meta.privacy_tokens_masked > 0 && (
            <span className="inline-flex items-center gap-1 font-mono text-emerald-400/90">
              <Lock className="w-3 h-3" />
              {meta.privacy_tokens_masked} masked
            </span>
          )}
        </div>

        <button
          type="button"
          onClick={handleCopyReply}
          className="inline-flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-100 transition-colors shrink-0"
          title="Copy formatted response"
        >
          {copiedReply ? (
            <>
              <Check className="w-3 h-3 text-emerald-400" />
              <span className="text-emerald-400">Copied</span>
            </>
          ) : (
            <>
              <Copy className="w-3 h-3" />
              <span>Copy</span>
            </>
          )}
        </button>
      </div>

      {/* Collapsible Model Thinking / Reasoning Accordion */}
      {meta.thinking && meta.thinking.trim().length > 0 && (
        <div className="rounded-lg border border-slate-800/90 bg-[#080D17] overflow-hidden">
          <button
            type="button"
            onClick={() => setThinkingOpen((prev) => !prev)}
            className="w-full flex items-center justify-between gap-2 px-3 py-2 text-left text-xs hover:bg-slate-800/40 transition-colors"
          >
            <span className="inline-flex items-center gap-2 text-slate-300 font-medium">
              <BrainCircuit className="w-3.5 h-3.5 text-violet-400 shrink-0" />
              <span>Model Thinking</span>
              {meta.thinking_level && (
                <span className="font-mono text-[10px] uppercase tracking-wider text-violet-300/90">
                  {meta.thinking_level}
                </span>
              )}
              {typeof meta.latency_ms === 'number' && meta.latency_ms > 0 && (
                <span className="font-mono text-[11px] text-slate-500">
                  · {formatLatency(meta.latency_ms)}
                </span>
              )}
            </span>
            <span className="inline-flex items-center gap-1 text-[11px] text-slate-400">
              <span>{thinkingOpen ? 'Hide trace' : 'Show trace'}</span>
              {thinkingOpen ? (
                <ChevronDown className="w-3.5 h-3.5" />
              ) : (
                <ChevronRight className="w-3.5 h-3.5" />
              )}
            </span>
          </button>

          {thinkingOpen && (
            <div className="px-3.5 py-3 border-t border-slate-800/80 bg-[#060A12] text-slate-300">
              <RichMarkdownRenderer content={meta.thinking} compact />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
