import { useState, type ReactNode } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Check, Copy } from 'lucide-react';

interface RichMarkdownRendererProps {
  content: string;
  compact?: boolean;
}

function CodeBlock({
  language,
  code,
}: {
  language: string;
  code: string;
}) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      // Clipboard unavailable in restricted context
    }
  };

  return (
    <div className="my-3 rounded-lg overflow-hidden border border-slate-800 bg-[#070B12]">
      <div className="flex items-center justify-between px-3 py-1.5 bg-[#0D1422] border-b border-slate-800/90">
        <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">
          {language || 'code'}
        </span>
        <button
          type="button"
          onClick={handleCopy}
          className="inline-flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-100 transition-colors"
        >
          {copied ? (
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
      <pre className="p-3.5 overflow-x-auto text-[12px] leading-relaxed font-mono text-sky-200/95">
        <code>{code}</code>
      </pre>
    </div>
  );
}

function sanitizeHref(href?: string): string | undefined {
  if (!href) return undefined;
  const trimmed = href.trim();
  if (trimmed.startsWith('https://') || trimmed.startsWith('http://') || trimmed.startsWith('mailto:')) {
    return trimmed;
  }
  return undefined;
}

export function RichMarkdownRenderer({ content, compact = false }: RichMarkdownRendererProps) {
  const textSize = compact ? 'text-xs' : 'text-[13.5px]';

  return (
    <div className={`${textSize} leading-relaxed text-slate-200 space-y-2.5 break-words`}>
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          h1: ({ children }: { children?: ReactNode }) => (
            <h1
              className={`${
                compact ? 'text-sm' : 'text-lg'
              } font-semibold text-slate-50 tracking-tight pt-1.5 pb-1 border-b border-slate-800/80`}
            >
              {children}
            </h1>
          ),
          h2: ({ children }: { children?: ReactNode }) => (
            <h2
              className={`${
                compact ? 'text-[13px]' : 'text-[15px]'
              } font-semibold text-slate-50 tracking-tight pt-2`}
            >
              {children}
            </h2>
          ),
          h3: ({ children }: { children?: ReactNode }) => (
            <h3
              className={`${
                compact ? 'text-xs' : 'text-[14px]'
              } font-semibold text-sky-300 pt-1.5`}
            >
              {children}
            </h3>
          ),
          h4: ({ children }: { children?: ReactNode }) => (
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300 pt-1">
              {children}
            </h4>
          ),
          p: ({ children }: { children?: ReactNode }) => (
            <p className="text-slate-200/95 leading-[1.65]">{children}</p>
          ),
          strong: ({ children }: { children?: ReactNode }) => (
            <strong className="font-semibold text-slate-50">{children}</strong>
          ),
          em: ({ children }: { children?: ReactNode }) => (
            <em className="italic text-slate-300">{children}</em>
          ),
          ul: ({ children }: { children?: ReactNode }) => (
            <ul className="list-disc pl-5 space-y-1.5 text-slate-200/95 marker:text-sky-400/80">
              {children}
            </ul>
          ),
          ol: ({ children }: { children?: ReactNode }) => (
            <ol className="list-decimal pl-5 space-y-1.5 text-slate-200/95 marker:text-sky-400/90 marker:font-mono marker:text-xs">
              {children}
            </ol>
          ),
          li: ({ children }: { children?: ReactNode }) => (
            <li className="leading-[1.6] pl-0.5">{children}</li>
          ),
          blockquote: ({ children }: { children?: ReactNode }) => (
            <blockquote className="border-l-2 border-sky-400/70 bg-sky-500/5 pl-3.5 pr-3 py-2 rounded-r-md text-slate-300 italic">
              {children}
            </blockquote>
          ),
          hr: () => <hr className="border-slate-800 my-3" />,
          a: ({ href, children }: { href?: string; children?: ReactNode }) => {
            const safe = sanitizeHref(href);
            if (!safe) return <span className="text-sky-300">{children}</span>;
            return (
              <a
                href={safe}
                target="_blank"
                rel="noopener noreferrer"
                className="text-sky-400 hover:text-sky-300 underline underline-offset-2"
              >
                {children}
              </a>
            );
          },
          table: ({ children }: { children?: ReactNode }) => (
            <div className="my-3 overflow-x-auto rounded-lg border border-slate-800 bg-[#080C15]">
              <table className="w-full text-left border-collapse text-xs">{children}</table>
            </div>
          ),
          thead: ({ children }: { children?: ReactNode }) => (
            <thead className="bg-[#0F172A] text-slate-200 border-b border-slate-800">
              {children}
            </thead>
          ),
          tbody: ({ children }: { children?: ReactNode }) => (
            <tbody className="divide-y divide-slate-800/75">{children}</tbody>
          ),
          tr: ({ children }: { children?: ReactNode }) => (
            <tr className="hover:bg-slate-800/35 transition-colors">{children}</tr>
          ),
          th: ({ children }: { children?: ReactNode }) => (
            <th className="px-3 py-2 font-semibold text-slate-100 whitespace-nowrap">{children}</th>
          ),
          td: ({ children }: { children?: ReactNode }) => (
            <td className="px-3 py-2 text-slate-300 align-top tabular-nums">{children}</td>
          ),
          pre: ({ children }: { children?: ReactNode }) => <>{children}</>,
          code: ({
            className,
            children,
          }: {
            className?: string;
            children?: ReactNode;
          }) => {
            const rawText = String(children ?? '').replace(/\n$/, '');
            const langMatch = /language-([\w-]+)/.exec(className || '');
            const isBlock = Boolean(langMatch) || rawText.includes('\n');

            if (isBlock) {
              return <CodeBlock language={langMatch?.[1] ?? 'text'} code={rawText} />;
            }

            return (
              <code className="px-1.5 py-0.5 rounded bg-slate-800/90 border border-slate-700/70 font-mono text-[12px] text-sky-300">
                {rawText}
              </code>
            );
          },
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
}
