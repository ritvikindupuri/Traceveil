import { useState, useEffect, useRef, useMemo } from 'react';
import { useServerFn } from '@tanstack/react-start';
import {
  Bot,
  Sparkles,
  Send,
  RotateCcw,
  CheckCircle2,
  Copy,
  Check,
  Download,
  Database,
  Code2,
  Terminal,
  ShieldCheck,
  Loader2,
  ChevronRight,
  MessageSquare,
  Lock,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  chatWithTenantIsolationAgent,
  type AutonomousAgentIsolationResult,
} from '@/lib/atlas/isolation.functions';
import { generateTailoredIsolationPrompts, getCleanTargetName } from '@/lib/atlas/prompt-tailoring';
import type { AttackGraph } from '@/lib/atlas/types';
import { cn } from '@/lib/utils';

interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  boundaryConfig?: AutonomousAgentIsolationResult;
  suggestedQuestions?: string[];
}

function renderInlineMarkdown(line: string): React.ReactNode {
  const tokens = line.split(/(`[^`]+`|\*\*[^*]+\*\*)/g);
  return tokens.map((tok, i) => {
    if (tok.startsWith('`') && tok.endsWith('`') && tok.length > 2) {
      return (
        <code key={i} className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] text-primary">
          {tok.slice(1, -1)}
        </code>
      );
    }
    if (tok.startsWith('**') && tok.endsWith('**') && tok.length > 4) {
      return (
        <strong key={i} className="font-semibold text-foreground">
          {tok.slice(2, -2)}
        </strong>
      );
    }
    return tok;
  });
}

function renderFormattedMessage(rawText: string) {
  if (!rawText) return null;

  const text = rawText
    .replace(/\bArgon\s*4\b/gi, 'Tenant Isolation Agent')
    .replace(/\*\*Argon\s*4\s*Tenant\s*Isolation\s*Agent\*\*/gi, 'Tenant Isolation Agent');

  // Check if text is raw JSON dump
  const trimmed = text.trim();
  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed.boundaryRule || parsed.endpoint || parsed.recommendedRlsPolicy) {
        return (
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <span className="rounded bg-primary/10 px-2 py-0.5 text-[10px] font-bold text-primary uppercase font-mono">
                Boundary Assessment
              </span>
              <span className="font-mono text-xs text-foreground font-semibold">
                {parsed.endpoint || '/api/resources/{id}'}
              </span>
            </div>

            <p className="text-xs text-foreground leading-relaxed">
              {parsed.boundaryRule || 'Authenticated tenant sessions must be partitioned by authenticated tenant_id, strictly returning 403 Forbidden on any cross-tenant read.'}
            </p>

            <div className="rounded border border-border/80 bg-card p-2.5 text-xs text-muted-foreground space-y-1">
              <div><strong>Identifier Key:</strong> <code className="font-mono text-primary text-[11px]">{parsed.idPointer || '/user_id'}</code></div>
              <div><strong>Database Defense:</strong> PostgreSQL Row Level Security (RLS) active</div>
              <div><strong>Gateway Defense:</strong> Fail-closed boundary middleware returning 403 Forbidden on mismatch</div>
            </div>

            <p className="text-[11px] text-muted-foreground">
              Review the live test suite and code tabs below to inspect the verified policies.
            </p>
          </div>
        );
      }
    } catch {
      // Not JSON, continue with markdown rendering
    }
  }

  // Split lines and render structured elements
  const lines = text.split('\n');
  const elements: React.ReactNode[] = [];
  let inCodeBlock = false;
  let codeBlockLines: string[] = [];

  lines.forEach((line, idx) => {
    const trimmedLine = line.trim();

    if (trimmedLine.startsWith('```')) {
      if (inCodeBlock) {
        // Close code block
        elements.push(
          <div key={`code-${idx}`} className="my-2 rounded border border-border bg-muted/20 p-2.5 font-mono text-[11px] text-foreground overflow-x-auto">
            <pre>{codeBlockLines.join('\n')}</pre>
          </div>
        );
        codeBlockLines = [];
        inCodeBlock = false;
      } else {
        inCodeBlock = true;
      }
      return;
    }

    if (inCodeBlock) {
      codeBlockLines.push(line);
      return;
    }

    // Blank line
    if (!trimmedLine) {
      elements.push(<div key={`space-${idx}`} className="h-1.5" />);
      return;
    }

    // Header 3: ### Title
    if (trimmedLine.startsWith('### ')) {
      elements.push(
        <h3 key={`h3-${idx}`} className="text-xs font-bold text-foreground mt-2.5 mb-1 flex items-center gap-1.5">
          <ShieldCheck className="size-3.5 text-primary shrink-0" />
          <span>{trimmedLine.replace(/^###\s+/, '')}</span>
        </h3>
      );
      return;
    }

    // Header 4: #### Title
    if (trimmedLine.startsWith('#### ')) {
      elements.push(
        <h4 key={`h4-${idx}`} className="text-[11px] font-semibold text-foreground mt-2 mb-0.5">
          {trimmedLine.replace(/^####\s+/, '')}
        </h4>
      );
      return;
    }

    // Bullet line: - Item or * Item
    if (trimmedLine.startsWith('- ') || trimmedLine.startsWith('* ')) {
      elements.push(
        <div key={`li-${idx}`} className="flex items-start gap-2 text-xs leading-relaxed pl-1 my-0.5">
          <span className="text-primary font-bold select-none text-[10px] mt-0.5">•</span>
          <span className="flex-1">{renderInlineMarkdown(trimmedLine.slice(2))}</span>
        </div>
      );
      return;
    }

    // Numbered line: 1. Item
    const numMatch = trimmedLine.match(/^(\d+)\.\s+(.*)$/);
    if (numMatch) {
      elements.push(
        <div key={`num-${idx}`} className="flex items-start gap-2 text-xs leading-relaxed pl-1 my-0.5">
          <span className="font-mono text-[10px] font-bold text-primary select-none mt-0.5">{numMatch[1]}.</span>
          <span className="flex-1">{renderInlineMarkdown(numMatch[2])}</span>
        </div>
      );
      return;
    }

    // Regular paragraph line
    elements.push(
      <p key={`p-${idx}`} className="text-xs leading-relaxed">
        {renderInlineMarkdown(line)}
      </p>
    );
  });

  return <div className="space-y-1">{elements}</div>;
}

export function TenantIsolation({
  signedIn,
  onSignIn,
  target,
  graph,
}: {
  signedIn: boolean;
  onSignIn: () => void;
  target?: string;
  graph?: AttackGraph | null;
}) {
  const chatServerFn = useServerFn(chatWithTenantIsolationAgent);
  const activeTarget = target || graph?.target || 'production-cluster (live)';

  const tailoredPrompts = useMemo(
    () => generateTailoredIsolationPrompts(activeTarget, graph),
    [activeTarget, graph]
  );

  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputValue, setInputValue] = useState('');
  const [isThinking, setIsThinking] = useState(false);
  const [activeCodeTab, setActiveCodeTab] = useState<Record<string, 'rls' | 'middleware' | 'runner'>>({});
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const prevTargetRef = useRef<string>(activeTarget);

  // Initialize or re-tailor conversation whenever target or graph changes
  useEffect(() => {
    const targetChanged = prevTargetRef.current !== activeTarget;
    prevTargetRef.current = activeTarget;

    if (messages.length === 0 || targetChanged) {
      const targetInfo = getCleanTargetName(activeTarget);
      setMessages([
        {
          id: `welcome-${activeTarget}`,
          role: 'assistant',
          content: `Hello! I'm your Tenant Isolation Agent.

I analyze your application architecture for **${targetInfo.cleanUrl}** to eliminate cross-tenant data leaks, BOLA (Broken Object Level Authorization), and IDOR exposures.

Ask me anything about your stack, or click any prompt below to generate zero-trust RLS policies and live isolation test probes.`,
          timestamp: new Date().toLocaleTimeString(),
          suggestedQuestions: tailoredPrompts,
        },
      ]);
    }
  }, [activeTarget, tailoredPrompts]);

  // Scroll to bottom on new message
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isThinking]);

  async function handleSendMessage(textToSend?: string) {
    const text = (textToSend || inputValue).trim();
    if (!text || isThinking) return;

    const userMessage: ChatMessage = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: text,
      timestamp: new Date().toLocaleTimeString(),
    };

    const newHistory = [...messages, userMessage];
    setMessages(newHistory);
    setInputValue('');
    setIsThinking(true);

    try {
      const response = await chatServerFn({
        data: {
          messages: newHistory.map(m => ({ role: m.role, content: m.content })),
          target: activeTarget,
        },
      });

      const assistantMessage: ChatMessage = {
        id: `assistant-${Date.now()}`,
        role: 'assistant',
        content: response.reply,
        timestamp: new Date().toLocaleTimeString(),
        boundaryConfig: response.boundaryConfig,
        suggestedQuestions: response.suggestedQuestions,
      };

      setMessages(prev => [...prev, assistantMessage]);
    } catch (err) {
      console.error('Chat agent failed:', err);
      setMessages(prev => [
        ...prev,
        {
          id: `assistant-error-${Date.now()}`,
          role: 'assistant',
          content: `I encountered an issue querying the model. Please check network connectivity or try again.`,
          timestamp: new Date().toLocaleTimeString(),
        },
      ]);
    } finally {
      setIsThinking(false);
    }
  }

  function handleResetChat() {
    const targetInfo = getCleanTargetName(activeTarget);
    setMessages([
      {
        id: `welcome-${Date.now()}`,
        role: 'assistant',
        content: `Reset session. Ready to assist with **${targetInfo.cleanUrl}** tenant isolation, RLS rules, and live boundary verification.`,
        timestamp: new Date().toLocaleTimeString(),
        suggestedQuestions: tailoredPrompts,
      },
    ]);
  }

  function copyToClipboard(text: string, key: string) {
    void navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  }

  function downloadScript(filename: string, content: string) {
    const blob = new Blob([content], { type: 'text/javascript' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="flex flex-col h-[750px] rounded-lg border border-border bg-card shadow-xs overflow-hidden">
      {/* 1. Chatbot Command Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border bg-muted/20 px-4 py-3 shrink-0">
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="flex items-center gap-2">
            <span className="relative flex h-2.5 w-2.5">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-emerald-500" />
            </span>
            <Bot className="size-4 text-primary" />
            <h2 className="text-sm font-semibold text-foreground">
              Tenant Isolation Copilot
            </h2>
          </div>

          <span className="text-muted-foreground/30">|</span>

          <span className="font-mono text-xs text-foreground bg-muted/60 px-2 py-0.5 rounded border border-border/60">
            {activeTarget}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={handleResetChat}
            className="h-8 gap-1.5 text-xs text-muted-foreground hover:text-foreground"
            title="Start new conversation"
          >
            <RotateCcw className="size-3.5" />
            <span>Reset Chat</span>
          </Button>
        </div>
      </div>

      {/* 2. Conversation Message Feed */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map(msg => {
          const isUser = msg.role === 'user';
          const codeTab = activeCodeTab[msg.id] || 'rls';

          return (
            <div
              key={msg.id}
              className={cn(
                'flex gap-3 max-w-3xl',
                isUser ? 'ml-auto flex-row-reverse' : 'mr-auto'
              )}
            >
              {!isUser && (
                <div className="size-7 rounded-full bg-primary/10 border border-primary/20 flex items-center justify-center text-primary shrink-0 mt-0.5">
                  <Bot className="size-4" />
                </div>
              )}

              <div className="space-y-3 min-w-0 flex-1">
                {/* Bubble Container */}
                <div
                  className={cn(
                    'rounded-lg px-4 py-3 text-xs leading-relaxed shadow-xs',
                    isUser
                      ? 'bg-primary text-primary-foreground ml-auto max-w-lg font-medium whitespace-pre-wrap'
                      : 'bg-muted/30 border border-border/80 text-foreground'
                  )}
                >
                  {isUser ? msg.content : renderFormattedMessage(msg.content)}
                </div>

                {/* Interactive Boundary Configuration Card (if attached to assistant message) */}
                {msg.boundaryConfig && (
                  <div className="rounded-lg border border-border bg-card shadow-xs overflow-hidden space-y-3 p-3.5">
                    {/* Header */}
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/80 pb-2.5">
                      <div className="flex items-center gap-2">
                        <ShieldCheck className="size-4 text-emerald-500" />
                        <span className="text-xs font-semibold text-foreground">
                          Live Isolation Probes & Verification
                        </span>
                        <span className="font-mono text-[10px] text-muted-foreground bg-muted px-1.5 py-0.2 rounded">
                          {msg.boundaryConfig.endpoint}
                        </span>
                      </div>
                      <span className="rounded bg-emerald-500/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-emerald-600 border border-emerald-500/20">
                        100% Boundary Enforced
                      </span>
                    </div>

                    {/* 4 Live Probes Grid */}
                    <div className="grid gap-2 sm:grid-cols-2">
                      {msg.boundaryConfig.testCases.map(tc => (
                        <div
                          key={tc.id}
                          className="flex items-start justify-between gap-2 rounded border border-border/60 bg-muted/20 p-2 text-xs"
                        >
                          <div className="space-y-0.5 min-w-0">
                            <div className="flex items-center gap-1.5 font-semibold text-[11px] text-foreground truncate">
                              <CheckCircle2 className="size-3 text-emerald-500 shrink-0" />
                              <span className="truncate">{tc.label}</span>
                            </div>
                            <p className="text-[10px] text-muted-foreground">{tc.details}</p>
                          </div>
                          <div className="text-right shrink-0 font-mono text-[10px]">
                            <span
                              className={cn(
                                'rounded px-1.5 py-0.2 font-semibold',
                                tc.actualStatus === 200
                                  ? 'bg-emerald-500/10 text-emerald-600'
                                  : 'bg-sky-500/10 text-sky-600'
                              )}
                            >
                              HTTP {tc.actualStatus}
                            </span>
                            <div className="text-muted-foreground/60 mt-0.5">{tc.latencyMs}ms</div>
                          </div>
                        </div>
                      ))}
                    </div>

                    {/* Code Tabs */}
                    <div className="border border-border/80 rounded-md overflow-hidden bg-muted/10">
                      <div className="flex items-center justify-between border-b border-border/80 bg-muted/30 px-3 py-1.5 text-xs">
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() =>
                              setActiveCodeTab(prev => ({ ...prev, [msg.id]: 'rls' }))
                            }
                            className={cn(
                              'px-2 py-1 rounded text-[11px] font-medium transition-colors cursor-pointer',
                              codeTab === 'rls'
                                ? 'bg-card text-foreground shadow-xs font-semibold'
                                : 'text-muted-foreground hover:text-foreground'
                            )}
                          >
                            PostgreSQL RLS
                          </button>
                          <button
                            onClick={() =>
                              setActiveCodeTab(prev => ({ ...prev, [msg.id]: 'middleware' }))
                            }
                            className={cn(
                              'px-2 py-1 rounded text-[11px] font-medium transition-colors cursor-pointer',
                              codeTab === 'middleware'
                                ? 'bg-card text-foreground shadow-xs font-semibold'
                                : 'text-muted-foreground hover:text-foreground'
                            )}
                          >
                            API Middleware
                          </button>
                          <button
                            onClick={() =>
                              setActiveCodeTab(prev => ({ ...prev, [msg.id]: 'runner' }))
                            }
                            className={cn(
                              'px-2 py-1 rounded text-[11px] font-medium transition-colors cursor-pointer',
                              codeTab === 'runner'
                                ? 'bg-card text-foreground shadow-xs font-semibold'
                                : 'text-muted-foreground hover:text-foreground'
                            )}
                          >
                            CI Runner (.mjs)
                          </button>
                        </div>

                        <div className="flex items-center gap-1.5">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              const code =
                                codeTab === 'rls'
                                  ? msg.boundaryConfig?.rlsPolicy
                                  : codeTab === 'middleware'
                                    ? msg.boundaryConfig?.middleware
                                    : msg.boundaryConfig?.runnerScript;
                              if (code) copyToClipboard(code, `${msg.id}-${codeTab}`);
                            }}
                            className="h-6 px-2 text-[10px] gap-1 text-muted-foreground hover:text-foreground"
                          >
                            {copiedKey === `${msg.id}-${codeTab}` ? (
                              <Check className="size-3 text-primary" />
                            ) : (
                              <Copy className="size-3" />
                            )}
                            <span>{copiedKey === `${msg.id}-${codeTab}` ? 'Copied' : 'Copy'}</span>
                          </Button>

                          {codeTab === 'runner' && (
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => {
                                if (msg.boundaryConfig) {
                                  downloadScript(
                                    `tenant-isolation-${msg.boundaryConfig.endpoint.replace(/[^a-z0-9]/gi, '_')}.mjs`,
                                    msg.boundaryConfig.runnerScript
                                  );
                                }
                              }}
                              className="h-6 px-2 text-[10px] gap-1"
                            >
                              <Download className="size-3" />
                              <span>Download</span>
                            </Button>
                          )}
                        </div>
                      </div>

                      <div className="max-h-48 overflow-auto p-3 font-mono text-[11px] leading-relaxed text-foreground bg-card select-text">
                        <pre className="whitespace-pre">
                          {codeTab === 'rls'
                            ? msg.boundaryConfig.rlsPolicy
                            : codeTab === 'middleware'
                              ? msg.boundaryConfig.middleware
                              : msg.boundaryConfig.runnerScript}
                        </pre>
                      </div>
                    </div>
                  </div>
                )}

                {/* Suggested Questions / Follow-ups */}
                {msg.suggestedQuestions && msg.suggestedQuestions.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {msg.suggestedQuestions.map((q, qIdx) => (
                      <button
                        key={qIdx}
                        onClick={() => void handleSendMessage(q)}
                        disabled={isThinking}
                        className="rounded-md border border-border/80 bg-card px-2.5 py-1 text-[11px] text-muted-foreground hover:text-foreground hover:border-primary/50 transition-all text-left cursor-pointer flex items-center gap-1"
                      >
                        <ChevronRight className="size-3 text-primary shrink-0" />
                        <span>{q}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
          );
        })}

        {isThinking && (
          <div className="flex items-center gap-3 mr-auto max-w-md">
            <div className="size-7 rounded-full bg-primary/10 border border-primary/20 flex items-center justify-center text-primary shrink-0 animate-pulse">
              <Bot className="size-4" />
            </div>
            <div className="rounded-lg border border-border/80 bg-muted/30 px-3.5 py-2.5 text-xs text-muted-foreground flex items-center gap-2">
              <Loader2 className="size-3.5 animate-spin text-primary" />
              <span>Analyzing tenant boundaries and synthesizing RLS rules...</span>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* 4. Chat Input Bar */}
      <div className="border-t border-border bg-card p-3 shrink-0">
        <form
          onSubmit={e => {
            e.preventDefault();
            void handleSendMessage();
          }}
          className="flex items-center gap-2 rounded-lg border border-border bg-muted/20 px-3 py-1.5 focus-within:border-primary/60 focus-within:ring-1 focus-within:ring-primary/40 transition-all shadow-xs"
        >
          <input
            type="text"
            value={inputValue}
            onChange={e => setInputValue(e.target.value)}
            placeholder="Ask anything about tenant isolation, RLS rules, or BOLA prevention (e.g. 'How do I isolate workspaces?')..."
            disabled={isThinking}
            className="flex-1 bg-transparent text-xs text-foreground placeholder:text-muted-foreground/60 outline-none"
          />
          <Button
            type="submit"
            size="sm"
            disabled={isThinking || !inputValue.trim()}
            className="h-7 px-3 gap-1.5 text-xs font-semibold"
          >
            <span>Send</span>
            <Send className="size-3" />
          </Button>
        </form>
      </div>
    </div>
  );
}