import { useState } from 'react';
import { Network, Crosshair, X, Info } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Tooltip, TooltipTrigger, TooltipContent, TooltipProvider } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import { categoryEvidence, toolEvidence, referenceTargets, severityLevel } from '@/lib/scan/visual-evidence';
import type { Inventory, Signal, Verdict } from '@/lib/scan/types';

const levelTone = (level: number) => level >= 4 ? 'text-destructive' : level >= 3 ? 'text-warning' : level > 0 ? 'text-chart-4' : 'text-muted-foreground';
const levels = ['No matches', 'Low', 'Medium', 'High', 'Critical'];

export function AuditVisuals({ inventory, signals, verdict }: { inventory: Inventory; signals: Signal[]; verdict: Verdict | null }) {
  const [selected, setSelected] = useState<string | null>(null);
  const [category, setCategory] = useState<string | null>(null);
  const tools = toolEvidence(inventory, signals);
  const rows = tools.length ? tools : [{ name: 'Transcript', signals }];
  const targets = referenceTargets.filter(t => signals.some(s => t.rules.includes(s.rule)));
  const height = Math.max(260, rows.length * 58 + 70);
  const focused = rows.find(t => t.name === selected);
  const categories = categoryEvidence(signals);
  const activeCategory = categories.find(c => c.name === category);
  const evidence = activeCategory?.matches ?? focused?.signals ?? [];
  return (
    <section className="border-y border-border" aria-label="Audit threat visualizations">
      <div className="grid min-w-0 xl:grid-cols-[1fr_280px]">
        <div className="min-w-0 xl:border-r xl:border-border">
          <div className="flex flex-wrap items-center justify-between gap-2 py-3 xl:pr-4">
            <h2 className="flex items-center gap-2 text-xs font-medium"><Network className="size-4 text-primary" />Attack topology</h2>
            <span className="font-mono text-[10px] text-muted-foreground">INFERRED REFERENCES · {tools.length} TOOLS</span>
          </div>
          <div className="max-h-[420px] overflow-auto overscroll-contain">
            <svg viewBox={`0 0 640 ${height}`} className="w-full min-w-[480px]" role="group" aria-label="Tool attack topology">
              <text x="20" y="18" className="fill-muted-foreground font-mono text-[10px]">SOURCE</text>
              <text x="252" y="18" className="fill-muted-foreground font-mono text-[10px]">TOOLS</text>
              <text x="478" y="18" className="fill-muted-foreground font-mono text-[10px]">REFERENCED TARGETS</text>
              {rows.map((tool, i) => {
                const y = 55 + i * 58;
                const level = Math.max(0, ...tool.signals.map(s => severityLevel[s.severity]));
                const dimmed = selected !== null && selected !== tool.name;
                return <g key={tool.name} opacity={dimmed ? 0.22 : 1}>
                  <path d={`M155 ${height / 2} C205 ${height / 2},205 ${y},250 ${y}`} className={cn('fill-none stroke-current', levelTone(level))} strokeWidth={selected === tool.name ? 2 : 1} opacity="0.5" />
                  {targets.map((target, ti) => {
                    const matching = tool.signals.filter(s => target.rules.includes(s.rule));
                    if (!matching.length) return null;
                    const ty = height / 2 + (ti - (targets.length - 1) / 2) * 65;
                    return <path key={target.name} d={`M415 ${y} C448 ${y},448 ${ty},480 ${ty}`} className={cn('fill-none stroke-current', levelTone(Math.max(...matching.map(s => severityLevel[s.severity]))))} strokeWidth="1.8" strokeDasharray="5 4"><title>{matching.map(s => `${s.label}: ${s.target}`).join('\n')}</title></path>;
                  })}
                  <circle cx="246" cy={y} r="3" className={cn('fill-current', levelTone(level))} />
                  <foreignObject x="252" y={y-18} width="163" height="36">
                    <Button variant="ghost" size="sm" className={cn('h-9 w-full justify-start overflow-hidden rounded border border-border bg-card px-2 font-mono text-[11px]', selected === tool.name && 'border-primary bg-accent')} title={tool.name} aria-pressed={selected === tool.name} onClick={() => { setCategory(null); setSelected(selected === tool.name ? null : tool.name); }}>
                      <span className="truncate">{tool.name}</span><span className={cn('ml-auto', levelTone(level))}>{tool.signals.length}</span>
                    </Button>
                  </foreignObject>
                </g>;
              })}
              <rect x="15" y={height/2-27} width="140" height="54" rx="4" className="fill-secondary stroke-primary" strokeOpacity="0.6" />
              <text x="28" y={height/2-4} className="fill-primary font-mono text-[10px]">{inventory.mode === 'transcript' ? 'AGENT SESSION' : 'MCP SERVER'}</text>
              <text x="28" y={height/2+14} className="fill-foreground font-mono text-[11px]"><title>{inventory.server ?? inventory.source}</title>{(inventory.server ?? inventory.source).slice(0,18)}</text>
              {targets.map((target, i) => {
                const y = height / 2 + (i - (targets.length - 1)/2)*65;
                return <g key={target.name}><rect x="480" y={y-20} width="152" height="40" rx="4" className="fill-card stroke-border" /><circle cx="492" cy={y} r="3" className="fill-warning" /><text x="502" y={y+4} className="fill-foreground font-mono text-[10px]">{target.name}</text></g>;
              })}
              {!targets.length && <text x="480" y={height/2} className="fill-muted-foreground font-mono text-[10px]">No target references</text>}
            </svg>
          </div>
          <div className="flex gap-4 py-3 font-mono text-[10px] text-muted-foreground"><span className="flex items-center gap-1.5"><i className="h-px w-4 bg-muted-foreground" />Inventory</span><span className="flex items-center gap-1.5"><i className="h-px w-4 bg-warning" />High</span><span className="flex items-center gap-1.5"><i className="h-px w-4 bg-destructive" />Critical</span></div>
        </div>
        <div className="border-t border-border py-3 xl:border-t-0 xl:pl-4">
          <h2 className="mb-4 flex items-center justify-between text-xs font-medium"><span className="flex items-center gap-2"><Crosshair className="size-4 text-primary" />Threat dimensions</span><span className="font-mono text-[10px] text-muted-foreground">STATIC</span></h2>
          <div className="grid grid-cols-2 gap-x-4 gap-y-5 xl:grid-cols-1 xl:gap-y-3">
            {categories.map(c => <Button key={c.name} variant="ghost" aria-pressed={category === c.name} onClick={() => {setSelected(null); setCategory(category === c.name ? null : c.name);}} className="block h-auto min-w-0 rounded p-1 text-left">
              <span className="flex flex-wrap justify-between gap-1 text-[11px]"><span>{c.name}</span><span className={cn('font-mono text-[10px]', levelTone(c.level))}>{levels[c.level]}</span></span>
              <span className="mt-2 grid grid-cols-4 gap-1">{[1,2,3,4].map(n => <span key={n} className={cn('h-1.5 rounded-sm', n <= c.level ? c.level >= 4 ? 'bg-destructive' : c.level >= 3 ? 'bg-warning' : 'bg-chart-4' : 'bg-secondary')} />)}</span>
              <span className="mt-1 block font-mono text-[9px] text-muted-foreground">{c.matches.length} rule matches</span>
            </Button>)}
          </div>
          {verdict && (
            <TooltipProvider delayDuration={100}>
              <Tooltip>
                <TooltipTrigger asChild>
                  <div className="mt-5 flex cursor-help items-center gap-3 border-t border-border pt-3 rounded-md p-1.5 hover:bg-muted/40 transition">
                    <svg viewBox="0 0 64 64" className="size-14 shrink-0" aria-label={`Model risk assessment ${verdict.risk} out of 100`}>
                      <circle cx="32" cy="32" r="27" className="fill-none stroke-secondary" strokeWidth="4" />
                      <circle cx="32" cy="32" r="27" pathLength="100" strokeDasharray={`${Math.max(0, Math.min(100,verdict.risk))} 100`} transform="rotate(-90 32 32)" className={cn('fill-none stroke-current', verdict.risk >= 70 ? 'text-destructive' : verdict.risk >= 40 ? 'text-warning' : 'text-primary')} strokeWidth="4" />
                      <text x="32" y="37" textAnchor="middle" className="fill-foreground font-mono text-[16px]">{verdict.risk}</text>
                    </svg>
                    <div>
                      <div className="flex items-center gap-1.5 text-[11px] font-medium">
                        <span>Model risk assessment</span>
                        <Info className="size-3 text-muted-foreground" />
                      </div>
                      <div className="mt-1 font-mono text-[10px] text-muted-foreground">{verdict.verdict.toUpperCase()} · {verdict.risk}/100</div>
                    </div>
                  </div>
                </TooltipTrigger>
                <TooltipContent side="top" className="max-w-xs space-y-2 p-3 text-xs bg-popover text-popover-foreground border border-border shadow-xl">
                  <div className="font-semibold text-foreground flex items-center justify-between border-b border-border pb-1">
                    <span>How This Score is Calculated</span>
                    <span className={cn('font-mono text-[10px] uppercase font-bold', verdict.verdict === 'block' ? 'text-destructive' : verdict.verdict === 'review' ? 'text-warning' : 'text-primary')}>{verdict.verdict} ({verdict.risk}/100)</span>
                  </div>
                  <p className="text-[11px] text-muted-foreground leading-relaxed">
                    The 0–100 risk score evaluates the probability and blast radius of prompt injection, parameter escalation, or data exfiltration:
                  </p>
                  <div className="space-y-1 text-[10px] font-mono bg-muted/30 p-2 rounded border border-border/50">
                    <div>• <strong className="text-destructive">+40 pts:</strong> Critical threats (credential exfiltration, arbitrary command execution)</div>
                    <div>• <strong className="text-warning">+20 pts:</strong> High risk findings (unscoped SSRF, path traversal)</div>
                    <div>• <strong className="text-foreground">+10 pts:</strong> Base exposure for static pattern triggers</div>
                  </div>
                  <div className="pt-1 text-[10px] border-t border-border/60 text-muted-foreground flex justify-between">
                    <span><strong>0–39:</strong> Allow</span>
                    <span><strong>40–69:</strong> Review</span>
                    <span><strong>70–100:</strong> Block</span>
                  </div>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          )}
        </div>
      </div>
      {(focused || activeCategory) && <div className="border-t border-border py-3">
        <div className="mb-2 flex items-center justify-between"><h3 className="font-mono text-xs break-all">{category ?? selected}</h3><Button variant="ghost" size="icon" className="size-6" aria-label="Clear selection" onClick={() => {setSelected(null); setCategory(null);}}><X /></Button></div>
        <ul className="max-h-44 space-y-2 overflow-auto">{evidence.map((s,i) => <li key={i} className="text-xs"><span className={cn('mr-2 font-mono text-[10px] uppercase', levelTone(severityLevel[s.severity]))}>{s.severity}</span>{s.label}<div className="mt-1 break-all font-mono text-[10px] text-muted-foreground">{s.target} · {s.excerpt}</div></li>)}</ul>
        {!evidence.length && <p className="text-xs text-muted-foreground">No static matches.</p>}
      </div>}
    </section>
  );
}