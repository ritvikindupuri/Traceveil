import { useState } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  FileCode,
  ExternalLink,
  Copy,
  Check,
  Wrench,
  Search,
  Filter,
  ArrowRight,
  ChevronDown,
  ChevronUp,
  Sparkles,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import type { AttackGraph, Finding, Evidence } from '@/lib/atlas/types';
import { cn } from '@/lib/utils';

export function DetailedFindings({
  graph,
  onNavigateToRemediation,
}: {
  graph: AttackGraph;
  onNavigateToRemediation?: () => void;
}) {
  const [filterSeverity, setFilterSeverity] = useState<'all' | 'high' | 'medium' | 'low'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>(() => {
    // Expand the first 3 findings by default
    const initial: Record<string, boolean> = {};
    graph.findings.slice(0, 3).forEach(f => {
      initial[f.id] = true;
    });
    return initial;
  });
  const [copiedId, setCopiedId] = useState<string | null>(null);

  function toggleExpand(id: string) {
    setExpandedFindings(prev => ({
      ...prev,
      [id]: !prev[id],
    }));
  }

  function copyText(text: string, id: string) {
    void navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  }

  // Plain-English explanation generator for every rule
  function getRuleDetails(rule: string, title: string) {
    switch (rule) {
      case 'public-cidr':
        return {
          category: 'Network Ingress Exposure',
          summary:
            'A security group or infrastructure declaration allows unrestricted public network ingress (0.0.0.0/0).',
          explanation:
            'This configuration opens ports directly to the entire public internet without any IP allowlisting or firewall filtering. Automated botnets, crawlers, and adversary reconnaissance tools (e.g. Shodan) continuously probe these ranges to perform automated brute-force attacks and exploit unauthenticated services.',
          lineCallout: 'Line defines an unrestricted 0.0.0.0/0 IPv4 ingress range',
          recommendedFix:
            'Restrict this CIDR range to your internal corporate VPC subnet (e.g. 10.0.0.0/16) or corporate VPN IP.',
        };
      case 'mutable-action':
        return {
          category: 'CI/CD Supply Chain Poisoning',
          summary:
            'A GitHub Actions step references a mutable action tag or branch rather than an immutable commit SHA.',
          explanation:
            'Using mutable tags like @v3 or @main leaves your pipeline vulnerable to upstream supply chain attacks. If the third-party action repository or author account is compromised, attackers can push a malicious commit to that tag, which will automatically execute in your build runners with access to repository secrets.',
          lineCallout: 'Line references a mutable action tag instead of a 40-character commit SHA',
          recommendedFix:
            'Pin the action to an immutable 40-character commit SHA (e.g. actions/checkout@24cb9080177205b6e8c946b17badbe402dac938f).',
        };
      case 'workflow-write':
        return {
          category: 'Excessive Automation Privileges',
          summary:
            'The workflow grants write-all permissions to the ephemeral GITHUB_TOKEN.',
          explanation:
            'Granting permissions: write-all allows any script or dependency running inside this workflow to modify repository source code, create or delete release assets, publish packages, and alter security settings. If an adversary injects code into your build, they can push backdoored commits directly into protected branches.',
          lineCallout: 'Line requests unrestricted write-all scope for GITHUB_TOKEN',
          recommendedFix:
            'Enforce least-privilege by explicitly granting only the necessary scopes: contents: read, pull-requests: read.',
        };
      case 'privileged':
        return {
          category: 'Container Host Breakout Risk',
          summary:
            'Container is configured to run in privileged mode (privileged: true).',
          explanation:
            'Privileged containers disable Linux namespace isolation boundaries and grant the container process full capabilities (CAP_SYS_ADMIN) over the host node. An attacker executing code within the container can mount host disks, access raw memory, and take complete control of the Kubernetes host worker node.',
          lineCallout: 'Line declares privileged: true, disabling container kernel isolation',
          recommendedFix:
            'Set privileged: false, allowPrivilegeEscalation: false, and drop all Linux capabilities: drop: ["ALL"].',
        };
      case 'root-user':
        return {
          category: 'Container Privilege Escalation',
          summary:
            'Container workload declares root user execution (USER root / UID 0).',
          explanation:
            'Running containerized workloads as root means that any remote code execution or application vulnerability immediately provides the attacker with superuser capabilities within the container filesystem, making privilege escalation significantly easier.',
          lineCallout: 'Line specifies root execution (UID 0)',
          recommendedFix:
            'Create a dedicated unprivileged user in your Dockerfile (e.g. USER appuser) and run your process under an unprivileged UID.',
        };
      case 'credential-pattern':
        return {
          category: 'Committed Secrets & Token Exposure',
          summary:
            'A plaintext API key, access token, or private key was found in source code.',
          explanation:
            'Hardcoded credentials in Git history can be read by anyone with repository access. If the repository is public or cloned onto developer machines, attackers can extract and replay the token to access protected services and exfiltrate data.',
          lineCallout: 'Line contains an exposed secret pattern or plaintext token',
          recommendedFix:
            'Immediately revoke and rotate this secret, and migrate storage to environment variables or a secret vault.',
        };
            case 'missing-csp':
        return {
          category: 'Browser Defense & Script Injection Risk',
          summary: 'The live web application response does not declare a Content-Security-Policy (CSP) header.',
          explanation: 'Without a Content-Security-Policy, the browser permits execution of arbitrary inline scripts, unauthorized third-party CDN scripts, and unauthenticated data exfiltration via fetch/XHR. This allows Cross-Site Scripting (XSS) vulnerabilities to directly hijack user sessions and sensitive client data.',
          lineCallout: 'HTTP Response lacks Content-Security-Policy header',
          recommendedFix: "Define a strict Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'; in reverse proxy or web server configuration."
        };
      case 'missing-hsts':
        return {
          category: 'Transport Encryption & SSL Stripping Risk',
          summary: 'The live web application response lacks an HTTP Strict Transport Security (HSTS) header.',
          explanation: 'Without HSTS, browsers may initially connect via plaintext HTTP before being redirected to HTTPS. Adversaries on the local network (public Wi-Fi, coffee shops) can intercept and strip SSL certificates, capturing session cookies and login credentials in transit.',
          lineCallout: 'HTTP Response lacks Strict-Transport-Security header',
          recommendedFix: "Enforce HSTS by adding: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload to response headers."
        };
      case 'missing-frame-options':
        return {
          category: 'Clickjacking & Framing Vulnerability',
          summary: 'The application allows iframe framing from arbitrary third-party origins (missing X-Frame-Options).',
          explanation: 'Adversaries can embed your web application inside a transparent iframe on a malicious website, tricking users into clicking invisible buttons or authorizing transactions (UI redressing / clickjacking).',
          lineCallout: 'HTTP Response lacks X-Frame-Options or frame-ancestors directive',
          recommendedFix: "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' to all HTTP response headers."
        };
      case 'server-banner-leak':
        return {
          category: 'Information Disclosure & Technology Fingerprinting',
          summary: 'The web server leaks underlying software banners and cloud routing versions in HTTP headers.',
          explanation: 'Leaking headers such as Server, X-Powered-By, or routing metadata informs attackers of exact software stacks and hosting providers, allowing them to target known CVE vulnerabilities and cloud-specific misconfigurations.',
          lineCallout: 'HTTP Response header leaks internal web server or cloud provider identity',
          recommendedFix: "Configure reverse proxy (Nginx, Cloudflare, Caddy) to suppress Server and X-Powered-By response headers."
        };
      case 'exposed-env':
        return {
          category: 'Critical Credential Disclosure',
          summary: 'The web server serves raw environment configuration files (.env) over public HTTP.',
          explanation: 'Exposed .env files contain production database passwords, third-party API secret keys, and JWT signing keys. Attackers can immediately download these files to achieve full administrative takeover.',
          lineCallout: 'HTTP GET /.env returned 200 OK with exposed configuration variables',
          recommendedFix: "Block access to hidden files and dotfiles (.env, .git) in web server configuration immediately and rotate all exposed secrets."
        };
      default:
        return {
          category: 'Security Risk Condition',
          summary: title,
          explanation:
            'This finding was identified from static inspection of your repository files. Review the code excerpt below to evaluate threat exposure.',
          lineCallout: 'Flagged configuration line in repository',
          recommendedFix: 'Review and apply least-privilege security configurations.',
        };
    }
  }

  // Filtered findings
  const filtered = graph.findings.filter(f => {
    const matchesSev = filterSeverity === 'all' || f.severity === filterSeverity;
    const matchesSearch =
      searchQuery === '' ||
      f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.rule.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSev && matchesSearch;
  });

  return (
    <div className="space-y-6">
      {/* Header with Title and Filters */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-4">
        <div>
          <h2 className="text-lg font-semibold text-foreground">Evidence-Backed Security Findings</h2>
          <p className="mt-1 text-xs text-muted-foreground">
            Detailed breakdown of all detected attack surfaces, vulnerable source lines, and remediation guides.
          </p>
        </div>

        {/* Filter Pills */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 size-3.5 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search findings..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="h-8 w-44 rounded-md border border-input bg-background pl-8 pr-3 text-xs outline-none focus:ring-1 focus:ring-ring"
            />
          </div>

          <div className="flex items-center gap-1 rounded-md border border-border bg-card p-1">
            <button
              onClick={() => setFilterSeverity('all')}
              className={cn(
                'rounded px-2.5 py-1 text-xs font-medium transition-colors',
                filterSeverity === 'all' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground'
              )}
            >
              All ({graph.findings.length})
            </button>
            <button
              onClick={() => setFilterSeverity('high')}
              className={cn(
                'rounded px-2.5 py-1 text-xs font-medium transition-colors',
                filterSeverity === 'high' ? 'bg-destructive text-destructive-foreground' : 'text-muted-foreground hover:text-foreground'
              )}
            >
              High ({graph.findings.filter(f => f.severity === 'high').length})
            </button>
            <button
              onClick={() => setFilterSeverity('medium')}
              className={cn(
                'rounded px-2.5 py-1 text-xs font-medium transition-colors',
                filterSeverity === 'medium' ? 'bg-warning/20 text-warning font-semibold' : 'text-muted-foreground hover:text-foreground'
              )}
            >
              Medium ({graph.findings.filter(f => f.severity === 'medium').length})
            </button>
          </div>
        </div>
      </div>

      {/* Findings List */}
      {filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-border p-12 text-center">
          <ShieldAlert className="size-8 text-muted-foreground" />
          <h3 className="mt-3 text-sm font-medium">No Matching Findings</h3>
          <p className="mt-1 text-xs text-muted-foreground">Try clearing your search query or severity filters.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {filtered.map(finding => {
            const isExpanded = Boolean(expandedFindings[finding.id]);
            const details = getRuleDetails(finding.rule, finding.title);
            const matchedEvidence = graph.evidence.filter(e => finding.evidenceIds.includes(e.id));
            const isHigh = finding.severity === 'high';

            return (
              <div
                key={finding.id}
                className={cn(
                  'rounded-lg border transition-all bg-card shadow-xs overflow-hidden',
                  isExpanded ? 'border-border' : 'border-border/70 hover:border-border'
                )}
              >
                {/* Accordion Summary Header */}
                <div
                  onClick={() => toggleExpand(finding.id)}
                  className="flex cursor-pointer items-center justify-between gap-3 p-4 transition-colors hover:bg-muted/20 select-none"
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <span
                      className={cn(
                        'size-2.5 rounded-full shrink-0',
                        isHigh ? 'bg-destructive animate-pulse' : 'bg-warning'
                      )}
                    />
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <h3 className="text-sm font-semibold text-foreground truncate">{finding.title}</h3>
                        <span
                          className={cn(
                            'rounded px-2 py-0.5 font-mono text-[9px] font-bold uppercase tracking-wider',
                            isHigh
                              ? 'bg-destructive/15 text-destructive border border-destructive/30'
                              : 'bg-warning/15 text-warning border border-warning/30'
                          )}
                        >
                          {finding.severity}
                        </span>
                        <span className="rounded bg-muted px-2 py-0.5 font-mono text-[9px] text-muted-foreground">
                          {details.category}
                        </span>
                      </div>
                      <p className="mt-1 text-xs text-muted-foreground truncate">{finding.fix}</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    <span className="font-mono text-[10px] text-muted-foreground hidden sm:inline">
                      {matchedEvidence.length} source file{matchedEvidence.length !== 1 ? 's' : ''}
                    </span>
                    <button className="text-muted-foreground hover:text-foreground">
                      {isExpanded ? <ChevronUp className="size-4" /> : <ChevronDown className="size-4" />}
                    </button>
                  </div>
                </div>

                {/* Expanded Detailed Content */}
                {isExpanded && (
                  <div className="border-t border-border/80 p-5 space-y-5 bg-background/50">
                    {/* Plain-English Threat Breakdown */}
                    <div className="rounded-lg border border-border/80 bg-card p-4 space-y-2">
                      <div className="flex items-center gap-2 text-xs font-semibold text-foreground">
                        <AlertTriangle className={cn('size-4', isHigh ? 'text-destructive' : 'text-warning')} />
                        <span>Security Risk & Threat Explanation</span>
                      </div>
                      <p className="text-xs leading-relaxed text-muted-foreground">
                        {details.explanation}
                      </p>
                    </div>

                    {/* Source Code Evidence with Highlighted Line */}
                    <div className="space-y-3">
                      <span className="text-xs font-semibold text-foreground flex items-center gap-2">
                        <FileCode className="size-4 text-primary" />
                        <span>Vulnerable Source Code Location</span>
                      </span>

                      {matchedEvidence.map(ev => {
                        return (
                          <div key={ev.id} className="rounded-lg border border-border overflow-hidden bg-card">
                            {/* File Bar */}
                            <div className="flex items-center justify-between gap-2 border-b border-border/80 bg-muted/40 px-3.5 py-2 text-xs">
                              <a
                                href={ev.url}
                                target="_blank"
                                rel="noreferrer"
                                className="flex items-center gap-1.5 font-mono text-xs text-primary hover:underline truncate font-medium"
                                title={ev.path}
                              >
                                <span className="truncate">{ev.path}</span>
                                <span className="text-muted-foreground shrink-0 font-bold">:{ev.line}</span>
                                <ExternalLink className="size-3 shrink-0 ml-1 opacity-70" />
                              </a>

                              <button
                                onClick={() => copyText(ev.path, `path-${ev.id}`)}
                                className="flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground rounded p-1"
                                title="Copy Path"
                              >
                                {copiedId === `path-${ev.id}` ? <Check className="size-3 text-primary" /> : <Copy className="size-3" />}
                                <span>{copiedId === `path-${ev.id}` ? 'Copied' : 'Copy'}</span>
                              </button>
                            </div>

                            {/* Highlighted Code Snippet with Line Gutter */}
                            <div className="rounded-b-lg border-t border-border bg-muted/20 p-4 font-mono text-xs text-foreground">
                              <div className="flex items-start gap-3">
                                {/* Line Number Gutter */}
                                <div className="select-none text-right font-mono text-muted-foreground text-xs pr-2 border-r border-border">
                                  <div>{Math.max(1, ev.line - 1)}</div>
                                  <div className="font-bold text-destructive bg-destructive/15 px-1 rounded-xs">{ev.line}</div>
                                  <div>{ev.line + 1}</div>
                                </div>

                                {/* Code Line with Highlight Callout */}
                                <div className="flex-1 overflow-x-auto">
                                  <div className="text-muted-foreground text-[11px] select-none italic mb-1">
                                    # ... preceding context
                                  </div>
                                  <div className="bg-destructive/10 border border-destructive/30 rounded px-2.5 py-1 text-destructive font-semibold shadow-2xs whitespace-pre">
                                    {ev.excerpt}
                                  </div>
                                  <div className="mt-1.5 flex items-center gap-1.5 text-[11px] text-destructive">
                                    <span>↳</span>
                                    <span className="font-sans font-medium">{details.lineCallout}</span>
                                  </div>
                                </div>
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>

                    {/* How to Fix / Action Call */}
                    <div className="flex flex-wrap items-center justify-between gap-4 rounded-lg border border-primary/30 bg-primary/5 p-4">
                      <div>
                        <div className="flex items-center gap-2 text-xs font-semibold text-foreground">
                          <Wrench className="size-3.5 text-primary" />
                          <span>Recommended Remediation</span>
                        </div>
                        <p className="mt-1 text-xs text-muted-foreground">{details.recommendedFix}</p>
                      </div>

                      {onNavigateToRemediation && (
                        <Button
                          size="sm"
                          onClick={onNavigateToRemediation}
                          className="gap-2 text-xs shrink-0"
                        >
                          <Sparkles className="size-3.5" />
                          <span>View Code Diff in Remediation Studio</span>
                          <ArrowRight className="size-3" />
                        </Button>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
