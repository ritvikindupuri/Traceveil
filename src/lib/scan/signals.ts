export type Signal = {
  id: string;
  label: string;
  severity: "critical" | "high" | "medium" | "low";
  file: string;
  line: number;
  excerpt: string;
};

const RULES: { id: string; label: string; severity: Signal["severity"]; re: RegExp }[] = [
  { id: "cred-scan", label: "Secret-scanning tooling", severity: "critical", re: /trufflehog|gitleaks/i },
  { id: "npm-token", label: "npm token access", severity: "critical", re: /NPM_TOKEN|\.npmrc|npm\s+(publish|token)|registry\.npmjs\.org\/-\/npm\/v1\/tokens/ },
  { id: "gh-token", label: "GitHub credential access", severity: "critical", re: /GITHUB_TOKEN|GH_TOKEN|ghp_[A-Za-z0-9]|api\.github\.com\/(user\/repos|repos\/[^"'`]+\/actions)|\.github\/workflows/ },
  { id: "cloud-creds", label: "Cloud credential harvesting", severity: "critical", re: /AWS_SECRET_ACCESS_KEY|169\.254\.169\.254|metadata\.google\.internal|GOOGLE_APPLICATION_CREDENTIALS|AZURE_CLIENT_SECRET|\.aws\/credentials/ },
  { id: "wallet", label: "Crypto wallet interception", severity: "high", re: /ethereum\.request|window\.ethereum|solana|bc1[a-z0-9]{20,}|0x[a-fA-F0-9]{40}/ },
  { id: "exfil", label: "Exfiltration endpoint", severity: "high", re: /webhook\.site|discord(app)?\.com\/api\/webhooks|pipedream|ngrok\.io|requestbin|oast\.|burpcollaborator|interact\.sh/i },
  { id: "proc", label: "Process spawning", severity: "medium", re: /child_process|execSync\(|spawnSync\(|Bun\.spawn/ },
  { id: "eval", label: "Dynamic code execution", severity: "high", re: /\beval\(|new Function\(|vm\.runIn/ },
  { id: "obf", label: "Obfuscation markers", severity: "high", re: /_0x[a-f0-9]{4,}|\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}|atob\(|Buffer\.from\([^)]{0,80}['"]base64['"]/i },
  { id: "env-dump", label: "Bulk environment read", severity: "medium", re: /JSON\.stringify\(process\.env\)|Object\.(keys|entries)\(process\.env\)/ },
  { id: "bun-runtime", label: "Runtime bootstrap download", severity: "high", re: /bun\.sh\/install|setup_bun|bun_environment/i },
  { id: "destructive", label: "Destructive filesystem ops", severity: "high", re: /rm\s+-rf\s+[~\/$]|shred\s|rimraf\(\s*['"`](~|\/)/ },
];

const CODE_EXT = /\.(c?js|mjs|ts|sh|py|json)$/i;

export function scanFile(path: string, text: string, limit = 40): Signal[] {
  if (!CODE_EXT.test(path)) return [];
  const lines = text.split("\n");
  const hits: Signal[] = [];
  for (let i = 0; i < lines.length && hits.length < limit; i++) {
    const line = lines[i];
    for (const r of RULES) {
      if (r.re.test(line)) {
        hits.push({
          id: r.id,
          label: r.label,
          severity: r.severity,
          file: path,
          line: i + 1,
          excerpt: line.trim().slice(0, 220),
        });
      }
    }
  }
  return hits;
}
