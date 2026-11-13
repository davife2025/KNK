import type { ArtifactKind, Finding, Severity } from '@knk/shared';

interface Rule {
  id: string;
  title: string;
  detail: string;
  severity: Severity;
  patterns: RegExp[];
  kinds?: ArtifactKind[];
}

export const SEVERITY_SCORE: Record<Severity, number> = { info: 5, low: 20, medium: 45, high: 70, critical: 90 };

// Deterministic signals. They set a floor under the risk score that a model can raise but never lower,
// so text inside an artifact cannot talk the analyser into calling it safe.
const RULES: Rule[] = [
  {
    id: 'static.pipe_to_shell',
    title: 'Downloads and runs code in one step',
    detail: 'A remote script is piped straight into a shell, so nothing is reviewed before it runs.',
    severity: 'high',
    patterns: [/\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b/i],
  },
  {
    id: 'static.encoded_exec',
    title: 'Decodes and executes hidden content',
    detail: 'Base64 or similar content is decoded and then executed, a common way to hide a payload.',
    severity: 'high',
    patterns: [/base64\s+(?:-d|--decode)[^\n]*\|\s*(?:ba)?sh\b/i, /\b(?:eval|exec|Function)\s*\([^\n]*(?:atob|base64)/i],
  },
  {
    id: 'static.powershell_encoded',
    title: 'Runs an encoded PowerShell command',
    detail: 'An encoded PowerShell command hides what it will do.',
    severity: 'high',
    patterns: [/powershell[^\n]*\s-enc(?:odedcommand)?\b/i],
  },
  {
    id: 'static.credential_files',
    title: 'Touches credential files',
    detail: 'References SSH keys, cloud credentials or package-manager tokens, which an installer or test repo should not need.',
    severity: 'high',
    patterns: [/(?:\.ssh\/|\bid_rsa\b|\bid_ed25519\b|\.aws\/credentials|\.git-credentials|\.netrc\b|\.npmrc\b)/i],
  },
  {
    id: 'static.wallet_files',
    title: 'Touches wallet or keystore files',
    detail: 'References wallet files, keystores or browser extension storage.',
    severity: 'high',
    patterns: [/(?:\.near-credentials|wallet\.dat|\.ethereum\/keystore|\.config\/solana\/id\.json|Local Extension Settings)/i],
  },
  {
    id: 'static.env_exfiltration',
    title: 'Sends environment data over the network',
    detail: 'Reads environment variables and sends them to a remote address in the same statement.',
    severity: 'high',
    patterns: [/(?:process\.env|\bprintenv\b|\benv\b\s*\|)[^\n]{0,160}(?:https?:\/\/|\bcurl\b|\bfetch\(|axios|XMLHttpRequest)/i],
  },
  {
    id: 'static.install_lifecycle',
    title: 'Runs code automatically on install',
    detail: 'A lifecycle script (preinstall, install, postinstall or prepare) executes when the package is installed.',
    severity: 'medium',
    kinds: ['repo_manifest', 'install_script'],
    patterns: [/"(?:preinstall|install|postinstall|prepare)"\s*:\s*"[^"]+"/],
  },
  {
    id: 'static.process_spawn',
    title: 'Spawns system processes',
    detail: 'Uses child_process or similar to run commands on the machine.',
    severity: 'medium',
    patterns: [/require\(\s*['"](?:node:)?child_process['"]\s*\)/, /from\s+['"](?:node:)?child_process['"]/, /\b(?:execSync|spawnSync)\s*\(/],
  },
  {
    id: 'static.dynamic_eval',
    title: 'Evaluates code built at runtime',
    detail: 'eval or new Function can run code that is assembled or fetched at runtime.',
    severity: 'medium',
    patterns: [/\beval\s*\(/, /\bnew\s+Function\s*\(/],
  },
  {
    id: 'static.remote_binary',
    title: 'References a remote executable or script',
    detail: 'Points at a downloadable script or binary on a remote host.',
    severity: 'medium',
    patterns: [/https?:\/\/[^\s'"]+\.(?:sh|exe|bin|ps1|msi)\b/i],
  },
  {
    id: 'static.obfuscation',
    title: 'Contains obfuscated strings',
    detail: 'Long escaped or character-code sequences are used to hide text from a reader.',
    severity: 'medium',
    patterns: [/(?:\\x[0-9a-f]{2}){20,}/i, /String\.fromCharCode\((?:\s*\d+\s*,){15,}/],
  },
  {
    id: 'static.ai_tool_overreach',
    title: 'AI tool runs with broad or automatic permissions',
    detail: 'The configuration skips approval prompts or hands an AI tool a raw shell.',
    severity: 'high',
    kinds: ['ai_tool_config'],
    patterns: [/--dangerously-skip-permissions/, /"(?:autoApprove|alwaysAllow)"\s*:\s*(?:true|\[)/, /"command"\s*:\s*"(?:ba|z)?sh"/],
  },
];

export interface StaticResult {
  findings: Finding[];
  floor: number;
}

export function runStaticAnalysis(kind: ArtifactKind, content: string): StaticResult {
  const lines = content.split('\n');
  const findings: Finding[] = [];
  for (const rule of RULES) {
    if (rule.kinds && !rule.kinds.includes(kind)) continue;
    const idx = lines.findIndex((l) => rule.patterns.some((p) => p.test(l)));
    if (idx >= 0) {
      findings.push({ id: rule.id, title: rule.title, detail: rule.detail, severity: rule.severity, source: 'static', line: idx + 1 });
    }
  }
  let floor = findings.reduce((m, f) => Math.max(m, SEVERITY_SCORE[f.severity]), 0);
  const serious = findings.filter((f) => f.severity === 'high' || f.severity === 'critical').length;
  if (serious >= 2) floor = Math.max(floor, 85); // weak signals add up
  return { findings, floor };
}
