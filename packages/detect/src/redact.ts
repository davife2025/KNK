export interface Redaction {
  type: string;
  count: number;
}

interface Rule {
  type: string;
  re: RegExp;
  sub?: (m: RegExpExecArray | string[]) => string;
}

// Heuristic, defence in depth: the KNK CLI redacts on the developer machine before anything is sent.
// A 64-hex string is NOT redacted on its own (transaction hashes look identical); only labelled ones.
const RULES: Rule[] = [
  { type: 'private_key_block', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
  { type: 'aws_access_key', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { type: 'github_token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/g },
  { type: 'huggingface_token', re: /\bhf_[A-Za-z0-9]{30,}\b/g },
  { type: 'slack_token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { type: 'knk_api_key', re: /\bknk_[0-9a-f]{8}_[A-Za-z0-9_-]{43}\b/g },
  { type: 'jwt', re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g },
  // NEAR secret keys are 64 bytes (~88 base58 chars); public keys are shorter and left alone.
  { type: 'near_secret_key', re: /\bed25519:[1-9A-HJ-NP-Za-km-z]{80,90}\b/g },
  { type: 'bearer_token', re: /\b(Bearer)\s+(?!\[REDACTED)[A-Za-z0-9._~+/=-]{20,}/g, sub: (m) => `${m[1]} [REDACTED:bearer_token]` },
  {
    type: 'seed_phrase',
    re: /\b(mnemonic|seed[ _-]?phrase)(\s*[:=]\s*)(["'])[^"'\n]{20,}\3/gi,
    sub: (m) => `${m[1]}${m[2]}[REDACTED:seed_phrase]`,
  },
  {
    type: 'secret_assignment',
    re: /\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY)[A-Z0-9_]*)(\s*[:=]\s*)(["']?)(?!\[REDACTED)[^\s"']{6,}\3/gi,
    sub: (m) => `${m[1]}${m[2]}[REDACTED:secret_assignment]`,
  },
];

export function redact(input: string): { text: string; redactions: Redaction[] } {
  let text = input;
  const redactions: Redaction[] = [];
  for (const rule of RULES) {
    let count = 0;
    text = text.replace(rule.re, (...args) => {
      count += 1;
      return rule.sub ? rule.sub(args as unknown as string[]) : `[REDACTED:${rule.type}]`;
    });
    if (count > 0) redactions.push({ type: rule.type, count });
  }
  return { text, redactions };
}
