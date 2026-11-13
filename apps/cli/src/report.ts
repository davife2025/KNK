import type { GateDecisionView, TrustState } from '@knk/shared';
import type { ScanResult } from './scan.js';
import { safe } from './sanitize.js';

const CODES = { g: 32, y: 33, r: 31, d: 2, b: 1 } as const;
const paint = (on: boolean) => (c: keyof typeof CODES, s: string) => (on ? `\u001b[${CODES[c]}m${s}\u001b[0m` : s);
const where = (rel: string, line?: number) => `${safe(rel, 120)}${line ? `:${line}` : ''}`;

export function renderScan(r: ScanResult, color: boolean): string {
  const p = paint(color);
  const out: string[] = [];
  const sent = r.artifacts.filter((a) => a.sent);
  const redacted = r.artifacts.reduce((n, a) => n + a.redactions, 0);

  out.push(`${p('b', 'KNK scan')}  ${safe(r.root, 160)}`);
  out.push(
    r.mode === 'online'
      ? `${p('d', `online: ${sent.length} artifact(s) reviewed by KNK, ${redacted} secret(s) redacted before sending`)}`
      : `${p('d', 'local only: nothing left this machine')}`,
  );
  out.push('');

  for (const a of r.artifacts) {
    for (const f of a.findings) out.push(`${p('y', '[!]')} ${safe(f.title)}  ${f.severity}  ${where(a.rel, f.line)}`);
    for (const f of a.remote?.payload.findings.filter((x) => x.source === 'model') ?? []) out.push(`${p('y', '[!]')} ${safe(f.title)}  ${f.severity}  (model) ${where(a.rel)}`);
    if (a.remote) {
      const v = a.remote.payload;
      out.push(`    ${safe(a.label)} -> ${v.verdict}, risk ${v.riskScore}, ${v.mode === 'static+model' ? 'model-assisted' : 'static checks only'}, signed ${v.id.slice(0, 8)}`);
    } else if (a.error) {
      out.push(`    ${safe(a.label)} -> not reviewed (${safe(a.error)})`);
    }
  }
  for (const f of r.otherFindings) {
    const sev = f.severity === 'low' ? p('d', '[i]') : p('y', '[!]');
    out.push(`${sev} ${safe(f.title)}  ${f.severity}  ${where(f.rel)}${f.detail ? `  (${safe(f.detail, 80)})` : ''}`);
  }
  for (const s of r.secrets) out.push(`${p('d', '[i]')} ${where(s.rel)}: ${s.count} secret(s) (${s.types.join(', ')}). Contents were not read out or sent.`);
  if (r.machine) {
    out.push('');
    out.push(p('b', 'Credential files on this machine (names only, contents never read out)'));
    if (r.machine.length === 0) out.push('  none found');
    for (const m of r.machine) out.push(`  ${m.type.padEnd(18)} ${safe(m.display)}${m.loose ? p('y', '  readable by other users') : ''}`);
  }

  out.push('');
  const tag = r.label === 'malicious' ? p('r', '[x]') : r.label === 'suspicious' ? p('y', '[!]') : p('g', '[ok]');
  out.push(`${tag} ${r.label} · risk ${r.risk}${sent.length ? ' · signed' : ''}`);
  if (r.label === 'benign') out.push(p('d', '    No known-bad patterns found. This is not proof the code is safe.'));
  if (r.trust && r.trust.level !== 'normal') out.push(`    ${safe(r.trust.subject)} is now ${r.trust.level.toUpperCase()} (risk ${r.trust.risk})`);
  for (const w of r.warnings) out.push(p('d', `    note: ${safe(w, 240)}`));
  out.push(p('d', `Nothing was executed or modified. ${r.files} file(s) examined.`));
  return out.join('\n');
}

export function renderGate(v: GateDecisionView, color: boolean): string {
  const p = paint(color);
  const d = v.payload;
  const out: string[] = [];
  if (d.decision === 'allow') out.push(`${p('g', '[ok]')} ALLOW  sign within 5 minutes, then confirm`);
  else if (d.decision === 'hold') out.push(`${p('y', '[hold]')} HOLD  needs ${d.approvalsRequired} approval(s)${d.releaseAt ? ` and a timelock until ${safe(d.releaseAt)}` : ''}`);
  else out.push(`${p('r', '[x]')} BLOCK  do not sign`);
  for (const r of v.reasons) out.push(`    - ${safe(r.reason, 240)}`);
  out.push(p('d', `    decision ${d.id}  ·  ${d.kind}  ·  trust ${d.trustLevel} (risk ${d.trustRisk})`));
  return out.join('\n');
}

export function renderStatus(o: { workspace: string; subject: string; scopes: string[]; trust: TrustState }, color: boolean): string {
  const p = paint(color);
  const lines = [
    `${p('g', '[ok]')} workspace “${safe(o.workspace)}”`,
    `    subject  ${safe(o.subject)}`,
    `    scopes   ${o.scopes.join(', ')}`,
    `    trust    ${o.trust.level} (risk ${o.trust.risk})`,
  ];
  for (const r of o.trust.reasons) lines.push(`    - ${safe(r, 240)}`);
  return lines.join('\n');
}
