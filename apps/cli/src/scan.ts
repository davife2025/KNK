import { realpath, stat } from 'node:fs/promises';
import path from 'node:path';
import { labelFor, redact, SEVERITY_SCORE } from '@knk/detect';
import type { AnalyzeResponse, ArtifactKind, TrustState, VerdictLabel } from '@knk/shared';
import { ApiFailure, type KnkClient } from './client.js';
import { detect, MAX_CONTENT, type LocalFinding, type SecretHit } from './detectors.js';
import { CliError } from './errors.js';
import { walk } from './fsutil.js';
import { scanMachine, type MachineHit } from './machine.js';
import { safe } from './sanitize.js';

export interface ScanOptions {
  path: string;
  untrusted: boolean;
  offline: boolean;
  machine: boolean;
  reportTokens: boolean;
  maxSend?: number;
}
export interface ScanDeps {
  client: KnkClient | null;
  subject: string;
  home: string;
  platform: NodeJS.Platform;
}
export interface ArtifactResult {
  rel: string;
  kind: ArtifactKind;
  label: string;
  truncated: boolean;
  findings: LocalFinding[];
  sent: boolean;
  redactions: number;
  remote?: AnalyzeResponse;
  error?: string;
}
export interface ScanResult {
  root: string;
  files: number;
  walkTruncated: boolean;
  mode: 'online' | 'local';
  artifacts: ArtifactResult[];
  otherFindings: LocalFinding[];
  secrets: SecretHit[];
  machine: MachineHit[] | null;
  label: VerdictLabel;
  risk: number;
  trust?: TrustState;
  warnings: string[];
}

const DEFAULT_MAX_SEND = 12;
const CONCURRENCY = 3;

/** Two distinct serious signals anywhere in the repo add up to a malicious call, like inside a single artifact. */
function localRisk(all: LocalFinding[]): number {
  const max = all.reduce((m, f) => Math.max(m, SEVERITY_SCORE[f.severity]), 0);
  const serious = new Set(all.filter((f) => f.severity === 'high' || f.severity === 'critical').map((f) => f.id)).size;
  return serious >= 2 ? Math.max(max, 85) : max;
}

async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T, i: number) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (next < items.length) {
        const i = next++;
        out[i] = await fn(items[i]!, i);
      }
    }),
  );
  return out;
}

/**
 * Read-only. Nothing in the scanned directory is executed or modified. Only artifacts that run on their own, or that
 * already look suspicious, leave the machine, and only after redaction. Everything else stays local.
 */
export async function runScan(opts: ScanOptions, deps: ScanDeps): Promise<ScanResult> {
  const target = path.resolve(opts.path);
  let st;
  try {
    st = await stat(target);
  } catch {
    throw new CliError(`Not found: ${safe(opts.path)}`);
  }
  if (!st.isDirectory()) throw new CliError('The scan target must be a directory.');
  const root = await realpath(target);

  const w = await walk(root);
  const d = await detect(root, w);
  const client = deps.client && !opts.offline ? deps.client : null;
  const warnings: string[] = [];
  if (w.truncated) warnings.push('The repository is large: only the first 5,000 files were examined.');

  // Under a cap the most dangerous artifacts go first: highest severity, then most findings.
  const weight = (c: { findings: LocalFinding[] }) => c.findings.reduce((m, f) => Math.max(m, SEVERITY_SCORE[f.severity]), 0) * 100 + c.findings.length;
  const wanted = d.candidates.filter((c) => c.review === 'always' || c.findings.length > 0).sort((a, b) => weight(b) - weight(a));
  const toSend = client ? wanted.slice(0, opts.maxSend ?? DEFAULT_MAX_SEND) : [];
  if (client && wanted.length > toSend.length) warnings.push(`${wanted.length - toSend.length} artifact(s) were not sent for review (limit ${toSend.length}).`);

  const results = new Map<string, ArtifactResult>(
    d.candidates.map((c) => [c.rel, { rel: c.rel, kind: c.kind, label: c.label, truncated: c.truncated, findings: c.findings, sent: false, redactions: 0 }]),
  );

  if (client) {
    if (opts.untrusted) {
      await client.ingest([{ subject: deps.subject, kind: 'untrusted_repo_opened', attrs: { files: w.files.length }, }]).catch((e) => warnings.push(`Could not record the untrusted repo event: ${e instanceof Error ? safe(e.message) : 'error'}`));
    }
    let degraded = false;
    await mapLimit(toSend, CONCURRENCY, async (c) => {
      const res = results.get(c.rel)!;
      const { text, redactions } = redact(c.content); // redaction happens here, before anything is sent
      res.redactions = redactions.reduce((n, r) => n + r.count, 0);
      try {
        res.remote = await client.analyze(c.kind, text.slice(0, MAX_CONTENT), deps.subject);
        res.sent = true;
      } catch (e) {
        if (e instanceof ApiFailure && (e.status === 401 || e.status === 403)) {
          throw new CliError(`KNK rejected your API key (${e.code}). Run: knk init`);
        }
        res.error = e instanceof Error ? safe(e.message) : 'failed';
        degraded = true;
      }
    });
    if (degraded) warnings.push('Some artifacts could not be reviewed by KNK; those results come from local checks only.');
  }

  const machine = opts.machine ? await scanMachine(deps.home, deps.platform) : null;
  if (client && opts.reportTokens && machine && machine.length > 0) {
    await client
      .ingest([{ subject: deps.subject, kind: 'deploy_token_on_disk', attrs: { location: 'home', count: machine.length, types: [...new Set(machine.map((m) => m.type))].join(',') } }])
      .catch((e) => warnings.push(`Could not record the credential event: ${e instanceof Error ? safe(e.message) : 'error'}`));
  }

  const artifacts = [...results.values()];
  const allLocal = [...artifacts.flatMap((a) => a.findings), ...d.findings];
  const remoteRisk = artifacts.reduce((m, a) => Math.max(m, a.remote?.payload.riskScore ?? 0), 0);
  const risk = Math.max(localRisk(allLocal), remoteRisk);

  let trust: TrustState | undefined;
  if (client && artifacts.some((a) => a.sent)) trust = await client.trust(deps.subject).catch(() => undefined);

  return {
    root,
    files: w.files.length,
    walkTruncated: w.truncated,
    mode: client ? 'online' : 'local',
    artifacts,
    otherFindings: d.findings,
    secrets: d.secrets,
    machine,
    label: labelFor(risk),
    risk,
    trust,
    warnings,
  };
}
