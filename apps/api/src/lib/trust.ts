import { EVENT_STAGE, type EventAttrs, type EventKind, type Stage, type TrustLevel, type TrustState } from '@knk/shared';

export interface TrustEvent {
  id: string;
  subject: string;
  kind: EventKind;
  attrs: EventAttrs;
  occurredAt: string;
}

export const TRUST_CONFIG = {
  windowDays: 14,
  halfLifeHours: 72, // a signal loses half its weight every 3 days
  chainBonus: { 2: 10, 3: 25 } as Record<number, number>, // weak signals in kill-chain order add up
  thresholds: { watch: 25, elevated: 50, critical: 75 },
  futureSkewMs: 5 * 60_000,
};
export type TrustConfig = typeof TRUST_CONFIG;

const CREDENTIAL_WEIGHT: Record<string, number> = { wallet: 35, deploy_token: 35, ssh: 30, cloud: 30, browser: 25 };

/** Base weight of one event, before time decay. Tunable: these are judgement calls, not measurements. */
export function eventWeight(e: Pick<TrustEvent, 'kind' | 'attrs'>): number {
  switch (e.kind) {
    case 'untrusted_repo_opened':
      return 15;
    case 'install_script_executed':
      return 10;
    case 'unverified_installer_used':
      return 25;
    case 'artifact_verdict':
      return e.attrs.verdict === 'malicious' ? 55 : e.attrs.verdict === 'suspicious' ? 25 : 0;
    case 'credential_read':
      return CREDENTIAL_WEIGHT[String(e.attrs.target)] ?? 20;
    case 'deploy_token_on_disk':
      return 15;
    case 'ai_tool_permission_change':
      return 20;
    case 'ai_tool_cross_host_action':
      return 35;
    case 'signing_request':
      return 0; // neutral by itself; the gate (Session 5) reads the trust state when one arrives
  }
}

export const levelFor = (risk: number, t = TRUST_CONFIG.thresholds): TrustLevel =>
  risk >= t.critical ? 'critical' : risk >= t.elevated ? 'elevated' : risk >= t.watch ? 'watch' : 'normal';

const RANK: Partial<Record<Stage, number>> = { initial_access: 1, credential_access: 2, privilege_escalation: 3 };

function describe(e: Pick<TrustEvent, 'kind' | 'attrs'>): string {
  switch (e.kind) {
    case 'untrusted_repo_opened':
      return 'Opened a repo from an untrusted source';
    case 'install_script_executed':
      return 'Ran an install script';
    case 'unverified_installer_used':
      return 'Used an unverified installer';
    case 'artifact_verdict':
      return `Artifact judged ${String(e.attrs.verdict ?? 'unknown')}`;
    case 'credential_read':
      return e.attrs.target ? `Read credentials (${String(e.attrs.target)})` : 'Read credentials';
    case 'deploy_token_on_disk':
      return 'Deploy token found on disk';
    case 'ai_tool_permission_change':
      return 'Broadened an AI tool’s permissions';
    case 'ai_tool_cross_host_action':
      return 'AI tool acted on another machine';
    case 'signing_request':
      return 'Signing request';
  }
}

/** Longest run of events whose kill-chain stage strictly increases over time. */
function longestChain<T extends { stage: Stage }>(seq: T[]): T[] {
  const n = seq.length;
  const len = Array<number>(n).fill(1);
  const prev = Array<number>(n).fill(-1);
  const rank = (i: number) => RANK[seq[i]!.stage] ?? 0;
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < i; j++) {
      if (rank(j) < rank(i) && len[j]! + 1 > len[i]!) {
        len[i] = len[j]! + 1;
        prev[i] = j;
      }
    }
  }
  let best = -1;
  for (let i = 0; i < n; i++) if (best < 0 || len[i]! >= len[best]!) best = i;
  const out: T[] = [];
  for (let i = best; i >= 0; i = prev[i]!) out.unshift(seq[i]!);
  return out;
}

/** Pure and deterministic: same events and `now` always give the same state, with the reasons attached. */
export function computeTrust(subject: string, events: TrustEvent[], now = new Date(), cfg: TrustConfig = TRUST_CONFIG): TrustState {
  const nowMs = now.getTime();
  const windowMs = cfg.windowDays * 86_400_000;
  const decay = (t: number) => 0.5 ** (Math.max(0, nowMs - t) / 3_600_000 / cfg.halfLifeHours);

  const inWindow = events
    .filter((e) => e.subject === subject)
    .map((e) => ({ e, t: Date.parse(e.occurredAt) }))
    .filter(({ t }) => Number.isFinite(t) && nowMs - t <= windowMs && t <= nowMs + cfg.futureSkewMs)
    .sort((a, b) => a.t - b.t);

  const scored = inWindow
    .map(({ e, t }) => ({ e, t, stage: EVENT_STAGE[e.kind], weight: eventWeight(e) }))
    .map((x) => ({ ...x, decayed: x.weight * decay(x.t) }))
    .filter((x) => x.weight > 0);

  const sum = scored.reduce((n, x) => n + x.decayed, 0);
  const chain = longestChain(scored.filter((x) => RANK[x.stage] !== undefined));
  const last = chain.at(-1);
  const bonus = chain.length >= 2 && last ? (cfg.chainBonus[Math.min(chain.length, 3)] ?? 0) * decay(last.t) : 0;
  const risk = Math.min(100, Math.round(sum + bonus));

  const reasons = [...scored]
    .sort((a, b) => b.decayed - a.decayed)
    .slice(0, 3)
    .map((x) => describe(x.e));
  if (chain.length >= 2) {
    reasons.push(`Chain across ${chain.length} stages: ${chain.map((x) => describe(x.e)).join(' → ')}`);
  }

  return {
    subject,
    risk,
    level: levelFor(risk, cfg.thresholds),
    chain: { length: chain.length >= 2 ? chain.length : 0, stages: chain.length >= 2 ? chain.map((x) => x.stage) : [] },
    contributions: scored.map((x) => ({
      eventId: x.e.id,
      kind: x.e.kind,
      stage: x.stage,
      weight: x.weight,
      decayedWeight: Math.round(x.decayed * 10) / 10,
    })),
    reasons,
    eventCount: inWindow.length,
    windowDays: cfg.windowDays,
    computedAt: now.toISOString(),
  };
}
