import { describe, expect, it } from 'vitest';
import type { EventKind } from '@knk/shared';
import { computeTrust, levelFor, TRUST_CONFIG, type TrustEvent } from '../src/lib/trust.js';

const NOW = new Date('2026-11-11T12:00:00Z');
const hoursAgo = (h: number) => new Date(NOW.getTime() - h * 3_600_000).toISOString();
let n = 0;
const ev = (kind: EventKind, h: number, attrs: TrustEvent['attrs'] = {}, subject = 'alice'): TrustEvent => ({
  id: `e${++n}`,
  subject,
  kind,
  attrs,
  occurredAt: hoursAgo(h),
});

describe('trust scoring', () => {
  it('an empty or benign history is normal', () => {
    expect(computeTrust('alice', [], NOW)).toMatchObject({ risk: 0, level: 'normal', eventCount: 0 });
    const s = computeTrust('alice', [ev('artifact_verdict', 1, { verdict: 'benign' }), ev('signing_request', 1)], NOW);
    expect(s.risk).toBe(0);
    expect(s.contributions).toEqual([]);
    expect(s.eventCount).toBe(2);
  });

  it('one routine signal stays normal; one malicious verdict is elevated', () => {
    expect(computeTrust('alice', [ev('install_script_executed', 0)], NOW).level).toBe('normal');
    const s = computeTrust('alice', [ev('artifact_verdict', 0, { verdict: 'malicious' })], NOW);
    expect(s.risk).toBe(55);
    expect(s.level).toBe('elevated');
  });

  it('weights credential reads by what was read', () => {
    const risk = (target: string) => computeTrust('a', [ev('credential_read', 0, { target }, 'a')], NOW).risk;
    expect(risk('wallet')).toBe(35);
    expect(risk('ssh')).toBe(30);
    expect(risk('something_else')).toBe(20);
  });

  it('signals fade: half the weight after one half-life, almost none after the window', () => {
    const fresh = computeTrust('alice', [ev('unverified_installer_used', 0)], NOW).risk;
    const aged = computeTrust('alice', [ev('unverified_installer_used', TRUST_CONFIG.halfLifeHours)], NOW).risk;
    expect(fresh).toBe(25);
    expect(aged).toBe(Math.round(25 / 2));
    expect(computeTrust('alice', [ev('unverified_installer_used', 24 * 15)], NOW)).toMatchObject({ risk: 0, eventCount: 0 });
  });

  it('weak signals in kill-chain order add up (the Binance shape)', () => {
    const chain = [
      ev('untrusted_repo_opened', 3),
      ev('credential_read', 2, { target: 'ssh' }),
      ev('ai_tool_cross_host_action', 1),
    ];
    const s = computeTrust('alice', chain, NOW);
    const plain = s.contributions.reduce((x, c) => x + c.decayedWeight, 0);
    expect(s.chain.length).toBe(3);
    expect(s.chain.stages).toEqual(['initial_access', 'credential_access', 'privilege_escalation']);
    expect(s.risk).toBeGreaterThan(plain + 20); // the chain bonus (up to 25) is on top of the plain sum
    expect(s.level).toBe('critical');
    expect(s.reasons.at(-1)).toMatch(/^Chain across 3 stages/);
  });

  it('out-of-order stages form a shorter chain and no bonus beyond it', () => {
    const s = computeTrust('alice', [ev('credential_read', 3, { target: 'ssh' }), ev('untrusted_repo_opened', 2), ev('ai_tool_cross_host_action', 1)], NOW);
    expect(s.chain.length).toBe(2);
  });

  it('ignores other subjects and future-dated events', () => {
    const s = computeTrust('alice', [ev('credential_read', 1, { target: 'wallet' }, 'bob'), ev('credential_read', -2, { target: 'wallet' })], NOW);
    expect(s.risk).toBe(0);
  });

  it('caps at 100 and maps thresholds to levels', () => {
    const many = Array.from({ length: 10 }, () => ev('artifact_verdict', 0, { verdict: 'malicious' }));
    expect(computeTrust('alice', many, NOW).risk).toBe(100);
    expect([0, 24, 25, 49, 50, 74, 75].map((r) => levelFor(r))).toEqual(['normal', 'normal', 'watch', 'watch', 'elevated', 'elevated', 'critical']);
  });

  it('is deterministic and explains itself', () => {
    const events = [ev('credential_read', 5, { target: 'deploy_token' }), ev('unverified_installer_used', 9)];
    expect(computeTrust('alice', events, NOW)).toEqual(computeTrust('alice', [...events].reverse(), NOW));
    expect(computeTrust('alice', events, NOW).reasons[0]).toBe('Read credentials (deploy_token)');
  });
});
