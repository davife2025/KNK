import { describe, expect, it } from 'vitest';
import { DEFAULT_POLICY, PolicyRules, type DecodedTx } from '@knk/shared';
import { evaluateGate } from '../src/lib/gate-policy.js';

const normal = { risk: 0, level: 'normal' as const };
const tx = (o: Partial<DecodedTx>): DecodedTx => ({ format: 'evm_raw', kind: 'native_transfer', ...o });
const ev = (decoded: DecodedTx | null, trust: { risk: number; level: 'normal' | 'watch' | 'elevated' | 'critical' } = normal, policy = DEFAULT_POLICY) =>
  evaluateGate({ decoded, trust, policy });
const rules = (r: ReturnType<typeof ev>) => r.hits.map((h) => h.rule);

describe('evaluateGate', () => {
  it('a plain transfer from a normal requester is allowed', () => {
    expect(ev(tx({ to: '0xabc', nativeValue: '5' }))).toEqual({ decision: 'allow', hits: [] });
  });

  it('undecodable transactions are blocked', () => {
    expect(ev(null).decision).toBe('block');
  });

  it('delegations are blocked by default, and held when the delegate is allowlisted', () => {
    const d = tx({ kind: 'delegation', delegates: [{ chainId: 1, address: '0xdel', nonce: 0 }] });
    expect(rules(ev(d))).toEqual(['delegation.not_allowlisted']);
    expect(ev(d).decision).toBe('block');
    const allow = PolicyRules.parse({ allowedDelegates: ['0xDEL'] });
    expect(ev(d, normal, allow)).toMatchObject({ decision: 'hold', hits: [{ rule: 'delegation.allowlisted' }] });
    expect(ev(d, normal, PolicyRules.parse({ delegation: 'hold' })).decision).toBe('hold');
    expect(ev(tx({ kind: 'delegation', delegates: [{ chainId: 0, address: '0xdel', nonce: 0 }] })).hits[0]?.reason).toContain('any chain');
  });

  it('trust maps to outcomes: watch allows, elevated holds, critical blocks', () => {
    expect(ev(tx({}), { risk: 30, level: 'watch' }).decision).toBe('allow');
    expect(ev(tx({}), { risk: 60, level: 'elevated' }).decision).toBe('hold');
    expect(ev(tx({}), { risk: 90, level: 'critical' })).toMatchObject({ decision: 'block', hits: [{ rule: 'trust.critical' }] });
    expect(ev(tx({}), { risk: 60, level: 'elevated' }, PolicyRules.parse({ trust: { watch: 'allow', elevated: 'allow', critical: 'block' } })).decision).toBe('allow');
  });

  it('destination allowlist applies to recipients and spenders, case-insensitively', () => {
    const p = PolicyRules.parse({ allowedDestinations: ['0xAAA'] });
    expect(ev(tx({ to: '0xaaa' }), normal, p).decision).toBe('allow');
    expect(rules(ev(tx({ to: '0xbbb' }), normal, p))).toEqual(['destination.unknown']);
    expect(ev(tx({ kind: 'token_transfer', to: '0xtoken', recipient: '0xbbb' }), normal, p).decision).toBe('hold');
    expect(ev(tx({ to: '0xbbb' }), normal, PolicyRules.parse({ allowedDestinations: ['0xaaa'], onUnknownDestination: 'block' })).decision).toBe('block');
    expect(ev(tx({ to: '0xbbb' })).decision).toBe('allow'); // no allowlist, no rule
  });

  it('value and transfer limits hold; at the limit is fine', () => {
    const p = PolicyRules.parse({ maxNativeValueWei: '100', maxTransferAmount: { USDC: '50' } });
    expect(ev(tx({ nativeValue: '100' }), normal, p).decision).toBe('allow');
    expect(rules(ev(tx({ nativeValue: '101' }), normal, p))).toEqual(['value.over_limit']);
    expect(rules(ev(tx({ kind: 'transfer', amount: '51', asset: 'usdc' }), normal, p))).toEqual(['transfer.over_limit']);
    expect(ev(tx({ kind: 'transfer', amount: '50', asset: 'usdc' }), normal, p).decision).toBe('allow');
  });

  it('unlimited approvals hold; contract calls hold by default and can be allowed', () => {
    expect(rules(ev(tx({ kind: 'token_approval', unlimited: true })))).toEqual(['approval.unlimited']);
    expect(ev(tx({ kind: 'token_approval', unlimited: false })).decision).toBe('allow');
    expect(rules(ev(tx({ kind: 'contract_call', selector: '0xdeadbeef' })))).toEqual(['contract_call.review']);
    expect(ev(tx({ kind: 'contract_call' }), normal, PolicyRules.parse({ onContractCall: 'allow' })).decision).toBe('allow');
  });

  it('block beats hold, and every reason is reported', () => {
    const d = tx({ kind: 'delegation', delegates: [{ chainId: 1, address: '0xdel', nonce: 0 }] });
    const r = ev(d, { risk: 60, level: 'elevated' });
    expect(r.decision).toBe('block');
    expect(rules(r)).toEqual(['trust.elevated', 'delegation.not_allowlisted']);
  });

  it('policy defaults are what the docs say', () => {
    expect(DEFAULT_POLICY).toMatchObject({ trust: { watch: 'allow', elevated: 'hold', critical: 'block' }, delegation: 'block', unlimitedApproval: 'hold', onContractCall: 'hold', timelockSeconds: 900, approvalsRequired: 1 });
    expect(() => PolicyRules.parse({ maxNativeValueWei: 'abc' })).toThrow();
  });
});
