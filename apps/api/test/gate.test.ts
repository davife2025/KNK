import { afterEach, describe, expect, it, vi } from 'vitest';
import { encodeFunctionData, erc20Abi, maxUint256, serializeTransaction } from 'viem';
import type { ConfirmResponse, GateDecisionView, PolicyResponse, WorkspaceWithKey } from '@knk/shared';
import { createApp } from '../src/app.js';
import { resetEnvForTests } from '../src/env.js';
import { VerdictSigner, verifySignature } from '../src/lib/signing.js';
import { memoryStore } from './helpers.js';

const TOKEN = 'bootstrap-token-0123456789';
const A = '0x1111111111111111111111111111111111111111';
const DELEGATE = '0x2222222222222222222222222222222222222222';
const SPENDER = '0x3333333333333333333333333333333333333333';
const TKN = '0x4444444444444444444444444444444444444444';
const base = { chainId: 1, nonce: 5, gas: 21000n, maxFeePerGas: 10n, maxPriorityFeePerGas: 1n } as const;
const rawTx = (o: Record<string, unknown>) => serializeTransaction({ type: 'eip1559', ...base, ...o } as never);

const transfer = { format: 'evm_raw' as const, raw: rawTx({ to: A, value: 1000n }) };
const unlimited = { format: 'evm_raw' as const, raw: rawTx({ to: TKN, data: encodeFunctionData({ abi: erc20Abi, functionName: 'approve', args: [SPENDER, maxUint256] }) }) };
const delegation = { format: 'evm_authorization' as const, chainId: 1, delegate: DELEGATE, nonce: 0 };

async function setup() {
  process.env.KNK_BOOTSTRAP_TOKEN = TOKEN;
  resetEnvForTests();
  const mem = memoryStore();
  const signer = VerdictSigner.ephemeral();
  const app = createApp({ store: mem.store, llm: null, signer });
  const mk = async (name: string) =>
    (await (await app.request('/v1/workspaces', { method: 'POST', headers: { 'x-bootstrap-token': TOKEN, 'content-type': 'application/json' }, body: JSON.stringify({ name }) })).json()) as WorkspaceWithKey;
  const ws = await mk('Acme');
  const call = (method: string, path: string, body?: unknown, key = ws.apiKey.key) =>
    app.request(path, { method, headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  const json = async <T>(p: Promise<Response>) => (await p).json() as Promise<T>;
  const adminKey2 = async () => ((await json<{ key: string }>(call('POST', '/v1/keys', { name: 'second admin', scopes: ['admin'] }))).key);
  const check = (tx: unknown, subject = 'alice@laptop', wallet = 'hot-3') => json<GateDecisionView>(call('POST', '/v1/gate/check', { subject, wallet, tx }));
  const confirm = (id: string, tx: unknown) => json<ConfirmResponse>(call('POST', `/v1/gate/decisions/${id}/confirm`, { tx }));
  const approve = (id: string, approver: string, key?: string) => call('POST', `/v1/gate/decisions/${id}/approve`, { approver }, key);
  const setPolicy = (rules: unknown) => call('PUT', '/v1/policy', rules);
  return { app, mem, signer, ws, mk, call, json, adminKey2, check, confirm, approve, setPolicy };
}

afterEach(() => vi.useRealTimers());

describe('allow, single use and signing', () => {
  it('allows a plain transfer, signs the decision, and the release works exactly once', async () => {
    const { check, confirm, signer, mem } = await setup();
    const d = await check(transfer);
    expect(d).toMatchObject({ state: 'released', payload: { decision: 'allow', kind: 'native_transfer', trustLevel: 'normal' } });
    expect(verifySignature(d.payload, d.signature, signer.publicKey)).toBe(true);
    expect(JSON.stringify([...mem.decisions.values()])).not.toContain(transfer.raw); // the raw tx is never stored

    expect(await confirm(d.payload.id, transfer)).toMatchObject({ proceed: true });
    expect(await confirm(d.payload.id, transfer)).toMatchObject({ proceed: false, reason: 'consumed' });
  });

  it('two simultaneous confirms release exactly once (atomic single use)', async () => {
    const { check, confirm } = await setup();
    const d = await check(transfer);
    const results = await Promise.all(Array.from({ length: 5 }, () => confirm(d.payload.id, transfer)));
    expect(results.filter((r) => r.proceed)).toHaveLength(1);
  });

  it('a different transaction cannot use an existing release (swap protection)', async () => {
    const { check, confirm } = await setup();
    const d = await check(transfer);
    const swapped = { format: 'evm_raw' as const, raw: rawTx({ to: SPENDER, value: 1000n }) };
    expect(await confirm(d.payload.id, swapped)).toMatchObject({ proceed: false, reason: 'fingerprint_mismatch' });
    expect(await confirm(d.payload.id, transfer)).toMatchObject({ proceed: true }); // the genuine one still works
  });

  it('an unused allow expires after five minutes', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const { check, confirm } = await setup();
    const d = await check(transfer);
    vi.setSystemTime(new Date(Date.now() + 301_000));
    expect(await confirm(d.payload.id, transfer)).toMatchObject({ proceed: false, reason: 'expired' });
  });

  it('records the request as a neutral signing_request event', async () => {
    const { check, mem } = await setup();
    await check(transfer);
    expect(mem.events.at(-1)).toMatchObject({ kind: 'signing_request', subject: 'alice@laptop', attrs: { decision: 'allow', wallet: 'hot-3' } });
  });
});

describe('block', () => {
  it('blocks a delegation request, undecodable input, and never releases them', async () => {
    const { check, confirm } = await setup();
    const d = await check(delegation);
    expect(d).toMatchObject({ state: 'blocked', payload: { decision: 'block' } });
    expect(d.reasons.map((r) => r.rule)).toEqual(['delegation.not_allowlisted']);
    expect(await confirm(d.payload.id, delegation)).toMatchObject({ proceed: false, reason: 'blocked' });

    const bad = await check({ format: 'evm_raw', raw: '0xdeadbeef' });
    expect(bad.reasons[0]?.rule).toBe('decode.failed');
    expect(bad.payload.kind).toBe('undecodable');
  });

  it('replays the Binance chain: precursors, then a delegation request from the same person', async () => {
    const { call, check } = await setup();
    const ago = (h: number) => new Date(Date.now() - h * 3_600_000).toISOString();
    await call('POST', '/v1/events', { events: [
      { subject: 'alice@laptop', kind: 'untrusted_repo_opened', occurredAt: ago(30) },
      { subject: 'alice@laptop', kind: 'credential_read', occurredAt: ago(6), attrs: { target: 'deploy_token' } },
      { subject: 'alice@laptop', kind: 'ai_tool_cross_host_action', occurredAt: ago(2) },
    ] });
    const d = await check(delegation, 'alice@laptop');
    expect(d.payload.decision).toBe('block');
    expect(d.payload.trustLevel).toBe('critical');
    expect(d.reasons.map((r) => r.rule)).toEqual(['trust.critical', 'delegation.not_allowlisted']);
    // even an ordinary transfer from that person is now blocked
    expect((await check(transfer, 'alice@laptop')).payload.decision).toBe('block');
    // while a teammate with no signals is unaffected
    expect((await check(transfer, 'bob@laptop')).payload.decision).toBe('allow');
  });
});

describe('hold: approval and timelock', () => {
  it('walks pending approval, timelock, release, and rejects self-approval', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const { check, confirm, approve, setPolicy, json, call, ws } = await setup();
    await setPolicy({ timelockSeconds: 60 });
    const d = await check(unlimited);
    expect(d).toMatchObject({ state: 'pending_approval', payload: { decision: 'hold', approvalsRequired: 1 } });
    expect(d.reasons[0]?.rule).toBe('approval.unlimited');
    expect(await confirm(d.payload.id, unlimited)).toMatchObject({ proceed: false, reason: 'pending_approval' });

    const self = await approve(d.payload.id, 'Alice@Laptop');
    expect(self.status).toBe(403);

    const ok = await json<GateDecisionView>(approve(d.payload.id, 'carol'));
    expect(ok.state).toBe('timelocked');
    expect(ok.approvals.map((a) => a.approver)).toEqual(['carol']);
    expect(await confirm(d.payload.id, unlimited)).toMatchObject({ proceed: false, reason: 'timelocked' });

    vi.setSystemTime(new Date(Date.now() + 61_000));
    expect((await json<GateDecisionView>(call('GET', `/v1/gate/decisions/${d.payload.id}`))).state).toBe('released');
    expect(await confirm(d.payload.id, unlimited)).toMatchObject({ proceed: true });
    expect(ws.workspace.name).toBe('Acme');
  });

  it('a held decision that is never approved expires', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const { check, confirm, setPolicy } = await setup();
    await setPolicy({ timelockSeconds: 0, confirmWindowSeconds: 60 });
    const d = await check(unlimited);
    vi.setSystemTime(new Date(Date.now() + 61_000));
    expect(await confirm(d.payload.id, unlimited)).toMatchObject({ proceed: false, reason: 'expired' });
  });

  it('two-person rule: needs two distinct approvers on two distinct API keys', async () => {
    const { check, approve, setPolicy, adminKey2, json, ws } = await setup();
    await setPolicy({ timelockSeconds: 0, approvalsRequired: 2 });
    const d = await check(unlimited);
    expect((await json<GateDecisionView>(approve(d.payload.id, 'carol'))).state).toBe('pending_approval');
    expect((await approve(d.payload.id, 'carol')).status).toBe(409); // same name
    expect((await approve(d.payload.id, 'dave')).status).toBe(409); // same key under another name
    const key2 = await adminKey2();
    expect((await json<GateDecisionView>(approve(d.payload.id, 'dave', key2))).state).toBe('released');
    expect(ws.apiKey.key).not.toBe(key2);
  });

  it('only admin keys approve, and only held decisions can be approved', async () => {
    const { check, approve, call, json } = await setup();
    const d = await check(unlimited);
    const weak = (await json<{ key: string }>(call('POST', '/v1/keys', { name: 'sensor', scopes: ['gate:check'] }))).key;
    expect((await approve(d.payload.id, 'carol', weak)).status).toBe(403);
    const allowed = await check(transfer);
    expect((await approve(allowed.payload.id, 'carol')).status).toBe(409);
    expect((await approve('nope', 'carol')).status).toBe(404);
  });

  it('rejecting closes the decision for good', async () => {
    const { check, confirm, call, json, approve } = await setup();
    const d = await check(unlimited);
    const rej = await json<GateDecisionView>(call('POST', `/v1/gate/decisions/${d.payload.id}/reject`, { approver: 'carol' }));
    expect(rej.state).toBe('rejected');
    expect(await confirm(d.payload.id, unlimited)).toMatchObject({ proceed: false, reason: 'rejected' });
    expect((await approve(d.payload.id, 'dave')).status).toBe(409);
  });

  it('trust collapsing after approval stops the release (time of use)', async () => {
    const { check, confirm, approve, setPolicy, call } = await setup();
    await setPolicy({ timelockSeconds: 0 });
    const d = await check(unlimited);
    await approve(d.payload.id, 'carol');
    await call('POST', '/v1/events', { events: [
      { subject: 'alice@laptop', kind: 'artifact_verdict', attrs: { verdict: 'malicious' } },
      { subject: 'alice@laptop', kind: 'artifact_verdict', attrs: { verdict: 'malicious' } },
    ] });
    expect(await confirm(d.payload.id, unlimited)).toMatchObject({ proceed: false, reason: 'trust_degraded' });
  });

  it('an allowlisted delegate is held for approval, never auto-allowed', async () => {
    const { check, setPolicy } = await setup();
    await setPolicy({ allowedDelegates: [DELEGATE] });
    const d = await check(delegation);
    expect(d.payload.decision).toBe('hold');
    expect(d.reasons[0]?.rule).toBe('delegation.allowlisted');
  });
});

describe('policy API, scopes and isolation', () => {
  it('serves defaults, then the custom policy; only admin writes; bad input is rejected', async () => {
    const { call, json, mem, ws } = await setup();
    const before = await json<PolicyResponse>(call('GET', '/v1/policy'));
    expect(before).toMatchObject({ source: 'default', updatedAt: null, rules: { timelockSeconds: 900 } });

    const weak = (await json<{ key: string }>(call('POST', '/v1/keys', { name: 's', scopes: ['gate:check'] }))).key;
    expect((await call('PUT', '/v1/policy', { timelockSeconds: 5 }, weak)).status).toBe(403);
    expect((await call('PUT', '/v1/policy', { maxNativeValueWei: 'abc' })).status).toBe(400);

    const put = await json<PolicyResponse>(call('PUT', '/v1/policy', { timelockSeconds: 5, allowedDestinations: [A] }));
    expect(put).toMatchObject({ source: 'custom', rules: { timelockSeconds: 5, delegation: 'block' } }); // unspecified fields revert to defaults
    expect((await json<PolicyResponse>(call('GET', '/v1/policy'))).rules.allowedDestinations).toEqual([A]);
    expect(mem.audits.map((a) => a.action)).toContain('policy.updated');
    expect(ws.workspace.id).toBeTruthy();
  });

  it('requires the gate:check scope and a valid body', async () => {
    const { call, json, check } = await setup();
    const sensor = (await json<{ key: string }>(call('POST', '/v1/keys', { name: 'events only', scopes: ['events:write'] }))).key;
    expect((await call('POST', '/v1/gate/check', { subject: 'a', wallet: 'w', tx: transfer }, sensor)).status).toBe(403);
    expect((await call('POST', '/v1/gate/check', { subject: 'a', wallet: 'w', tx: { format: 'nope' } })).status).toBe(400);
    expect((await call('POST', '/v1/gate/check', { subject: 'a', wallet: 'w', tx: { format: 'evm_raw', raw: 'not hex' } })).status).toBe(400);
    expect((await check(transfer)).payload.id).toBeTruthy();
  });

  it('decisions are private to their workspace', async () => {
    const { check, call, mk, confirm } = await setup();
    const d = await check(unlimited);
    const other = await mk('Other');
    expect((await call('GET', `/v1/gate/decisions/${d.payload.id}`, undefined, other.apiKey.key)).status).toBe(404);
    expect((await call('POST', `/v1/gate/decisions/${d.payload.id}/confirm`, { tx: unlimited }, other.apiKey.key)).status).toBe(404);
    expect((await call('POST', `/v1/gate/decisions/${d.payload.id}/approve`, { approver: 'x' }, other.apiKey.key)).status).toBe(404);
    expect(await confirm(d.payload.id, unlimited)).toMatchObject({ reason: 'pending_approval' });
  });

  it('refuses to decide without a signing key', async () => {
    process.env.KNK_BOOTSTRAP_TOKEN = TOKEN;
    resetEnvForTests();
    const mem = memoryStore();
    const app = createApp({ store: mem.store, llm: null, signer: null });
    const ws = (await (await app.request('/v1/workspaces', { method: 'POST', headers: { 'x-bootstrap-token': TOKEN, 'content-type': 'application/json' }, body: JSON.stringify({ name: 'X' }) })).json()) as WorkspaceWithKey;
    const res = await app.request('/v1/gate/check', { method: 'POST', headers: { authorization: `Bearer ${ws.apiKey.key}`, 'content-type': 'application/json' }, body: JSON.stringify({ subject: 'a', wallet: 'w', tx: transfer }) });
    expect(res.status).toBe(503);
  });
});
