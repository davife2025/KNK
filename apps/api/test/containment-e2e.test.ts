import { randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { createGuardHandler, type AgentGuardAdapter } from '@knk/guard';
import type { CreatedWebhook, ResponseRun, WorkspaceWithKey } from '@knk/shared';
import { createApp } from '../src/app.js';
import { resetEnvForTests } from '../src/env.js';
import { createDispatcher } from '../src/lib/dispatcher.js';
import { createResponseKit } from '../src/lib/response.js';
import { createSecretBox } from '../src/lib/secret-box.js';
import { VerdictSigner } from '../src/lib/signing.js';
import { memoryStore } from './helpers.js';

const TOKEN = 'bootstrap-token-0123456789';
const ago = (h: number) => new Date(Date.now() - h * 3_600_000).toISOString();

/**
 * The full containment path with no mocks between KNK and the receiver: ingestion -> trust goes critical ->
 * playbook -> signed webhook over a real socket -> @knk/guard verifies it -> the customer's adapter cuts off the agents.
 * The agent adapter here is a stand-in; nothing talks to the real Agent API.
 */
describe('containment end to end (real HTTP, stand-in agent adapter)', () => {
  const servers: ReturnType<typeof createServer>[] = [];
  afterEach(() => servers.splice(0).forEach((s) => s.close()));

  async function receiver(secretRef: { current: string }, adapter: AgentGuardAdapter) {
    const seen: { event?: string; status?: number }[] = [];
    let handle: ReturnType<typeof createGuardHandler> | null = null;
    const server = createServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', async () => {
        handle ??= createGuardHandler({ secret: secretRef.current, adapter });
        const out = await handle({ headers: req.headers, body });
        seen.push({ event: req.headers['knk-event'] as string, status: out.status });
        res.statusCode = out.status;
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify(out.body));
      });
    });
    servers.push(server);
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    return { seen, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/knk` };
  }

  async function setup() {
    process.env.KNK_BOOTSTRAP_TOKEN = TOKEN;
    resetEnvForTests();
    const mem = memoryStore();
    const box = createSecretBox(randomBytes(32));
    const kit = createResponseKit(mem.store, { box: () => box, allowPrivate: true, dispatcher: createDispatcher({ allowPrivate: true, backoffMs: [5, 5] }) });
    const app = createApp({ store: mem.store, llm: null, signer: VerdictSigner.ephemeral(), kit });
    const ws = (await (await app.request('/v1/workspaces', { method: 'POST', headers: { 'x-bootstrap-token': TOKEN, 'content-type': 'application/json' }, body: JSON.stringify({ name: 'Acme' }) })).json()) as WorkspaceWithKey;
    const call = (method: string, path: string, body?: unknown) =>
      app.request(path, { method, headers: { authorization: `Bearer ${ws.apiKey.key}`, 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
    const json = async <T>(p: Promise<Response>) => (await p).json() as Promise<T>;
    const incident = async () => {
      const s = 'alice@laptop';
      await call('POST', '/v1/events', { events: [
        { subject: s, kind: 'untrusted_repo_opened', occurredAt: ago(30) },
        { subject: s, kind: 'credential_read', occurredAt: ago(6), attrs: { target: 'deploy_token' } },
        { subject: s, kind: 'ai_tool_cross_host_action', occurredAt: ago(2) },
      ] });
      await kit.engine.idle();
    };
    const runs = async () => (await json<{ runs: ResponseRun[] }>(call('GET', '/v1/responses'))).runs;
    return { call, json, kit, incident, runs, mem };
  }

  const recorder = () => {
    const calls: string[] = [];
    const adapter: AgentGuardAdapter = {
      async revokeGrantTokens(id) { calls.push(`revoke:${id}`); },
      async prepareFreeze(id) { calls.push(`freeze:${id}`); return { correlationId: `corr-${id}` }; },
    };
    return { calls, adapter };
  };

  it('a critical developer triggers a signed request that cuts off both agents on the customer side', async () => {
    const { calls, adapter } = recorder();
    const secret = { current: '' };
    const rx = await receiver(secret, adapter);
    const { call, json, incident, runs } = await setup();

    const hook = await json<CreatedWebhook>(call('POST', '/v1/webhooks', { url: rx.url }));
    secret.current = hook.secret;
    await call('POST', '/v1/playbooks', { name: 'Contain', triggers: ['trust.critical'], webhookId: hook.id, kind: 'containment', agentIds: ['agent-a', 'agent-b'] });

    await incident();

    expect(calls).toEqual(['revoke:agent-a', 'freeze:agent-a', 'revoke:agent-b', 'freeze:agent-b']);
    expect(rx.seen).toEqual([{ event: 'containment.requested', status: 200 }]);
    expect(await runs()).toMatchObject([{ status: 'delivered', attempts: 1, httpStatus: 200, eventType: 'containment.requested', subject: 'alice@laptop' }]);
  });

  it('a receiver with the wrong secret refuses the request; nothing is cut off and it is not retried', async () => {
    const { calls, adapter } = recorder();
    const rx = await receiver({ current: 'a-different-secret' }, adapter);
    const { call, json, incident, runs } = await setup();

    const hook = await json<CreatedWebhook>(call('POST', '/v1/webhooks', { url: rx.url }));
    await call('POST', '/v1/playbooks', { name: 'Contain', triggers: ['trust.critical'], webhookId: hook.id, kind: 'containment', agentIds: ['agent-a'] });
    await incident();

    expect(calls).toEqual([]);
    expect(rx.seen).toEqual([{ event: 'containment.requested', status: 401 }]);
    expect(await runs()).toMatchObject([{ status: 'failed', attempts: 1, httpStatus: 401 }]); // 4xx is final
  });

  it('an unreachable receiver is retried, then recorded as failed so the team can see it', async () => {
    const { call, json, incident, runs } = await setup();
    const rx = await receiver({ current: 'x' }, recorder().adapter);
    servers.pop()!.close(); // nothing is listening any more
    const hook = await json<CreatedWebhook>(call('POST', '/v1/webhooks', { url: rx.url }));
    await call('POST', '/v1/playbooks', { name: 'Alert', triggers: ['trust.critical'], webhookId: hook.id });
    await incident();
    const [run] = await runs();
    expect(run).toMatchObject({ status: 'failed', attempts: 3 });
    expect(run!.error).toBeTruthy();
  });

  it('a partial failure on the customer side returns 500 and KNK retries, so the incident is eventually handled', async () => {
    let revokeCalls = 0;
    const calls: string[] = [];
    const adapter: AgentGuardAdapter = {
      async revokeGrantTokens(id) { if (++revokeCalls === 1) throw new Error('token store down'); calls.push(`revoke:${id}`); },
      async prepareFreeze(id) { calls.push(`freeze:${id}`); return { correlationId: 'c' }; },
    };
    const secret = { current: '' };
    const rx = await receiver(secret, adapter);
    const { call, json, incident, runs } = await setup();
    const hook = await json<CreatedWebhook>(call('POST', '/v1/webhooks', { url: rx.url }));
    secret.current = hook.secret;
    await call('POST', '/v1/playbooks', { name: 'Contain', triggers: ['trust.critical'], webhookId: hook.id, kind: 'containment', agentIds: ['agent-a'] });
    await incident();
    expect(rx.seen.map((s) => s.status)).toEqual([500, 200]); // first attempt failed, the retry succeeded
    expect(calls).toContain('revoke:agent-a');
    expect(await runs()).toMatchObject([{ status: 'delivered', attempts: 2 }]);
  });
});
