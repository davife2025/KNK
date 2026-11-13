import { describe, expect, it } from 'vitest';
import type { ContainmentData, WebhookEnvelope } from '@knk/shared';
import { createGuardHandler, signWebhook, type AgentGuardAdapter } from '../src/index.js';

const SECRET = 'whsec_guard_test';
const NOW = Date.UTC(2026, 10, 12, 12, 0, 0);

const envelope = (type: WebhookEnvelope['type'], data: Record<string, unknown>): WebhookEnvelope => ({
  id: 'evt-1',
  type,
  createdAt: new Date(NOW).toISOString(),
  workspaceId: 'ws-1',
  data,
});
const containment = (over: Partial<ContainmentData> = {}) =>
  envelope('containment.requested', {
    incidentId: 'inc-1',
    trigger: 'trust.critical',
    subject: 'alice@laptop',
    reasons: ['Chain across 3 stages'],
    agentIds: ['agent-a', 'agent-b'],
    actions: ['revoke_grants', 'prepare_freeze'],
    ...over,
  });
const request = (env: WebhookEnvelope, secret = SECRET) => {
  const body = JSON.stringify(env);
  return { headers: { 'knk-signature': signWebhook(secret, body, NOW) }, body };
};

function adapter(opts: { failRevoke?: string; failFreeze?: string } = {}) {
  const calls: string[] = [];
  const a: AgentGuardAdapter = {
    async revokeGrantTokens(id) {
      calls.push(`revoke:${id}`);
      if (id === opts.failRevoke) throw new Error('store unavailable');
    },
    async prepareFreeze(id) {
      calls.push(`freeze:${id}`);
      if (id === opts.failFreeze) throw new Error('api down');
      return { correlationId: `corr-${id}` };
    },
  };
  return { a, calls };
}
const handler = (a: AgentGuardAdapter, onEvent?: (e: WebhookEnvelope) => void) =>
  createGuardHandler({ secret: SECRET, adapter: a, onEvent, nowMs: () => NOW });

describe('guard handler', () => {
  it('cuts off each agent: grants first, then the freeze is prepared', async () => {
    const { a, calls } = adapter();
    const res = await handler(a)(request(containment()));
    expect(res.status).toBe(200);
    expect(calls).toEqual(['revoke:agent-a', 'freeze:agent-a', 'revoke:agent-b', 'freeze:agent-b']);
    expect(res.body).toMatchObject({ ok: true, agents: [{ agentId: 'agent-a', grantsRevoked: true, freezePrepared: { correlationId: 'corr-agent-a' } }, { agentId: 'agent-b' }] });
  });

  it('refuses forged, tampered and unsigned requests and touches nothing', async () => {
    const { a, calls } = adapter();
    const h = handler(a);
    expect((await h(request(containment(), 'attacker-secret'))).status).toBe(401);
    const good = request(containment());
    expect((await h({ ...good, body: good.body.replace('agent-a', 'agent-z') })).status).toBe(401);
    expect((await h({ headers: {}, body: good.body })).status).toBe(401);
    expect(calls).toEqual([]);
  });

  it('runs an incident once even if KNK retries the delivery', async () => {
    const { a, calls } = adapter();
    const h = handler(a);
    await h(request(containment()));
    const again = await h(request(containment()));
    expect(again.body).toMatchObject({ ok: true, duplicate: true });
    expect(calls).toHaveLength(4);
  });

  it('a partial failure reports 500, still tries every agent and every action, and a retry runs again', async () => {
    const { a, calls } = adapter({ failRevoke: 'agent-a' });
    const h = handler(a);
    const res = await h(request(containment()));
    expect(res.status).toBe(500);
    expect(calls).toEqual(['revoke:agent-a', 'freeze:agent-a', 'revoke:agent-b', 'freeze:agent-b']); // freeze still attempted
    expect(res.body).toMatchObject({
      ok: false,
      agents: [
        { agentId: 'agent-a', grantsRevoked: false, freezePrepared: { correlationId: 'corr-agent-a' }, errors: [expect.stringContaining('revoke_grants')] },
        { agentId: 'agent-b', grantsRevoked: true, errors: [] },
      ],
    });
    await h(request(containment()));
    expect(calls).toHaveLength(8); // not remembered as done, so the retry ran again
  });

  it('honours the action list and passes other events to onEvent without acting', async () => {
    const { a, calls } = adapter();
    const seen: string[] = [];
    const h = handler(a, (e) => void seen.push(e.type));
    await h(request(containment({ incidentId: 'inc-2', actions: ['revoke_grants'] })));
    expect(calls).toEqual(['revoke:agent-a', 'revoke:agent-b']);
    const alert = await h(request(envelope('gate.blocked', { subject: 'alice' })));
    expect(alert.body).toMatchObject({ ok: true, handled: false });
    expect(seen).toEqual(['containment.requested', 'gate.blocked']);
    expect(calls).toHaveLength(2);
  });

  it('rejects malformed JSON and malformed envelopes (after the signature check)', async () => {
    const { a } = adapter();
    const h = handler(a);
    const sig = (b: string) => ({ headers: { 'knk-signature': signWebhook(SECRET, b, NOW) }, body: b });
    expect((await h(sig('not json'))).status).toBe(400);
    expect((await h(sig('{"hello":1}'))).status).toBe(400);
    expect((await h(request(containment({ agentIds: 'nope' as never })))).status).toBe(400);
  });
});
