import { beforeEach, describe, expect, it } from 'vitest';
import type { CreatedKey, MeResponse, UsageSummary, WorkspaceWithKey } from '@knk/shared';
import { createApp } from '../src/app.js';
import { resetEnvForTests } from '../src/env.js';
import { memoryStore } from './helpers.js';

const TOKEN = 'bootstrap-token-0123456789';

async function setup() {
  process.env.KNK_BOOTSTRAP_TOKEN = TOKEN;
  resetEnvForTests();
  const mem = memoryStore();
  const app = createApp({ store: mem.store });
  const res = await app.request('/v1/workspaces', {
    method: 'POST',
    headers: { 'x-bootstrap-token': TOKEN, 'content-type': 'application/json' },
    body: JSON.stringify({ name: 'Acme Exchange' }),
  });
  const created = (await res.json()) as WorkspaceWithKey;
  const auth = (key: string) => ({ authorization: `Bearer ${key}`, 'content-type': 'application/json' });
  return { app, mem, created, admin: created.apiKey.key, auth, res };
}

describe('bootstrap', () => {
  beforeEach(() => resetEnvForTests());

  it('is disabled without a configured token', async () => {
    delete process.env.KNK_BOOTSTRAP_TOKEN;
    resetEnvForTests();
    const res = await createApp({ store: memoryStore().store }).request('/v1/workspaces', { method: 'POST' });
    expect(res.status).toBe(503);
  });

  it('rejects a wrong token and an invalid body', async () => {
    const { app } = await setup();
    const bad = await app.request('/v1/workspaces', { method: 'POST', headers: { 'x-bootstrap-token': 'nope' } });
    expect(bad.status).toBe(401);
    const invalid = await app.request('/v1/workspaces', {
      method: 'POST',
      headers: { 'x-bootstrap-token': TOKEN, 'content-type': 'application/json' },
      body: JSON.stringify({ name: '' }),
    });
    expect(invalid.status).toBe(400);
  });

  it('creates a workspace with an admin key and stores only the hash', async () => {
    const { res, created, mem } = await setup();
    expect(res.status).toBe(201);
    expect(created.apiKey.scopes).toContain('admin');
    const stored = await mem.store.findKeyByPrefix(created.apiKey.prefix);
    expect(stored?.keyHash).not.toBe(created.apiKey.key);
  });
});

describe('authentication', () => {
  it('rejects missing, malformed, unknown and revoked keys', async () => {
    const { app, admin, auth } = await setup();
    expect((await app.request('/v1/me')).status).toBe(401);
    expect((await app.request('/v1/me', { headers: auth('knk_00000000_' + 'a'.repeat(43)) })).status).toBe(401);
    expect((await app.request('/v1/me', { headers: auth(admin) })).status).toBe(200);

    const made = (await (await app.request('/v1/keys', {
      method: 'POST',
      headers: auth(admin),
      body: JSON.stringify({ name: 'ci' }),
    })).json()) as CreatedKey;
    expect((await app.request('/v1/me', { headers: auth(made.key) })).status).toBe(200);
    expect((await app.request(`/v1/keys/${made.id}`, { method: 'DELETE', headers: auth(admin) })).status).toBe(204);
    expect((await app.request('/v1/me', { headers: auth(made.key) })).status).toBe(401);
  });

  it('enforces scopes: a default key cannot manage keys', async () => {
    const { app, admin, auth } = await setup();
    const made = (await (await app.request('/v1/keys', {
      method: 'POST',
      headers: auth(admin),
      body: JSON.stringify({ name: 'sensor' }),
    })).json()) as CreatedKey;
    expect(made.scopes).not.toContain('admin');
    expect((await app.request('/v1/keys', { headers: auth(made.key) })).status).toBe(403);
  });

  it('never exposes the key hash or secret when listing', async () => {
    const { app, admin, auth } = await setup();
    const text = await (await app.request('/v1/keys', { headers: auth(admin) })).text();
    expect(text).not.toContain('keyHash');
    expect(text).not.toContain(admin);
  });
});

describe('metering and audit', () => {
  it('meters authenticated calls per route and summarises them', async () => {
    const { app, mem, admin, auth, created } = await setup();
    await app.request('/v1/me', { headers: auth(admin) });
    await app.request('/v1/me', { headers: auth(admin) });
    await app.request('/v1/keys', { headers: auth(admin) });
    await app.request('/v1/me'); // unauthenticated: not metered
    expect(mem.usage).toHaveLength(3);
    expect(mem.usage[0]?.endpoint).toBe('GET /v1/me');

    const summary = (await (await app.request('/v1/usage', { headers: auth(admin) })).json()) as UsageSummary;
    expect(summary.byEndpoint.find((r) => r.endpoint === 'GET /v1/me')?.requests).toBe(2);
    expect(summary.total).toBeGreaterThanOrEqual(3);
    const me = (await (await app.request('/v1/me', { headers: auth(admin) })).json()) as MeResponse;
    expect(me.workspace.id).toBe(created.workspace.id);
  });

  it('writes audit entries for key lifecycle changes', async () => {
    const { app, mem, admin, auth } = await setup();
    const made = (await (await app.request('/v1/keys', {
      method: 'POST',
      headers: auth(admin),
      body: JSON.stringify({ name: 'temp' }),
    })).json()) as CreatedKey;
    await app.request(`/v1/keys/${made.id}`, { method: 'DELETE', headers: auth(admin) });
    expect(mem.audits.map((a) => a.action)).toEqual(['key.created', 'key.revoked']);
  });
});
