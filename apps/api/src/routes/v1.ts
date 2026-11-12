import { Hono } from 'hono';
import { z } from 'zod';
import {
  ALL_SCOPES,
  CreateKeyRequest,
  CreateWorkspaceRequest,
  type ApiKeyInfo,
  type CreatedKey,
  type MeResponse,
  type UsageSummary,
  type WorkspaceWithKey,
} from '@knk/shared';
import { getEnv } from '../env.js';
import { generateApiKey, safeEqual } from '../lib/api-keys.js';
import { apiError } from '../lib/errors.js';
import { requireApiKey, requireScope, type AppEnv } from '../middleware/auth.js';
import { meterUsage } from '../middleware/usage.js';
import type { KeyRecord, Store } from '../store/types.js';

const toInfo = (k: KeyRecord): ApiKeyInfo => ({
  id: k.id,
  name: k.name,
  prefix: k.prefix,
  scopes: k.scopes,
  createdAt: k.createdAt,
  lastUsedAt: k.lastUsedAt,
  revokedAt: k.revokedAt,
});

const issues = (e: z.ZodError) =>
  e.issues.map((i) => `${i.path.join('.') || 'body'}: ${i.message}`).join('; ');

export function v1Routes(store: Store): Hono<AppEnv> {
  const v1 = new Hono<AppEnv>();

  // Bootstrap: creates a workspace and its first (admin) key. Gated by KNK_BOOTSTRAP_TOKEN.
  v1.post('/v1/workspaces', async (c) => {
    const expected = getEnv().KNK_BOOTSTRAP_TOKEN;
    if (!expected) return apiError(c, 503, 'bootstrap_disabled', 'Workspace creation is not enabled');
    if (!safeEqual(c.req.header('x-bootstrap-token') ?? '', expected)) {
      return apiError(c, 401, 'unauthorized', 'Invalid bootstrap token');
    }
    const body = CreateWorkspaceRequest.safeParse(await c.req.json().catch(() => null));
    if (!body.success) return apiError(c, 400, 'invalid_request', issues(body.error));

    const gen = generateApiKey();
    const { workspace, key } = await store.createWorkspace({
      name: body.data.name,
      prefix: gen.prefix,
      keyHash: gen.hash,
      scopes: ALL_SCOPES,
    });
    const out: WorkspaceWithKey = { workspace, apiKey: { ...toInfo(key), key: gen.key } };
    return c.json(out, 201);
  });

  // Everything below needs a valid API key and is metered.
  // '/v1/keys/*' also matches '/v1/keys'; listing both would meter those calls twice.
  for (const path of ['/v1/me', '/v1/usage', '/v1/keys/*']) {
    v1.use(path, requireApiKey(store), meterUsage(store));
  }

  v1.get('/v1/me', async (c) => {
    const auth = c.get('auth');
    const workspace = await store.getWorkspace(auth.workspaceId);
    if (!workspace) return apiError(c, 404, 'not_found', 'Workspace not found');
    const out: MeResponse = { workspace, apiKeyId: auth.apiKeyId, scopes: auth.scopes };
    return c.json(out);
  });

  v1.get('/v1/usage', async (c) => {
    const days = z.coerce.number().int().min(1).max(90).catch(30).parse(c.req.query('days'));
    const since = new Date(Date.now() - days * 86_400_000);
    const byEndpoint = await store.usageSummary(c.get('auth').workspaceId, since);
    const out: UsageSummary = {
      since: since.toISOString(),
      total: byEndpoint.reduce((n, r) => n + r.units, 0),
      byEndpoint,
    };
    return c.json(out);
  });

  v1.get('/v1/keys', requireScope('admin'), async (c) => {
    const keys = await store.listKeys(c.get('auth').workspaceId);
    return c.json({ keys: keys.map(toInfo) });
  });

  v1.post('/v1/keys', requireScope('admin'), async (c) => {
    const body = CreateKeyRequest.safeParse(await c.req.json().catch(() => null));
    if (!body.success) return apiError(c, 400, 'invalid_request', issues(body.error));
    const auth = c.get('auth');

    const gen = generateApiKey();
    const rec = await store.insertKey({
      workspaceId: auth.workspaceId,
      name: body.data.name,
      prefix: gen.prefix,
      keyHash: gen.hash,
      scopes: body.data.scopes,
    });
    await store.audit({
      workspaceId: auth.workspaceId,
      actor: `key:${auth.keyPrefix}`,
      action: 'key.created',
      target: rec.id,
      meta: { name: rec.name, scopes: rec.scopes },
    });
    const out: CreatedKey = { ...toInfo(rec), key: gen.key };
    return c.json(out, 201);
  });

  v1.delete('/v1/keys/:id', requireScope('admin'), async (c) => {
    const auth = c.get('auth');
    const id = c.req.param('id');
    const revoked = await store.revokeKey(auth.workspaceId, id);
    if (!revoked) return apiError(c, 404, 'not_found', 'Key not found or already revoked');
    await store.audit({
      workspaceId: auth.workspaceId,
      actor: `key:${auth.keyPrefix}`,
      action: 'key.revoked',
      target: id,
    });
    return c.body(null, 204);
  });

  return v1;
}
