import { randomBytes, randomUUID } from 'node:crypto';
import { Hono } from 'hono';
import {
  CreatePlaybookRequest,
  CreateWebhookRequest,
  type CreatedWebhook,
  type Playbook,
  type WebhookEnvelope,
  type WebhookInfo,
} from '@knk/shared';
import { apiError } from '../lib/errors.js';
import type { ResponseKit } from '../lib/response.js';
import { assertPublicUrl, UrlRejected } from '../lib/ssrf.js';
import { requireApiKey, requireScope, type AppEnv } from '../middleware/auth.js';
import { meterUsage } from '../middleware/usage.js';
import type { Store, WebhookRecord } from '../store/types.js';

const issues = (e: { issues: { path: PropertyKey[]; message: string }[] }) =>
  e.issues.map((i) => `${i.path.join('.') || 'body'}: ${i.message}`).join('; ');

const toInfo = (w: WebhookRecord): WebhookInfo => ({ id: w.id, url: w.url, description: w.description, createdAt: w.createdAt });

export function responseRoutes(store: Store, kit: ResponseKit): Hono<AppEnv> {
  const r = new Hono<AppEnv>();
  for (const path of ['/v1/webhooks/*', '/v1/playbooks/*', '/v1/responses']) r.use(path, requireApiKey(store), meterUsage(store));
  const admin = requireScope('admin');

  r.post('/v1/webhooks', admin, async (c) => {
    const body = CreateWebhookRequest.safeParse(await c.req.json().catch(() => null));
    if (!body.success) return apiError(c, 400, 'invalid_request', issues(body.error));
    const box = kit.box();
    if (!box) return apiError(c, 503, 'encryption_not_configured', 'Secret encryption is not configured');
    try {
      await assertPublicUrl(body.data.url, kit.urlPolicy);
    } catch (e) {
      return apiError(c, 400, 'invalid_url', e instanceof UrlRejected ? e.reason : 'invalid_url');
    }
    const secret = `whsec_${randomBytes(32).toString('base64url')}`;
    const rec = await store.insertWebhook({ workspaceId: c.get('auth').workspaceId, url: body.data.url, description: body.data.description ?? null, secretEnc: box.encrypt(secret) });
    const auth = c.get('auth');
    await store.audit({ workspaceId: auth.workspaceId, actor: `key:${auth.keyPrefix}`, action: 'webhook.created', target: rec.id, meta: { url: rec.url } });
    const out: CreatedWebhook = { ...toInfo(rec), secret };
    return c.json(out, 201);
  });

  r.get('/v1/webhooks', admin, async (c) => c.json({ webhooks: (await store.listWebhooks(c.get('auth').workspaceId)).map(toInfo) }));

  r.delete('/v1/webhooks/:id', admin, async (c) => {
    const auth = c.get('auth');
    if (!(await store.deleteWebhook(auth.workspaceId, c.req.param('id')))) return apiError(c, 404, 'not_found', 'Webhook not found');
    await store.audit({ workspaceId: auth.workspaceId, actor: `key:${auth.keyPrefix}`, action: 'webhook.deleted', target: c.req.param('id') });
    return c.body(null, 204);
  });

  // Sends a signed test event now and reports exactly what happened.
  r.post('/v1/webhooks/:id/test', admin, async (c) => {
    const auth = c.get('auth');
    const hook = await store.getWebhook(auth.workspaceId, c.req.param('id'));
    if (!hook) return apiError(c, 404, 'not_found', 'Webhook not found');
    const box = kit.box();
    if (!box) return apiError(c, 503, 'encryption_not_configured', 'Secret encryption is not configured');
    const envelope: WebhookEnvelope = { id: randomUUID(), type: 'webhook.test', createdAt: new Date().toISOString(), workspaceId: auth.workspaceId, data: { message: 'KNK webhook test' } };
    return c.json(await kit.dispatcher.deliver({ url: hook.url, secret: box.decrypt(hook.secretEnc) }, envelope));
  });

  r.post('/v1/playbooks', admin, async (c) => {
    const body = CreatePlaybookRequest.safeParse(await c.req.json().catch(() => null));
    if (!body.success) return apiError(c, 400, 'invalid_request', issues(body.error));
    const auth = c.get('auth');
    if (!(await store.getWebhook(auth.workspaceId, body.data.webhookId))) return apiError(c, 400, 'unknown_webhook', 'webhookId does not match a webhook in this workspace');
    const rec: Playbook = await store.insertPlaybook({ workspaceId: auth.workspaceId, ...body.data });
    await store.audit({ workspaceId: auth.workspaceId, actor: `key:${auth.keyPrefix}`, action: 'playbook.created', target: rec.id, meta: { kind: rec.kind, triggers: rec.triggers } });
    return c.json(rec, 201);
  });

  r.get('/v1/playbooks', admin, async (c) => c.json({ playbooks: await store.listPlaybooks(c.get('auth').workspaceId) }));

  r.delete('/v1/playbooks/:id', admin, async (c) => {
    const auth = c.get('auth');
    if (!(await store.deletePlaybook(auth.workspaceId, c.req.param('id')))) return apiError(c, 404, 'not_found', 'Playbook not found');
    await store.audit({ workspaceId: auth.workspaceId, actor: `key:${auth.keyPrefix}`, action: 'playbook.deleted', target: c.req.param('id') });
    return c.body(null, 204);
  });

  r.get('/v1/responses', admin, async (c) => {
    const limit = Math.min(Math.max(Number(c.req.query('limit')) || 50, 1), 200);
    return c.json({ runs: await store.listRuns(c.get('auth').workspaceId, limit) });
  });

  return r;
}
