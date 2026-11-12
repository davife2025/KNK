import { Hono } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { IngestRequest, type IngestResponse, type TrustListResponse, type TrustState } from '@knk/shared';
import { apiError } from '../lib/errors.js';
import { redact } from '../lib/redact.js';
import { TRUST_CONFIG } from '../lib/trust.js';
import { trustSnapshot } from '../lib/trust-service.js';
import { requireApiKey, requireScope, type AppEnv } from '../middleware/auth.js';
import { meterUsage } from '../middleware/usage.js';
import type { NewEvent, Store } from '../store/types.js';

const MAX_AGE_MS = 30 * 86_400_000;

export function eventRoutes(store: Store): Hono<AppEnv> {
  const r = new Hono<AppEnv>();
  for (const path of ['/v1/events', '/v1/subjects/*', '/v1/trust']) {
    r.use(path, requireApiKey(store), meterUsage(store));
  }

  r.post(
    '/v1/events',
    requireScope('events:write'),
    bodyLimit({ maxSize: 128 * 1024, onError: (c) => apiError(c, 413, 'payload_too_large', 'Request body is too large') }),
    async (c) => {
      const body = IngestRequest.safeParse(await c.req.json().catch(() => null));
      if (!body.success) {
        const msg = body.error.issues.map((i) => `${i.path.join('.') || 'body'}: ${i.message}`).join('; ');
        return apiError(c, 400, 'invalid_request', msg);
      }

      const now = Date.now();
      const events: NewEvent[] = [];
      for (const [i, e] of body.data.events.entries()) {
        const t = e.occurredAt ? Date.parse(e.occurredAt) : now;
        if (t > now + TRUST_CONFIG.futureSkewMs) return apiError(c, 400, 'invalid_request', `events.${i}.occurredAt: is in the future`);
        if (now - t > MAX_AGE_MS) return apiError(c, 400, 'invalid_request', `events.${i}.occurredAt: is older than 30 days`);
        // Attributes are metadata, but redact string values anyway in case a sensor sends too much.
        const attrs = Object.fromEntries(Object.entries(e.attrs).map(([k, v]) => [k, typeof v === 'string' ? redact(v).text : v]));
        events.push({ subject: e.subject, kind: e.kind, attrs, occurredAt: new Date(t).toISOString() });
      }

      const { workspaceId } = c.get('auth');
      await store.insertEvents(workspaceId, events);
      const subjects = await trustSnapshot(store, workspaceId, { subjects: [...new Set(events.map((e) => e.subject))] });

      c.set('units', events.length); // per-event metering: placeholder pricing weight
      const out: IngestResponse = { accepted: events.length, subjects };
      return c.json(out, 201);
    },
  );

  r.get('/v1/trust', requireScope('gate:check'), async (c) => {
    const limit = Math.min(Math.max(Number(c.req.query('limit')) || 50, 1), 200);
    const out: TrustListResponse = { subjects: await trustSnapshot(store, c.get('auth').workspaceId, { limit }) };
    return c.json(out);
  });

  r.get('/v1/subjects/:subject/trust', requireScope('gate:check'), async (c) => {
    const [state] = await trustSnapshot(store, c.get('auth').workspaceId, { subjects: [c.req.param('subject')] });
    return c.json(state as TrustState);
  });

  return r;
}
