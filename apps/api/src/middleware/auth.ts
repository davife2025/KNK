import type { MiddlewareHandler } from 'hono';
import type { Scope } from '@knk/shared';
import { parseApiKey, verifyApiKey } from '../lib/api-keys.js';
import { apiError } from '../lib/errors.js';
import type { Store } from '../store/types.js';

export interface AuthContext {
  workspaceId: string;
  apiKeyId: string;
  keyPrefix: string;
  scopes: Scope[];
}
export type AppEnv = { Variables: { auth: AuthContext } };

const TOUCH_INTERVAL_MS = 60_000;

/** Authenticates `Authorization: Bearer knk_...`. Every failure returns the same 401 on purpose. */
export function requireApiKey(store: Store): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    const header = c.req.header('authorization') ?? '';
    const token = header.startsWith('Bearer ') ? header.slice(7).trim() : '';
    const parsed = parseApiKey(token);
    if (!parsed) return apiError(c, 401, 'unauthorized', 'Missing or invalid API key');

    const rec = await store.findKeyByPrefix(parsed.prefix);
    if (!rec || rec.revokedAt || !verifyApiKey(token, rec.keyHash)) {
      return apiError(c, 401, 'unauthorized', 'Missing or invalid API key');
    }

    c.set('auth', {
      workspaceId: rec.workspaceId,
      apiKeyId: rec.id,
      keyPrefix: rec.prefix,
      scopes: rec.scopes,
    });

    const stale = !rec.lastUsedAt || Date.now() - Date.parse(rec.lastUsedAt) > TOUCH_INTERVAL_MS;
    if (stale) void store.touchKey(rec.id).catch((e) => console.error('touchKey', e));
    await next();
  };
}

/** `admin` implies every scope. */
export function requireScope(scope: Scope): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    const { scopes } = c.get('auth');
    if (!scopes.includes('admin') && !scopes.includes(scope)) {
      return apiError(c, 403, 'forbidden', `This key lacks the "${scope}" scope`);
    }
    await next();
  };
}
