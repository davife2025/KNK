import type { MiddlewareHandler } from 'hono';
import { routePath } from 'hono/route';
import type { Store } from '../store/types.js';
import type { AppEnv, AuthContext } from './auth.js';

/** Meters one unit per authenticated request (server errors are not billed). Never blocks the response. */
export function meterUsage(store: Store): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    await next();
    const auth = c.get('auth') as AuthContext | undefined;
    if (!auth || c.res.status >= 500) return;
    void store
      .recordUsage({
        workspaceId: auth.workspaceId,
        apiKeyId: auth.apiKeyId,
        endpoint: `${c.req.method} ${routePath(c)}`,
        units: 1,
      })
      .catch((e) => console.error('recordUsage', e));
  };
}
