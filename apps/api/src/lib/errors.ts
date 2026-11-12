import type { Context } from 'hono';
import type { ApiError } from '@knk/shared';

export type ErrorStatus = 400 | 401 | 403 | 404 | 409 | 500 | 503;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function apiError(c: Context<any>, status: ErrorStatus, code: string, message: string) {
  const body: ApiError = { error: { code, message, requestId: c.get('requestId') } };
  return c.json(body, status);
}
