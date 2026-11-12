import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { requestId } from 'hono/request-id';
import type { ApiError } from '@knk/shared';
import { status } from './routes/status.js';

export function createApp(): Hono {
  const app = new Hono();

  app.use('*', requestId());
  app.use('*', logger());
  app.use('*', cors());

  app.route('/', status);

  app.notFound((c) => {
    const body: ApiError = {
      error: { code: 'not_found', message: 'Route not found', requestId: c.get('requestId') },
    };
    return c.json(body, 404);
  });

  app.onError((err, c) => {
    console.error(err);
    const body: ApiError = {
      error: { code: 'internal_error', message: 'Unexpected error', requestId: c.get('requestId') },
    };
    return c.json(body, 500);
  });

  return app;
}
