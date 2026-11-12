import { Hono } from 'hono';
import type { StatusResponse } from '@knk/shared';
import { getEnv } from '../env.js';

export const status = new Hono();

status.get('/health', (c) => c.json({ ok: true }));

status.get('/v1/status', (c) => {
  const env = getEnv();
  const body: StatusResponse = {
    service: 'knk-api',
    version: '0.0.0',
    integrations: {
      supabase: Boolean(env.SUPABASE_URL && env.SUPABASE_SERVICE_ROLE_KEY),
      llm: Boolean(env.HF_TOKEN),
    },
  };
  return c.json(body);
});
