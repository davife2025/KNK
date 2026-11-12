import { describe, expect, it } from 'vitest';
import { StatusResponse } from '@knk/shared';
import { createApp } from '../src/app.js';

describe('status routes', () => {
  const app = createApp();

  it('GET /health returns ok', async () => {
    const res = await app.request('/health');
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  it('GET /v1/status matches the shared contract', async () => {
    const res = await app.request('/v1/status');
    expect(res.status).toBe(200);
    expect(StatusResponse.safeParse(await res.json()).success).toBe(true);
  });

  it('unknown routes return the shared error shape', async () => {
    const res = await app.request('/nope');
    expect(res.status).toBe(404);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe('not_found');
  });
});
