import { createServer, type IncomingMessage } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { verifyWebhook } from '@knk/guard';
import type { WebhookEnvelope } from '@knk/shared';
import { createDispatcher } from '../src/lib/dispatcher.js';

const SECRET = 'whsec_dispatch_test';
const env: WebhookEnvelope = { id: 'evt-1', type: 'webhook.test', createdAt: new Date().toISOString(), workspaceId: 'ws', data: { hello: 'world' } };
const PUBLIC = async () => ['93.184.216.34'];
const target = (url = 'https://hooks.example.com/knk') => ({ url, secret: SECRET });

function mockFetch(statuses: (number | Error)[]) {
  const calls: { url: string; init: RequestInit }[] = [];
  const impl = (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    const next = statuses[Math.min(calls.length - 1, statuses.length - 1)]!;
    if (next instanceof Error) throw next;
    return new Response(null, { status: next });
  }) as unknown as typeof fetch;
  return { impl, calls };
}
const dispatcher = (statuses: (number | Error)[], sleeps: number[] = []) => {
  const f = mockFetch(statuses);
  return { ...f, d: createDispatcher({ fetchImpl: f.impl, resolve: PUBLIC, sleep: async (ms) => void sleeps.push(ms), backoffMs: [10, 20] }) };
};

describe('dispatcher (mocked network)', () => {
  it('sends a signed JSON POST that a receiver can verify', async () => {
    const { d, calls } = dispatcher([200]);
    const res = await d.deliver(target(), env);
    expect(res).toEqual({ ok: true, attempts: 1, httpStatus: 200, error: null });
    const init = calls[0]!.init;
    const h = init.headers as Record<string, string>;
    expect(init.method).toBe('POST');
    expect(init.redirect).toBe('manual');
    expect(h['knk-event']).toBe('webhook.test');
    expect(h['knk-delivery']).toBe('evt-1');
    expect(verifyWebhook({ secret: SECRET, body: init.body as string, header: h['knk-signature'] })).toEqual({ ok: true });
    expect(JSON.parse(init.body as string)).toEqual(env);
  });

  it('retries server errors with backoff and then succeeds', async () => {
    const sleeps: number[] = [];
    const { d, calls } = dispatcher([503, 500, 200], sleeps);
    expect(await d.deliver(target(), env)).toMatchObject({ ok: true, attempts: 3, httpStatus: 200 });
    expect(calls).toHaveLength(3);
    expect(sleeps).toEqual([10, 20]);
  });

  it('gives up after the last attempt and reports why', async () => {
    const { d, calls } = dispatcher([502]);
    expect(await d.deliver(target(), env)).toEqual({ ok: false, attempts: 3, httpStatus: 502, error: 'HTTP 502' });
    expect(calls).toHaveLength(3);
  });

  it('does not retry client errors, and treats redirects as failures without following them', async () => {
    const a = dispatcher([401]);
    expect(await a.d.deliver(target(), env)).toMatchObject({ ok: false, attempts: 1, httpStatus: 401 });
    const b = dispatcher([302]);
    expect(await b.d.deliver(target(), env)).toMatchObject({ ok: false, attempts: 1, error: 'redirect_not_followed' });
    expect(b.calls).toHaveLength(1);
    const c = dispatcher([429, 200]);
    expect(await c.d.deliver(target(), env)).toMatchObject({ ok: true, attempts: 2 }); // rate limiting is retried
  });

  it('retries network failures and timeouts', async () => {
    const { d } = dispatcher([new Error('ECONNRESET'), 200]);
    expect(await d.deliver(target(), env)).toMatchObject({ ok: true, attempts: 2 });
  });

  it('refuses private targets without making any request', async () => {
    for (const url of ['https://127.0.0.1/hook', 'https://169.254.169.254/latest', 'http://hooks.example.com/']) {
      const { d, calls } = dispatcher([200]);
      const res = await d.deliver(target(url), env);
      expect(res.ok).toBe(false);
      expect(res.attempts).toBe(1);
      expect(calls).toHaveLength(0);
    }
  });

  it('signs each attempt with a fresh timestamp', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    try {
      const f = mockFetch([500, 200]);
      const d = createDispatcher({ fetchImpl: f.impl, resolve: PUBLIC, sleep: async () => void vi.setSystemTime(Date.now() + 60_000), backoffMs: [10] });
      await d.deliver(target(), env);
      const t = (i: number) => /t=(\d+)/.exec((f.calls[i]!.init.headers as Record<string, string>)['knk-signature'])![1];
      expect(Number(t(1))).toBeGreaterThan(Number(t(0)));
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('dispatcher (real sockets and the connect-time guard)', () => {
  const servers: ReturnType<typeof createServer>[] = [];
  afterEach(() => servers.splice(0).forEach((s) => s.close()));

  async function listen(status = 200) {
    const hits: { headers: IncomingMessage['headers']; body: string }[] = [];
    const server = createServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        hits.push({ headers: req.headers, body });
        res.statusCode = status;
        res.end('ok');
      });
    });
    servers.push(server);
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    return { hits, port: (server.address() as AddressInfo).port };
  }

  it('DNS rebinding: a hostname that passed the early check but really resolves to loopback is blocked at connect time', async () => {
    const { hits, port } = await listen();
    // The early resolver is lied to (says "public"); the real lookup of "localhost" at connect time says loopback.
    const d = createDispatcher({ resolve: PUBLIC, sleep: async () => {}, backoffMs: [1, 1] });
    const res = await d.deliver(target(`https://localhost:${port}/hook`), env);
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/blocked address/);
    expect(res.attempts).toBe(1); // blocked addresses are not retried
    expect(hits).toHaveLength(0); // nothing reached the server
  });

  it('delivers over a real socket when private targets are explicitly allowed (dev), with a verifiable signature', async () => {
    const { hits, port } = await listen();
    const d = createDispatcher({ allowPrivate: true });
    const res = await d.deliver(target(`http://127.0.0.1:${port}/hook`), env);
    expect(res).toMatchObject({ ok: true, attempts: 1, httpStatus: 200 });
    expect(hits).toHaveLength(1);
    expect(verifyWebhook({ secret: SECRET, body: hits[0]!.body, header: hits[0]!.headers['knk-signature'] as string })).toEqual({ ok: true });
    expect(hits[0]!.headers['content-type']).toBe('application/json');
  });
});
