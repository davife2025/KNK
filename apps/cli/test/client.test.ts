import { describe, expect, it } from 'vitest';
import { ApiFailure, createClient } from '../src/client.js';
import { trustState } from './fakes.js';

const KEY = `knk_aaaaaaaa_${'b'.repeat(43)}`;
const ok = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

function client(handler: (url: string, init: RequestInit) => Response | Promise<Response>) {
  const seen: { url: string; init: RequestInit }[] = [];
  const c = createClient({ baseUrl: 'https://api.example.com', key: KEY, fetchImpl: (async (url: string, init: RequestInit) => (seen.push({ url, init }), handler(url, init))) as unknown as typeof fetch });
  return { c, seen };
}

describe('API client', () => {
  it('sends the bearer key, never follows redirects, and encodes the subject in the path', async () => {
    const { c, seen } = client(() => ok(trustState('a b/c@x')));
    await c.trust('a b/c@x');
    const { url, init } = seen[0]!;
    expect(url).toBe('https://api.example.com/v1/subjects/a%20b%2Fc%40x/trust');
    expect((init.headers as Record<string, string>).authorization).toBe(`Bearer ${KEY}`);
    expect(init.redirect).toBe('error'); // the Authorization header must never be replayed to another host
  });

  it('refuses a plain-http base URL before any request is made', () => {
    expect(() => createClient({ baseUrl: 'http://api.example.com', key: KEY })).toThrow(/https/);
  });

  it('turns API errors, network failures, timeouts and malformed responses into ApiFailure', async () => {
    const api = client(() => ok({ error: { code: 'forbidden', message: 'This key lacks the "analyze" scope' } }, 403));
    await expect(api.c.me()).rejects.toMatchObject({ name: 'ApiFailure', status: 403, code: 'forbidden', message: 'This key lacks the "analyze" scope' });

    const down = client(() => { throw new TypeError('fetch failed'); });
    await expect(down.c.me()).rejects.toMatchObject({ status: 0, code: 'unreachable' });

    const slow = client(() => { const e = new Error('t'); e.name = 'TimeoutError'; throw e; });
    await expect(slow.c.me()).rejects.toMatchObject({ code: 'timeout' });

    const junk = client(() => ok({ not: 'a me response' }));
    await expect(junk.c.me()).rejects.toMatchObject({ status: 502, code: 'bad_response' });

    const html = client(() => new Response('<html>gateway error</html>', { status: 502 }));
    await expect(html.c.me()).rejects.toBeInstanceOf(ApiFailure);
  });

  it('only includes subject on analyze when one is given', async () => {
    const { c, seen } = client(() => ok({ nothing: true }));
    await c.analyze('source_file', 'x').catch(() => {});
    await c.analyze('source_file', 'x', 'alice').catch(() => {});
    expect(JSON.parse(seen[0]!.init.body as string)).toEqual({ kind: 'source_file', content: 'x' });
    expect(JSON.parse(seen[1]!.init.body as string)).toEqual({ kind: 'source_file', content: 'x', subject: 'alice' });
  });
});
