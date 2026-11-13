import { signWebhook } from '@knk/guard';
import { WEBHOOK_HEADERS, type WebhookEnvelope } from '@knk/shared';
import { Agent, fetch as undiciFetch } from 'undici';
import { assertPublicUrl, guardedLookup, UrlRejected, type Resolver } from './ssrf.js';

export interface DeliveryResult {
  ok: boolean;
  attempts: number;
  httpStatus: number | null;
  error: string | null;
}

export interface Dispatcher {
  deliver(target: { url: string; secret: string }, envelope: WebhookEnvelope): Promise<DeliveryResult>;
}

const RETRYABLE = (status: number) => status === 408 || status === 429 || status >= 500;

export function createDispatcher(
  opts: {
    allowPrivate?: boolean;
    resolve?: Resolver;
    fetchImpl?: typeof fetch;
    sleep?: (ms: number) => Promise<void>;
    timeoutMs?: number;
    backoffMs?: number[]; // wait before attempt 2, 3, ...
  } = {},
): Dispatcher {
  const allowPrivate = opts.allowPrivate ?? false;
  const agent = new Agent({ connect: { lookup: guardedLookup(allowPrivate) } });
  const doFetch: typeof fetch = opts.fetchImpl ?? (((url: string, init: RequestInit) => undiciFetch(url, { ...init, dispatcher: agent } as never)) as unknown as typeof fetch);
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const backoff = opts.backoffMs ?? [1000, 4000];
  const maxAttempts = backoff.length + 1;

  return {
    async deliver(target, envelope) {
      const body = JSON.stringify(envelope);
      let result: DeliveryResult = { ok: false, attempts: 0, httpStatus: null, error: 'not attempted' };
      for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        let retry = false;
        try {
          const url = await assertPublicUrl(target.url, { allowPrivate, resolve: opts.resolve });
          const res = await doFetch(url.toString(), {
            method: 'POST',
            redirect: 'manual', // never follow: a redirect could point at an internal address
            headers: {
              'content-type': 'application/json',
              'user-agent': 'KNK-Webhooks/1',
              [WEBHOOK_HEADERS.signature]: signWebhook(target.secret, body), // fresh timestamp each attempt
              [WEBHOOK_HEADERS.event]: envelope.type,
              [WEBHOOK_HEADERS.delivery]: envelope.id,
            },
            body,
            signal: AbortSignal.timeout(opts.timeoutMs ?? 5000),
          });
          await res.body?.cancel();
          if (res.status >= 200 && res.status < 300) return { ok: true, attempts: attempt, httpStatus: res.status, error: null };
          const redirected = res.status >= 300 && res.status < 400;
          result = { ok: false, attempts: attempt, httpStatus: res.status, error: redirected ? 'redirect_not_followed' : `HTTP ${res.status}` };
          retry = RETRYABLE(res.status);
        } catch (e) {
          const rejected = e instanceof UrlRejected;
          const msg = rejected ? e.reason : e instanceof Error && e.name === 'TimeoutError' ? 'timeout' : e instanceof Error ? (e.cause instanceof Error ? e.cause.message : e.message) : 'failed';
          result = { ok: false, attempts: attempt, httpStatus: null, error: msg };
          retry = !rejected && !/blocked address/.test(msg);
        }
        if (!retry || attempt === maxAttempts) break;
        await sleep(backoff[attempt - 1] ?? 1000);
      }
      return result;
    },
  };
}
