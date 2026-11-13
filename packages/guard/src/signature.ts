import { createHmac, timingSafeEqual } from 'node:crypto';

/**
 * Header format: `t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<raw body>">`.
 * The timestamp is part of what is signed, so a captured request cannot be replayed after the tolerance window.
 */
export function signWebhook(secret: string, body: string, nowMs = Date.now()): string {
  const t = Math.floor(nowMs / 1000);
  const v1 = createHmac('sha256', secret).update(`${t}.${body}`).digest('hex');
  return `t=${t},v1=${v1}`;
}

export type VerifyResult = { ok: true } | { ok: false; reason: 'malformed' | 'stale' | 'mismatch' };

export function verifyWebhook(opts: {
  secret: string;
  body: string;
  header: string | null | undefined;
  toleranceSeconds?: number;
  nowMs?: number;
}): VerifyResult {
  const m = /^t=(\d{1,12}),v1=([0-9a-f]{64})$/.exec(opts.header ?? '');
  if (!m) return { ok: false, reason: 'malformed' };
  const t = Number(m[1]);
  const skew = Math.abs((opts.nowMs ?? Date.now()) / 1000 - t);
  if (skew > (opts.toleranceSeconds ?? 300)) return { ok: false, reason: 'stale' };
  const expected = createHmac('sha256', opts.secret).update(`${t}.${opts.body}`).digest();
  const given = Buffer.from(m[2]!, 'hex');
  return given.length === expected.length && timingSafeEqual(given, expected) ? { ok: true } : { ok: false, reason: 'mismatch' };
}
