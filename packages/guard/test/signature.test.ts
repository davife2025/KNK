import { describe, expect, it } from 'vitest';
import { signWebhook, verifyWebhook } from '../src/index.js';

const SECRET = 'whsec_test_secret';
const BODY = '{"id":"1","type":"webhook.test"}';
const NOW = Date.UTC(2026, 10, 12, 12, 0, 0);

describe('webhook signatures', () => {
  it('a signed body verifies', () => {
    expect(verifyWebhook({ secret: SECRET, body: BODY, header: signWebhook(SECRET, BODY, NOW), nowMs: NOW })).toEqual({ ok: true });
  });

  it('rejects a different secret, a changed body, and a malformed header', () => {
    const h = signWebhook(SECRET, BODY, NOW);
    expect(verifyWebhook({ secret: 'other', body: BODY, header: h, nowMs: NOW })).toEqual({ ok: false, reason: 'mismatch' });
    expect(verifyWebhook({ secret: SECRET, body: BODY + ' ', header: h, nowMs: NOW })).toEqual({ ok: false, reason: 'mismatch' });
    for (const bad of [undefined, null, '', 'garbage', 't=1,v1=xyz', `t=abc,v1=${'0'.repeat(64)}`]) {
      expect(verifyWebhook({ secret: SECRET, body: BODY, header: bad, nowMs: NOW })).toEqual({ ok: false, reason: 'malformed' });
    }
  });

  it('rejects replays outside the tolerance window, in either direction', () => {
    const h = signWebhook(SECRET, BODY, NOW);
    expect(verifyWebhook({ secret: SECRET, body: BODY, header: h, nowMs: NOW + 299_000 })).toEqual({ ok: true });
    expect(verifyWebhook({ secret: SECRET, body: BODY, header: h, nowMs: NOW + 301_000 })).toEqual({ ok: false, reason: 'stale' });
    expect(verifyWebhook({ secret: SECRET, body: BODY, header: h, nowMs: NOW - 301_000 })).toEqual({ ok: false, reason: 'stale' });
  });

  it('the timestamp is signed: moving it invalidates the signature', () => {
    const v1 = signWebhook(SECRET, BODY, NOW).split('v1=')[1];
    const moved = `t=${Math.floor(NOW / 1000) + 10},v1=${v1}`;
    expect(verifyWebhook({ secret: SECRET, body: BODY, header: moved, nowMs: NOW })).toEqual({ ok: false, reason: 'mismatch' });
  });
});
