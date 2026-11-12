import { describe, expect, it } from 'vitest';
import { canonicalJson } from '@knk/shared';
import { VerdictSigner, verifySignature } from '../src/lib/signing.js';

describe('verdict signing', () => {
  it('canonical JSON ignores key order and undefined', () => {
    expect(canonicalJson({ b: 1, a: { d: 2, c: [3, { z: 1, y: undefined }] } })).toBe('{"a":{"c":[3,{"z":1}],"d":2},"b":1}');
  });

  it('signs and verifies; any tampering fails', () => {
    const s = VerdictSigner.ephemeral();
    const payload = { id: 'v1', riskScore: 12, findings: [{ id: 'a' }] };
    const sig = s.sign(payload);
    expect(verifySignature({ findings: [{ id: 'a' }], riskScore: 12, id: 'v1' }, sig, s.publicKey)).toBe(true);
    expect(verifySignature({ ...payload, riskScore: 11 }, sig, s.publicKey)).toBe(false);
    expect(verifySignature(payload, sig, VerdictSigner.ephemeral().publicKey)).toBe(false);
    expect(verifySignature(payload, 'garbage', s.publicKey)).toBe(false);
  });

  it('restores a signer from its exported key with a stable key id', () => {
    const a = VerdictSigner.ephemeral();
    // @ts-expect-error reading the private field in a test only to round-trip it
    const b64 = a.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
    const b = VerdictSigner.fromBase64Pkcs8(b64);
    expect(b.keyId).toBe(a.keyId);
    expect(verifySignature({ x: 1 }, b.sign({ x: 1 }), a.publicKey)).toBe(true);
  });
});
