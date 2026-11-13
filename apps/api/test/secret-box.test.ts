import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createSecretBox } from '../src/lib/secret-box.js';

describe('secret box (AES-256-GCM)', () => {
  const box = createSecretBox(randomBytes(32));

  it('round-trips, and never stores the plaintext', () => {
    const blob = box.encrypt('whsec_super_secret');
    expect(blob).not.toContain('whsec_super_secret');
    expect(box.decrypt(blob)).toBe('whsec_super_secret');
  });

  it('uses a fresh nonce each time', () => {
    expect(box.encrypt('same')).not.toBe(box.encrypt('same'));
  });

  it('fails on a wrong key, on tampering, and on junk', () => {
    const blob = box.encrypt('secret');
    expect(() => createSecretBox(randomBytes(32)).decrypt(blob)).toThrow();
    const parts = blob.split('.');
    parts[3] = Buffer.from('tampered').toString('base64url');
    expect(() => box.decrypt(parts.join('.'))).toThrow();
    expect(() => box.decrypt('nonsense')).toThrow();
    expect(() => createSecretBox(Buffer.alloc(16))).toThrow();
  });
});
