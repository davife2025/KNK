import { describe, expect, it } from 'vitest';
import { generateApiKey, hashApiKey, parseApiKey, safeEqual, verifyApiKey } from '../src/lib/api-keys.js';

describe('api keys', () => {
  it('generates a well-formed key whose prefix parses back', () => {
    const { key, prefix, hash } = generateApiKey();
    expect(key).toMatch(/^knk_[0-9a-f]{8}_[A-Za-z0-9_-]{43}$/);
    expect(parseApiKey(key)).toEqual({ prefix });
    expect(hash).toBe(hashApiKey(key));
    expect(hash).not.toContain(key);
  });

  it('verifies only the right key', () => {
    const a = generateApiKey();
    const b = generateApiKey();
    expect(verifyApiKey(a.key, a.hash)).toBe(true);
    expect(verifyApiKey(b.key, a.hash)).toBe(false);
    expect(verifyApiKey(a.key, 'not-hex')).toBe(false);
  });

  it('rejects malformed keys', () => {
    expect(parseApiKey('')).toBeNull();
    expect(parseApiKey('knk_short_x')).toBeNull();
    expect(parseApiKey('Bearer knk_00000000_' + 'a'.repeat(43))).toBeNull();
  });

  it('safeEqual compares secrets of any length', () => {
    expect(safeEqual('same', 'same')).toBe(true);
    expect(safeEqual('same', 'different-length')).toBe(false);
  });
});
