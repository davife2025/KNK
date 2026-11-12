import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

// Format: knk_<8 hex prefix>_<43 char secret>. The prefix is a public lookup id.
// The secret is 256 bits of randomness, so a plain SHA-256 is appropriate (no slow KDF needed).
const KEY_RE = /^knk_([0-9a-f]{8})_[A-Za-z0-9_-]{43}$/;

export interface GeneratedKey {
  key: string;
  prefix: string;
  hash: string;
}

export function hashApiKey(key: string): string {
  return createHash('sha256').update(key).digest('hex');
}

export function generateApiKey(): GeneratedKey {
  const prefix = randomBytes(4).toString('hex');
  const key = `knk_${prefix}_${randomBytes(32).toString('base64url')}`;
  return { key, prefix, hash: hashApiKey(key) };
}

export function parseApiKey(key: string): { prefix: string } | null {
  const match = KEY_RE.exec(key);
  return match ? { prefix: match[1]! } : null;
}

export function verifyApiKey(key: string, storedHash: string): boolean {
  const a = Buffer.from(hashApiKey(key), 'hex');
  const b = Buffer.from(storedHash, 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Constant-time string comparison for shared secrets such as the bootstrap token. */
export function safeEqual(a: string, b: string): boolean {
  const ha = createHash('sha256').update(a).digest();
  const hb = createHash('sha256').update(b).digest();
  return timingSafeEqual(ha, hb);
}
