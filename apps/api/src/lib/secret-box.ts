import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { getEnv } from '../env.js';

/** AES-256-GCM for secrets we must be able to read back (webhook signing secrets can't be stored as hashes). */
export interface SecretBox {
  encrypt(plain: string): string;
  decrypt(blob: string): string;
}

export function createSecretBox(key: Buffer): SecretBox {
  if (key.length !== 32) throw new Error('Encryption key must be 32 bytes');
  const b64 = (b: Buffer) => b.toString('base64url');
  return {
    encrypt(plain) {
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      const ct = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
      return ['v1', b64(iv), b64(cipher.getAuthTag()), b64(ct)].join('.');
    },
    decrypt(blob) {
      const [v, iv, tag, ct] = blob.split('.');
      if (v !== 'v1' || !iv || !tag || !ct) throw new Error('Unrecognised secret format');
      const d = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64url'));
      d.setAuthTag(Buffer.from(tag, 'base64url'));
      return Buffer.concat([d.update(Buffer.from(ct, 'base64url')), d.final()]).toString('utf8');
    },
  };
}

let cached: SecretBox | null | undefined;

/** Production requires KNK_ENCRYPTION_KEY. Elsewhere an ephemeral key is used (stored secrets die on restart). */
export function getDefaultSecretBox(): SecretBox | null {
  if (cached !== undefined) return cached;
  const { KNK_ENCRYPTION_KEY, NODE_ENV } = getEnv();
  if (KNK_ENCRYPTION_KEY) return (cached = createSecretBox(Buffer.from(KNK_ENCRYPTION_KEY, 'base64')));
  if (NODE_ENV === 'production') return (cached = null);
  console.warn('KNK_ENCRYPTION_KEY is not set: using an ephemeral key (development only)');
  return (cached = createSecretBox(randomBytes(32)));
}
