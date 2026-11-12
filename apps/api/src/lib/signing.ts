import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from 'node:crypto';
import { canonicalJson } from '@knk/shared';
import { getEnv } from '../env.js';

/** Signs verdicts with Ed25519. A signature proves KNK issued the content, not that a model ran honestly. */
export class VerdictSigner {
  readonly keyId: string;
  readonly publicKey: string; // base64 SPKI DER

  constructor(private readonly privateKey: KeyObject) {
    const spki = createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
    this.publicKey = spki.toString('base64');
    this.keyId = createHash('sha256').update(spki).digest('hex').slice(0, 16);
  }

  static fromBase64Pkcs8(b64: string): VerdictSigner {
    return new VerdictSigner(createPrivateKey({ key: Buffer.from(b64, 'base64'), format: 'der', type: 'pkcs8' }));
  }

  static ephemeral(): VerdictSigner {
    return new VerdictSigner(generateKeyPairSync('ed25519').privateKey);
  }

  sign(payload: unknown): string {
    return edSign(null, Buffer.from(canonicalJson(payload)), this.privateKey).toString('base64');
  }
}

export function verifySignature(payload: unknown, signatureB64: string, publicKeyB64: string): boolean {
  try {
    const key = createPublicKey({ key: Buffer.from(publicKeyB64, 'base64'), format: 'der', type: 'spki' });
    return edVerify(null, Buffer.from(canonicalJson(payload)), key, Buffer.from(signatureB64, 'base64'));
  } catch {
    return false;
  }
}

let cached: VerdictSigner | undefined;

/** Production requires KNK_SIGNING_KEY. Elsewhere an ephemeral key is used (signatures die on restart). */
export function getDefaultSigner(): VerdictSigner | null {
  if (cached) return cached;
  const { KNK_SIGNING_KEY, NODE_ENV } = getEnv();
  if (KNK_SIGNING_KEY) return (cached = VerdictSigner.fromBase64Pkcs8(KNK_SIGNING_KEY));
  if (NODE_ENV === 'production') return null;
  console.warn('KNK_SIGNING_KEY is not set: using an ephemeral signing key (development only)');
  return (cached = VerdictSigner.ephemeral());
}
