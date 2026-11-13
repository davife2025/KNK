import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { VerdictSigner } from '../lib/signing.js';

const { privateKey } = generateKeyPairSync('ed25519');
const signer = new VerdictSigner(privateKey);
console.log(`KNK_SIGNING_KEY=${privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64')}`);
console.log(`# key id: ${signer.keyId}`);
console.log(`KNK_ENCRYPTION_KEY=${randomBytes(32).toString('base64')}`);
