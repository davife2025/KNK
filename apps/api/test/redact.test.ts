import { describe, expect, it } from 'vitest';
import { redact } from '../src/lib/redact.js';

describe('redact', () => {
  it('removes common secret shapes and reports counts', () => {
    const input = [
      'AWS=AKIAABCDEFGHIJKLMNOP',
      'gh=ghp_' + 'a'.repeat(36),
      'hf=hf_' + 'b'.repeat(34),
      '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----',
      'Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345',
      'DEPLOY_TOKEN=supersecretvalue123',
      'mnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow"',
      'near=ed25519:' + '5'.repeat(88),
    ].join('\n');
    const { text, redactions } = redact(input);
    for (const leaked of ['AKIAABCDEFGHIJKLMNOP', 'ghp_aaaa', 'hf_bbbb', 'MIIEvQIBADANBg', 'abcdefghijklmnopqrstuvwxyz012345', 'supersecretvalue123', 'legal winner', '55555555']) {
      expect(text).not.toContain(leaked);
    }
    const types = redactions.map((r) => r.type);
    expect(types).toEqual(expect.arrayContaining(['aws_access_key', 'github_token', 'huggingface_token', 'private_key_block', 'bearer_token', 'secret_assignment', 'seed_phrase', 'near_secret_key']));
  });

  it('keeps ordinary content, transaction hashes and NEAR public keys', () => {
    const tx = '0x' + 'ab'.repeat(32);
    const pub = 'ed25519:' + '6'.repeat(44);
    const input = `npm install left-pad\ntx ${tx}\nkey ${pub}`;
    const { text, redactions } = redact(input);
    expect(text).toBe(input);
    expect(redactions).toEqual([]);
  });

  it('does not double-count a redacted value', () => {
    const { redactions } = redact('API_KEY=ghp_' + 'a'.repeat(36));
    expect(redactions.reduce((n, r) => n + r.count, 0)).toBe(1);
  });
});
