import { describe, expect, it } from 'vitest';
import { assertPublicUrl, isBlockedAddress, UrlRejected } from '../src/lib/ssrf.js';

const PUBLIC = async () => ['93.184.216.34'];
const reject = async (url: string, policy = { allowPrivate: false, resolve: PUBLIC }) => {
  try {
    await assertPublicUrl(url, policy);
    return 'allowed';
  } catch (e) {
    return e instanceof UrlRejected ? e.reason : 'other';
  }
};

describe('isBlockedAddress', () => {
  it('blocks private, loopback, link-local, metadata and reserved IPv4', () => {
    for (const ip of ['10.0.0.1', '127.0.0.1', '127.255.255.254', '169.254.169.254', '172.16.0.1', '172.31.255.255', '192.168.1.1', '100.64.0.1', '0.0.0.0', '224.0.0.1', '240.0.0.1']) {
      expect(isBlockedAddress(ip), ip).toBe(true);
    }
  });

  it('allows ordinary public IPv4', () => {
    for (const ip of ['8.8.8.8', '93.184.216.34', '172.15.255.255', '172.32.0.1', '1.1.1.1']) expect(isBlockedAddress(ip), ip).toBe(false);
  });

  it('blocks private IPv6 and the IPv4-mapped forms that are used to sneak past filters', () => {
    for (const ip of ['::1', '::', 'fc00::1', 'fd12:3456::1', 'fe80::1', 'ff02::1', '::ffff:10.0.0.1', '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:a9fe:a9fe']) {
      expect(isBlockedAddress(ip), ip).toBe(true);
    }
    expect(isBlockedAddress('2606:4700:4700::1111')).toBe(false);
    expect(isBlockedAddress('::ffff:8.8.8.8')).toBe(false);
  });

  it('treats anything unparseable as blocked', () => {
    for (const bad of ['', 'localhost', '999.1.1.1', '1.2.3', '0x7f000001', '2130706433']) expect(isBlockedAddress(bad), bad).toBe(true);
  });
});

describe('assertPublicUrl', () => {
  it('accepts a public https URL', async () => {
    expect(await reject('https://hooks.example.com/knk')).toBe('allowed');
  });

  it('rejects bad schemes, credentials and garbage', async () => {
    expect(await reject('http://hooks.example.com/')).toBe('https_required');
    expect(await reject('ftp://hooks.example.com/')).toBe('https_required');
    expect(await reject('javascript:alert(1)')).toBe('https_required');
    expect(await reject('https://user:pw@hooks.example.com/')).toBe('credentials_in_url');
    expect(await reject('not a url')).toBe('invalid_url');
  });

  it('rejects literal private addresses in every notation URL parsing normalises', async () => {
    for (const u of ['https://127.0.0.1/', 'https://10.1.2.3/', 'https://169.254.169.254/latest/meta-data', 'https://[::1]/', 'https://[fd00::1]/', 'https://[::ffff:10.0.0.1]/', 'https://2130706433/', 'https://0x7f.1/', 'https://127.1/']) {
      expect(await reject(u), u).toBe('private_address');
    }
  });

  it('rejects hostnames that resolve to private addresses, even if only one of several does', async () => {
    expect(await reject('https://internal.example/', { allowPrivate: false, resolve: async () => ['10.0.0.5'] })).toBe('private_address');
    expect(await reject('https://mixed.example/', { allowPrivate: false, resolve: async () => ['93.184.216.34', '127.0.0.1'] })).toBe('private_address');
    expect(await reject('https://nx.example/', { allowPrivate: false, resolve: async () => { throw new Error('ENOTFOUND'); } })).toBe('unresolvable_host');
    expect(await reject('https://empty.example/', { allowPrivate: false, resolve: async () => [] })).toBe('unresolvable_host');
  });

  it('allowPrivate (dev only) permits http and private targets but still refuses credentials', async () => {
    const dev = { allowPrivate: true, resolve: PUBLIC };
    expect(await reject('http://127.0.0.1:3000/hook', dev)).toBe('allowed');
    expect(await reject('http://user:pw@127.0.0.1/', dev)).toBe('credentials_in_url');
  });
});
