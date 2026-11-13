import dns from 'node:dns';
import { BlockList, isIP } from 'node:net';

// Addresses a webhook must never reach: private, loopback, link-local (incl. cloud metadata), multicast, reserved.
const blocked = new BlockList();
for (const [net, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
] as const) blocked.addSubnet(net, prefix, 'ipv4');
for (const [net, prefix] of [
  ['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8], ['2001:db8::', 32], ['64:ff9b::', 96],
] as const) blocked.addSubnet(net, prefix, 'ipv6');

/** Unparseable input counts as blocked. IPv4-mapped IPv6 (::ffff:a.b.c.d) is judged by its IPv4 part. */
export function isBlockedAddress(address: string): boolean {
  const family = isIP(address);
  if (!family) return true;
  return blocked.check(address, family === 6 ? 'ipv6' : 'ipv4');
}

export class UrlRejected extends Error {
  constructor(readonly reason: string) {
    super(reason);
    this.name = 'UrlRejected';
  }
}

export type Resolver = (host: string) => Promise<string[]>;
const defaultResolver: Resolver = async (host) => (await dns.promises.lookup(host, { all: true })).map((a) => a.address);

export interface UrlPolicy {
  /** Development and tests only: allows http and private addresses. Refused by the env schema in production. */
  allowPrivate: boolean;
  resolve?: Resolver;
}

/** Early check (at registration and before each delivery). The connect-time guard below is the authoritative one. */
export async function assertPublicUrl(raw: string, policy: UrlPolicy): Promise<URL> {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new UrlRejected('invalid_url');
  }
  if (url.protocol !== 'https:' && !(policy.allowPrivate && url.protocol === 'http:')) throw new UrlRejected('https_required');
  if (url.username || url.password) throw new UrlRejected('credentials_in_url');
  if (policy.allowPrivate) return url;

  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (isIP(host)) {
    if (isBlockedAddress(host)) throw new UrlRejected('private_address');
    return url;
  }
  let addrs: string[];
  try {
    addrs = await (policy.resolve ?? defaultResolver)(host);
  } catch {
    throw new UrlRejected('unresolvable_host');
  }
  if (addrs.length === 0) throw new UrlRejected('unresolvable_host');
  if (addrs.some(isBlockedAddress)) throw new UrlRejected('private_address');
  return url;
}

/**
 * DNS lookup used when the socket actually connects. It checks the addresses it is about to use,
 * so a hostname that resolved to a public address earlier cannot be re-pointed at a private one (DNS rebinding).
 */
export function guardedLookup(allowPrivate: boolean) {
  return (
    hostname: string,
    options: dns.LookupOptions,
    callback: (err: NodeJS.ErrnoException | null, address: string | dns.LookupAddress[], family?: number) => void,
  ): void => {
    dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
      if (err) return callback(err, '');
      const list = addresses as dns.LookupAddress[];
      const bad = list.find((a) => isBlockedAddress(a.address));
      if (bad && !allowPrivate) return callback(new Error(`blocked address ${bad.address}`) as NodeJS.ErrnoException, '');
      if (options.all) return callback(null, list);
      const first = list[0];
      return first ? callback(null, first.address, first.family) : callback(new Error('no address') as NodeJS.ErrnoException, '');
    });
  };
}
