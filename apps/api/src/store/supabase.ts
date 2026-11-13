import type { SupabaseClient } from '@supabase/supabase-js';
import { EventKind, PolicyRules, Scope, type EventAttrs, type VerdictPayload } from '@knk/shared';
import { getSupabase } from '../lib/supabase.js';
import type { DecisionRecord, KeyRecord, Store, StoredEvent, WebhookRecord } from './types.js';
import type { Playbook, ResponseRun } from '@knk/shared';

interface KeyRow {
  id: string;
  workspace_id: string;
  name: string;
  prefix: string;
  key_hash: string;
  scopes: string[];
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

const validScopes = (raw: string[]): Scope[] =>
  raw.filter((s): s is Scope => Scope.safeParse(s).success);

interface EventRow {
  id: string;
  subject: string;
  kind: string;
  payload: EventAttrs | null;
  occurred_at: string;
}

const toEvents = (rows: EventRow[]): StoredEvent[] =>
  rows.flatMap((r) => {
    const kind = EventKind.safeParse(r.kind); // tolerate kinds added by newer versions
    return kind.success
      ? [{ id: r.id, subject: r.subject, kind: kind.data, attrs: r.payload ?? {}, occurredAt: r.occurred_at }]
      : [];
  });

interface DecisionRow {
  id: string;
  workspace_id: string;
  subject: string;
  wallet: string;
  decision: DecisionRecord['decision'];
  fingerprint: string;
  kind: string;
  summary: DecisionRecord['summary'];
  hits: DecisionRecord['hits'];
  trust_risk: number;
  trust_level: DecisionRecord['trustLevel'];
  approvals_required: number;
  release_at: string | null;
  expires_at: string | null;
  status: DecisionRecord['status'];
  created_at: string;
  payload: DecisionRecord['payload'];
  signature: string;
}

const toDecision = (r: DecisionRow): DecisionRecord => ({
  id: r.id,
  workspaceId: r.workspace_id,
  subject: r.subject,
  wallet: r.wallet,
  decision: r.decision,
  fingerprint: r.fingerprint,
  kind: r.kind,
  summary: r.summary,
  hits: r.hits,
  trustRisk: r.trust_risk,
  trustLevel: r.trust_level,
  approvalsRequired: r.approvals_required,
  releaseAt: r.release_at,
  expiresAt: r.expires_at,
  status: r.status,
  createdAt: r.created_at,
  payload: r.payload,
  signature: r.signature,
});

interface WebhookRow {
  id: string;
  workspace_id: string;
  url: string;
  description: string | null;
  secret_enc: string;
  created_at: string;
}
const toWebhook = (r: WebhookRow): WebhookRecord => ({ id: r.id, workspaceId: r.workspace_id, url: r.url, description: r.description, secretEnc: r.secret_enc, createdAt: r.created_at });

interface PlaybookRow {
  id: string;
  name: string;
  enabled: boolean;
  triggers: Playbook['triggers'];
  subjects: string[];
  webhook_id: string;
  kind: Playbook['kind'];
  agent_ids: string[];
  cooldown_seconds: number;
  created_at: string;
}
const toPlaybook = (r: PlaybookRow): Playbook => ({ id: r.id, name: r.name, enabled: r.enabled, triggers: r.triggers, subjects: r.subjects, webhookId: r.webhook_id, kind: r.kind, agentIds: r.agent_ids, cooldownSeconds: r.cooldown_seconds, createdAt: r.created_at });

interface RunRow {
  id: string;
  playbook_id: string | null;
  webhook_id: string | null;
  trigger: string;
  subject: string;
  event_type: string;
  status: ResponseRun['status'];
  attempts: number;
  http_status: number | null;
  error: string | null;
  created_at: string;
  finished_at: string | null;
}

const toKey = (r: KeyRow): KeyRecord => ({
  id: r.id,
  workspaceId: r.workspace_id,
  name: r.name,
  prefix: r.prefix,
  keyHash: r.key_hash,
  scopes: validScopes(r.scopes),
  createdAt: r.created_at,
  lastUsedAt: r.last_used_at,
  revokedAt: r.revoked_at,
});

/** The client is resolved lazily so the API can boot (and /health work) without Supabase configured. */
export function createSupabaseStore(client: () => SupabaseClient = getSupabase): Store {
  return {
    async createWorkspace({ name, prefix, keyHash, scopes }) {
      const { data, error } = await client().rpc('create_workspace', {
        p_name: name,
        p_prefix: prefix,
        p_key_hash: keyHash,
        p_scopes: scopes,
      });
      if (error) throw error;
      const key = toKey(data as KeyRow);
      return { workspace: { id: key.workspaceId, name }, key };
    },

    async getWorkspace(id) {
      const { data, error } = await client()
        .from('workspaces')
        .select('id,name')
        .eq('id', id)
        .maybeSingle();
      if (error) throw error;
      return data as { id: string; name: string } | null;
    },

    async findKeyByPrefix(prefix) {
      const { data, error } = await client()
        .from('api_keys')
        .select('*')
        .eq('prefix', prefix)
        .maybeSingle();
      if (error) throw error;
      return data ? toKey(data as KeyRow) : null;
    },

    async touchKey(id) {
      const { error } = await client()
        .from('api_keys')
        .update({ last_used_at: new Date().toISOString() })
        .eq('id', id);
      if (error) throw error;
    },

    async listKeys(workspaceId) {
      const { data, error } = await client()
        .from('api_keys')
        .select('*')
        .eq('workspace_id', workspaceId)
        .order('created_at', { ascending: false });
      if (error) throw error;
      return (data as KeyRow[]).map(toKey);
    },

    async insertKey({ workspaceId, name, prefix, keyHash, scopes }) {
      const { data, error } = await client()
        .from('api_keys')
        .insert({ workspace_id: workspaceId, name, prefix, key_hash: keyHash, scopes })
        .select('*')
        .single();
      if (error) throw error;
      return toKey(data as KeyRow);
    },

    async revokeKey(workspaceId, id) {
      const { data, error } = await client()
        .from('api_keys')
        .update({ revoked_at: new Date().toISOString() })
        .eq('id', id)
        .eq('workspace_id', workspaceId)
        .is('revoked_at', null)
        .select('id');
      if (error) throw error;
      return (data?.length ?? 0) > 0;
    },

    async recordUsage({ workspaceId, apiKeyId, endpoint, units }) {
      const { error } = await client()
        .from('usage_events')
        .insert({ workspace_id: workspaceId, api_key_id: apiKeyId, endpoint, units });
      if (error) throw error;
    },

    async usageSummary(workspaceId, since) {
      const { data, error } = await client().rpc('usage_by_endpoint', {
        p_workspace: workspaceId,
        p_since: since.toISOString(),
      });
      if (error) throw error;
      return (data as { endpoint: string; requests: number | string; units: number | string }[]).map(
        (r) => ({ endpoint: r.endpoint, requests: Number(r.requests), units: Number(r.units) }),
      );
    },

    async audit({ workspaceId, actor, action, target, meta }) {
      const { error } = await client()
        .from('audit_log')
        .insert({ workspace_id: workspaceId, actor, action, target: target ?? null, meta: meta ?? {} });
      if (error) throw error;
    },

    async insertVerdict({ payload, signature }) {
      // Only the hash of the analysed artifact is stored, never its content.
      const { error } = await client().from('verdicts').insert({
        id: payload.id,
        workspace_id: payload.workspaceId,
        outcome: payload.verdict,
        summary: payload.summary,
        model: payload.model,
        key_id: payload.keyId,
        signature,
        kind: payload.kind,
        artifact_sha256: payload.artifactSha256,
        risk_score: payload.riskScore,
        findings: payload.findings,
        mode: payload.mode,
        payload,
      });
      if (error) throw error;
    },

    async getVerdict(workspaceId, id) {
      const { data, error } = await client()
        .from('verdicts')
        .select('payload,signature')
        .eq('id', id)
        .eq('workspace_id', workspaceId)
        .maybeSingle();
      if (error) throw error;
      const row = data as { payload: VerdictPayload; signature: string } | null;
      return row ? { payload: row.payload, signature: row.signature, alg: 'Ed25519' } : null;
    },

    async insertEvents(workspaceId, events) {
      const { data, error } = await client()
        .from('events')
        .insert(
          events.map((e) => ({
            workspace_id: workspaceId,
            subject: e.subject,
            kind: e.kind,
            payload: e.attrs,
            occurred_at: e.occurredAt,
          })),
        )
        .select('id,subject,kind,payload,occurred_at');
      if (error) throw error;
      return toEvents(data as EventRow[]);
    },

    async listEvents(workspaceId, { since, subject, limit }) {
      let q = client()
        .from('events')
        .select('id,subject,kind,payload,occurred_at')
        .eq('workspace_id', workspaceId)
        .gte('occurred_at', since.toISOString());
      if (subject) q = q.eq('subject', subject);
      const { data, error } = await q.order('occurred_at', { ascending: false }).limit(limit);
      if (error) throw error;
      return toEvents(data as EventRow[]);
    },

    async getPolicy(workspaceId) {
      const { data, error } = await client()
        .from('policies')
        .select('rules,updated_at')
        .eq('workspace_id', workspaceId)
        .eq('name', 'default')
        .maybeSingle();
      if (error) throw error;
      if (!data) return null;
      const rules = PolicyRules.safeParse((data as { rules: unknown }).rules);
      return rules.success ? { rules: rules.data, updatedAt: (data as { updated_at: string }).updated_at } : null;
    },

    async setPolicy(workspaceId, rules) {
      const updatedAt = new Date().toISOString();
      const { error } = await client()
        .from('policies')
        .upsert({ workspace_id: workspaceId, name: 'default', rules, enabled: true, updated_at: updatedAt }, { onConflict: 'workspace_id,name' });
      if (error) throw error;
      return { updatedAt };
    },

    async insertDecision(r) {
      const { error } = await client().from('gate_decisions').insert({
        id: r.id,
        workspace_id: r.workspaceId,
        subject: r.subject,
        wallet: r.wallet,
        decision: r.decision,
        fingerprint: r.fingerprint,
        kind: r.kind,
        summary: r.summary,
        hits: r.hits,
        trust_risk: r.trustRisk,
        trust_level: r.trustLevel,
        approvals_required: r.approvalsRequired,
        release_at: r.releaseAt,
        expires_at: r.expiresAt,
        payload: r.payload,
        signature: r.signature,
      });
      if (error) throw error;
    },

    async getDecision(workspaceId, id) {
      const { data, error } = await client().from('gate_decisions').select('*').eq('id', id).eq('workspace_id', workspaceId).maybeSingle();
      if (error) throw error;
      if (!data) return null;
      const { data: rows, error: e2 } = await client()
        .from('gate_approvals')
        .select('approver,created_at')
        .eq('decision_id', id)
        .order('created_at', { ascending: true });
      if (e2) throw e2;
      const approvals = (rows as { approver: string; created_at: string }[]).map((a) => ({ approver: a.approver, at: a.created_at }));
      return { record: toDecision(data as DecisionRow), approvals };
    },

    async addApproval(_workspaceId, id, { approver, apiKeyId }) {
      const { error } = await client().from('gate_approvals').insert({ decision_id: id, approver, api_key_id: apiKeyId });
      if (error?.code === '23505') return 'duplicate'; // unique violation
      if (error) throw error;
      return 'ok';
    },

    async closeDecision(workspaceId, id, status) {
      const { data, error } = await client()
        .from('gate_decisions')
        .update({ status, consumed_at: status === 'consumed' ? new Date().toISOString() : null })
        .eq('id', id)
        .eq('workspace_id', workspaceId)
        .eq('status', 'open')
        .select('id');
      if (error) throw error;
      return (data?.length ?? 0) > 0;
    },

    async insertWebhook({ workspaceId, url, description, secretEnc }) {
      const { data, error } = await client().from('webhooks').insert({ workspace_id: workspaceId, url, description, secret_enc: secretEnc }).select('*').single();
      if (error) throw error;
      return toWebhook(data as WebhookRow);
    },
    async listWebhooks(workspaceId) {
      const { data, error } = await client().from('webhooks').select('*').eq('workspace_id', workspaceId).order('created_at', { ascending: false });
      if (error) throw error;
      return (data as WebhookRow[]).map(toWebhook);
    },
    async getWebhook(workspaceId, id) {
      const { data, error } = await client().from('webhooks').select('*').eq('workspace_id', workspaceId).eq('id', id).maybeSingle();
      if (error) throw error;
      return data ? toWebhook(data as WebhookRow) : null;
    },
    async deleteWebhook(workspaceId, id) {
      const { data, error } = await client().from('webhooks').delete().eq('workspace_id', workspaceId).eq('id', id).select('id');
      if (error) throw error;
      return (data?.length ?? 0) > 0; // playbooks go with it (on delete cascade)
    },
    async insertPlaybook(p) {
      const { data, error } = await client()
        .from('playbooks')
        .insert({ workspace_id: p.workspaceId, name: p.name, triggers: p.triggers, subjects: p.subjects, webhook_id: p.webhookId, kind: p.kind, agent_ids: p.agentIds, cooldown_seconds: p.cooldownSeconds })
        .select('*')
        .single();
      if (error) throw error;
      return toPlaybook(data as PlaybookRow);
    },
    async listPlaybooks(workspaceId) {
      const { data, error } = await client().from('playbooks').select('*').eq('workspace_id', workspaceId).order('created_at', { ascending: true });
      if (error) throw error;
      return (data as PlaybookRow[]).map(toPlaybook);
    },
    async deletePlaybook(workspaceId, id) {
      const { data, error } = await client().from('playbooks').delete().eq('workspace_id', workspaceId).eq('id', id).select('id');
      if (error) throw error;
      return (data?.length ?? 0) > 0;
    },
    async hasRecentRun(workspaceId, playbookId, subject, trigger, since) {
      const { data, error } = await client()
        .from('response_runs')
        .select('id')
        .eq('workspace_id', workspaceId)
        .eq('playbook_id', playbookId)
        .eq('trigger', trigger)
        .ilike('subject', subject.replace(/[\\%_]/g, (m) => `\\${m}`))
        .in('status', ['pending', 'delivered'])
        .gte('created_at', since.toISOString())
        .limit(1);
      if (error) throw error;
      return (data?.length ?? 0) > 0;
    },
    async insertRun(r) {
      const { error } = await client().from('response_runs').insert({
        id: r.id,
        workspace_id: r.workspaceId,
        playbook_id: r.playbookId,
        webhook_id: r.webhookId,
        trigger: r.trigger,
        subject: r.subject,
        event_type: r.eventType,
        payload: r.payload,
      });
      if (error) throw error;
    },
    async finishRun(workspaceId, id, r) {
      const { error } = await client()
        .from('response_runs')
        .update({ status: r.ok ? 'delivered' : 'failed', attempts: r.attempts, http_status: r.httpStatus, error: r.error, finished_at: new Date().toISOString() })
        .eq('workspace_id', workspaceId)
        .eq('id', id);
      if (error) throw error;
    },
    async listRuns(workspaceId, limit) {
      const { data, error } = await client().from('response_runs').select('*').eq('workspace_id', workspaceId).order('created_at', { ascending: false }).limit(limit);
      if (error) throw error;
      return (data as RunRow[]).map((r) => ({ id: r.id, playbookId: r.playbook_id, webhookId: r.webhook_id, trigger: r.trigger, subject: r.subject, eventType: r.event_type, status: r.status, attempts: r.attempts, httpStatus: r.http_status, error: r.error, createdAt: r.created_at, finishedAt: r.finished_at }));
    },
  };
}
