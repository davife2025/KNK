import { randomUUID } from 'node:crypto';
import type { SignedVerdict } from '@knk/shared';
import { PolicyRules } from '@knk/shared';
import type { Playbook, ResponseRun } from '@knk/shared';
import type { NewRun, RunResult, WebhookRecord, ApprovalRecord, DecisionRecord, KeyRecord, Store, StoredEvent, UsageRecord, UsageRow, AuditEntry } from '../src/store/types.js';

/** In-memory Store so route and auth behaviour can be tested without Supabase. */
export function memoryStore() {
  const workspaces = new Map<string, { id: string; name: string }>();
  const keys = new Map<string, KeyRecord>();
  const usage: UsageRecord[] = [];
  const audits: AuditEntry[] = [];
  const verdicts = new Map<string, SignedVerdict>();
  const events: (StoredEvent & { workspaceId: string })[] = [];
  const policies = new Map<string, { rules: PolicyRules; updatedAt: string }>();
  const decisions = new Map<string, DecisionRecord>();
  const approvals = new Map<string, (ApprovalRecord & { apiKeyId: string })[]>();
  const webhooks = new Map<string, WebhookRecord>();
  const playbooks = new Map<string, Playbook & { workspaceId: string }>();
  const runs = new Map<string, ResponseRun & { workspaceId: string; payload: NewRun['payload'] }>();

  const mkKey = (i: Omit<KeyRecord, 'id' | 'createdAt' | 'lastUsedAt' | 'revokedAt'>): KeyRecord => {
    const rec: KeyRecord = { ...i, id: randomUUID(), createdAt: new Date().toISOString(), lastUsedAt: null, revokedAt: null };
    keys.set(rec.id, rec);
    return rec;
  };

  const store: Store = {
    async createWorkspace({ name, prefix, keyHash, scopes }) {
      const workspace = { id: randomUUID(), name };
      workspaces.set(workspace.id, workspace);
      return { workspace, key: mkKey({ workspaceId: workspace.id, name: 'Default', prefix, keyHash, scopes }) };
    },
    async getWorkspace(id) {
      return workspaces.get(id) ?? null;
    },
    async findKeyByPrefix(prefix) {
      return [...keys.values()].find((k) => k.prefix === prefix) ?? null;
    },
    async touchKey(id) {
      const k = keys.get(id);
      if (k) k.lastUsedAt = new Date().toISOString();
    },
    async listKeys(workspaceId) {
      return [...keys.values()].filter((k) => k.workspaceId === workspaceId);
    },
    async insertKey(input) {
      return mkKey(input);
    },
    async revokeKey(workspaceId, id) {
      const k = keys.get(id);
      if (!k || k.workspaceId !== workspaceId || k.revokedAt) return false;
      k.revokedAt = new Date().toISOString();
      return true;
    },
    async recordUsage(rec) {
      usage.push(rec);
    },
    async usageSummary(workspaceId): Promise<UsageRow[]> {
      const by = new Map<string, UsageRow>();
      for (const u of usage.filter((x) => x.workspaceId === workspaceId)) {
        const row = by.get(u.endpoint) ?? { endpoint: u.endpoint, requests: 0, units: 0 };
        row.requests += 1;
        row.units += u.units;
        by.set(u.endpoint, row);
      }
      return [...by.values()];
    },
    async audit(entry) {
      audits.push(entry);
    },
    async insertVerdict(v) {
      verdicts.set(v.payload.id, { ...v, alg: 'Ed25519' });
    },
    async getVerdict(workspaceId, id) {
      const v = verdicts.get(id);
      return v && v.payload.workspaceId === workspaceId ? v : null;
    },
    async insertEvents(workspaceId, list) {
      const stored = list.map((e) => ({ ...e, id: randomUUID(), workspaceId }));
      events.push(...stored);
      return stored;
    },
    async listEvents(workspaceId, { since, subject, limit }) {
      return events
        .filter((e) => e.workspaceId === workspaceId && Date.parse(e.occurredAt) >= since.getTime() && (!subject || e.subject === subject))
        .slice(0, limit);
    },
    async getPolicy(workspaceId) {
      return policies.get(workspaceId) ?? null;
    },
    async setPolicy(workspaceId, rules) {
      const updatedAt = new Date().toISOString();
      policies.set(workspaceId, { rules: PolicyRules.parse(rules), updatedAt });
      return { updatedAt };
    },
    async insertDecision(rec) {
      decisions.set(rec.id, { ...rec, status: 'open', createdAt: new Date().toISOString() });
    },
    async getDecision(workspaceId, id) {
      const record = decisions.get(id);
      if (!record || record.workspaceId !== workspaceId) return null;
      return { record: { ...record }, approvals: (approvals.get(id) ?? []).map(({ approver, at }) => ({ approver, at })) };
    },
    async addApproval(_ws, id, { approver, apiKeyId }) {
      const list = approvals.get(id) ?? [];
      if (list.some((a) => a.approver.toLowerCase() === approver.toLowerCase() || a.apiKeyId === apiKeyId)) return 'duplicate';
      approvals.set(id, [...list, { approver, apiKeyId, at: new Date().toISOString() }]);
      return 'ok';
    },
    async closeDecision(workspaceId, id, status) {
      const d = decisions.get(id);
      if (!d || d.workspaceId !== workspaceId || d.status !== 'open') return false;
      d.status = status;
      return true;
    },
    async insertWebhook({ workspaceId, url, description, secretEnc }) {
      const rec = { id: randomUUID(), workspaceId, url, description, secretEnc, createdAt: new Date().toISOString() };
      webhooks.set(rec.id, rec);
      return rec;
    },
    async listWebhooks(workspaceId) {
      return [...webhooks.values()].filter((w) => w.workspaceId === workspaceId);
    },
    async getWebhook(workspaceId, id) {
      const w = webhooks.get(id);
      return w && w.workspaceId === workspaceId ? w : null;
    },
    async deleteWebhook(workspaceId, id) {
      const w = webhooks.get(id);
      if (!w || w.workspaceId !== workspaceId) return false;
      webhooks.delete(id);
      for (const [pid, p] of playbooks) if (p.webhookId === id) playbooks.delete(pid);
      return true;
    },
    async insertPlaybook(p) {
      const rec = { id: randomUUID(), enabled: true, createdAt: new Date().toISOString(), ...p };
      playbooks.set(rec.id, rec);
      const { workspaceId: _w, ...pub } = rec;
      return pub;
    },
    async listPlaybooks(workspaceId) {
      return [...playbooks.values()].filter((p) => p.workspaceId === workspaceId).map(({ workspaceId: _w, ...pub }) => pub);
    },
    async deletePlaybook(workspaceId, id) {
      const p = playbooks.get(id);
      if (!p || p.workspaceId !== workspaceId) return false;
      playbooks.delete(id);
      return true;
    },
    async hasRecentRun(workspaceId, playbookId, subject, trigger, since) {
      return [...runs.values()].some(
        (r) => r.workspaceId === workspaceId && r.playbookId === playbookId && r.trigger === trigger && r.subject.toLowerCase() === subject.toLowerCase() && (r.status === 'pending' || r.status === 'delivered') && Date.parse(r.createdAt) >= since.getTime(),
      );
    },
    async insertRun(r) {
      runs.set(r.id, { id: r.id, workspaceId: r.workspaceId, playbookId: r.playbookId, webhookId: r.webhookId, trigger: r.trigger, subject: r.subject, eventType: r.eventType, status: 'pending', attempts: 0, httpStatus: null, error: null, createdAt: new Date().toISOString(), finishedAt: null, payload: r.payload });
    },
    async finishRun(workspaceId, id, res: RunResult) {
      const r = runs.get(id);
      if (r && r.workspaceId === workspaceId) Object.assign(r, { status: res.ok ? 'delivered' : 'failed', attempts: res.attempts, httpStatus: res.httpStatus, error: res.error, finishedAt: new Date().toISOString() });
    },
    async listRuns(workspaceId, limit) {
      return [...runs.values()].filter((r) => r.workspaceId === workspaceId).slice(-limit).reverse().map(({ workspaceId: _w, payload: _p, ...pub }) => pub);
    },
  };
  return { store, usage, audits, verdicts, events, decisions, webhooks, playbooks, runs };
}
