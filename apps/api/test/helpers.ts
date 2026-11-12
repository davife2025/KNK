import { randomUUID } from 'node:crypto';
import type { SignedVerdict } from '@knk/shared';
import { PolicyRules } from '@knk/shared';
import type { ApprovalRecord, DecisionRecord, KeyRecord, Store, StoredEvent, UsageRecord, UsageRow, AuditEntry } from '../src/store/types.js';

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
  };
  return { store, usage, audits, verdicts, events, decisions };
}
