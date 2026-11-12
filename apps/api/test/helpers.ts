import { randomUUID } from 'node:crypto';
import type { KeyRecord, Store, UsageRecord, UsageRow, AuditEntry } from '../src/store/types.js';

/** In-memory Store so route and auth behaviour can be tested without Supabase. */
export function memoryStore() {
  const workspaces = new Map<string, { id: string; name: string }>();
  const keys = new Map<string, KeyRecord>();
  const usage: UsageRecord[] = [];
  const audits: AuditEntry[] = [];

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
  };
  return { store, usage, audits };
}
