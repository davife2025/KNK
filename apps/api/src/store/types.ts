import type { Scope } from '@knk/shared';

export interface KeyRecord {
  id: string;
  workspaceId: string;
  name: string;
  prefix: string;
  keyHash: string;
  scopes: Scope[];
  createdAt: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
}

export interface NewKey {
  workspaceId: string;
  name: string;
  prefix: string;
  keyHash: string;
  scopes: Scope[];
}

export interface AuditEntry {
  workspaceId: string;
  actor: string;
  action: string;
  target?: string;
  meta?: Record<string, unknown>;
}

export interface UsageRecord {
  workspaceId: string;
  apiKeyId: string;
  endpoint: string;
  units: number;
}

export interface UsageRow {
  endpoint: string;
  requests: number;
  units: number;
}

/** All persistence the API needs. Supabase in production, in-memory in tests. */
export interface Store {
  createWorkspace(input: {
    name: string;
    prefix: string;
    keyHash: string;
    scopes: Scope[];
  }): Promise<{ workspace: { id: string; name: string }; key: KeyRecord }>;
  getWorkspace(id: string): Promise<{ id: string; name: string } | null>;
  findKeyByPrefix(prefix: string): Promise<KeyRecord | null>;
  touchKey(id: string): Promise<void>;
  listKeys(workspaceId: string): Promise<KeyRecord[]>;
  insertKey(input: NewKey): Promise<KeyRecord>;
  revokeKey(workspaceId: string, id: string): Promise<boolean>;
  recordUsage(rec: UsageRecord): Promise<void>;
  usageSummary(workspaceId: string, since: Date): Promise<UsageRow[]>;
  audit(entry: AuditEntry): Promise<void>;
}
