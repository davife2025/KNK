import type { EventAttrs, EventKind, Scope, SignedVerdict } from '@knk/shared';
import type { TrustEvent } from '../lib/trust.js';

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

export type StoredEvent = TrustEvent;

export interface NewEvent {
  subject: string;
  kind: EventKind;
  attrs: EventAttrs;
  occurredAt: string;
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
  insertVerdict(v: Omit<SignedVerdict, 'alg'>): Promise<void>;
  getVerdict(workspaceId: string, id: string): Promise<SignedVerdict | null>;
  insertEvents(workspaceId: string, events: NewEvent[]): Promise<StoredEvent[]>;
  listEvents(workspaceId: string, q: { since: Date; subject?: string; limit: number }): Promise<StoredEvent[]>;
}
