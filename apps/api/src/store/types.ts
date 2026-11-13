import type { Playbook, ResponseRun, Trigger, WebhookEnvelope, DecodedTx, EventAttrs, EventKind, GateDecisionPayload, GateHit, Outcome, PolicyRules, Scope, SignedVerdict, TrustLevel } from '@knk/shared';
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

export interface DecisionRecord {
  id: string;
  workspaceId: string;
  subject: string;
  wallet: string;
  decision: Outcome;
  fingerprint: string;
  kind: string;
  summary: DecodedTx | null;
  hits: GateHit[];
  trustRisk: number;
  trustLevel: TrustLevel;
  approvalsRequired: number;
  releaseAt: string | null;
  expiresAt: string | null;
  status: 'open' | 'rejected' | 'consumed';
  createdAt: string;
  payload: GateDecisionPayload;
  signature: string;
}

export interface ApprovalRecord {
  approver: string;
  at: string;
}

export interface WebhookRecord {
  id: string;
  workspaceId: string;
  url: string;
  description: string | null;
  secretEnc: string;
  createdAt: string;
}

export interface NewPlaybook {
  workspaceId: string;
  name: string;
  triggers: Trigger[];
  subjects: string[];
  webhookId: string;
  kind: 'alert' | 'containment';
  agentIds: string[];
  cooldownSeconds: number;
}

export interface NewRun {
  id: string;
  workspaceId: string;
  playbookId: string | null;
  webhookId: string | null;
  trigger: string;
  subject: string;
  eventType: string;
  payload: WebhookEnvelope;
}

export interface RunResult {
  ok: boolean;
  attempts: number;
  httpStatus: number | null;
  error: string | null;
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
  getPolicy(workspaceId: string): Promise<{ rules: PolicyRules; updatedAt: string } | null>;
  setPolicy(workspaceId: string, rules: PolicyRules): Promise<{ updatedAt: string }>;
  insertDecision(rec: Omit<DecisionRecord, 'status' | 'createdAt'>): Promise<void>;
  getDecision(workspaceId: string, id: string): Promise<{ record: DecisionRecord; approvals: ApprovalRecord[] } | null>;
  /** One approval per approver name and per API key, enforced atomically. */
  addApproval(workspaceId: string, id: string, a: { approver: string; apiKeyId: string }): Promise<'ok' | 'duplicate'>;
  /** Moves an open decision to rejected or consumed. Returns false if it was not open (so consume is single-use). */
  closeDecision(workspaceId: string, id: string, status: 'rejected' | 'consumed'): Promise<boolean>;
  insertWebhook(input: { workspaceId: string; url: string; description: string | null; secretEnc: string }): Promise<WebhookRecord>;
  listWebhooks(workspaceId: string): Promise<WebhookRecord[]>;
  getWebhook(workspaceId: string, id: string): Promise<WebhookRecord | null>;
  /** Also removes the playbooks that use it. */
  deleteWebhook(workspaceId: string, id: string): Promise<boolean>;
  insertPlaybook(input: NewPlaybook): Promise<Playbook>;
  listPlaybooks(workspaceId: string): Promise<Playbook[]>;
  deletePlaybook(workspaceId: string, id: string): Promise<boolean>;
  /** True if a pending or delivered run exists since `since`. Failed runs do not count, so a retry is allowed. */
  hasRecentRun(workspaceId: string, playbookId: string, subject: string, trigger: string, since: Date): Promise<boolean>;
  insertRun(run: NewRun): Promise<void>;
  finishRun(workspaceId: string, id: string, result: RunResult): Promise<void>;
  listRuns(workspaceId: string, limit: number): Promise<ResponseRun[]>;
  listEvents(workspaceId: string, q: { since: Date; subject?: string; limit: number }): Promise<StoredEvent[]>;
}
