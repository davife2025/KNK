import { z } from 'zod';

/** Kill-chain stages, in the order an attack tends to progress. */
export const Stage = z.enum(['initial_access', 'credential_access', 'privilege_escalation', 'signing_path']);
export type Stage = z.infer<typeof Stage>;

export const EventKind = z.enum([
  'untrusted_repo_opened',
  'install_script_executed',
  'unverified_installer_used',
  'artifact_verdict',
  'credential_read',
  'deploy_token_on_disk',
  'ai_tool_permission_change',
  'ai_tool_cross_host_action',
  'signing_request',
]);
export type EventKind = z.infer<typeof EventKind>;

export const EVENT_STAGE: Record<EventKind, Stage> = {
  untrusted_repo_opened: 'initial_access',
  install_script_executed: 'initial_access',
  unverified_installer_used: 'initial_access',
  artifact_verdict: 'initial_access',
  credential_read: 'credential_access',
  deploy_token_on_disk: 'credential_access',
  ai_tool_permission_change: 'privilege_escalation',
  ai_tool_cross_host_action: 'privilege_escalation',
  signing_request: 'signing_path',
};

export const TrustLevel = z.enum(['normal', 'watch', 'elevated', 'critical']);
export type TrustLevel = z.infer<typeof TrustLevel>;

const Attr = z.union([z.string().max(200), z.number(), z.boolean()]);
/** Metadata only: events describe what happened, never carry file or code content. */
export const EventAttrs = z
  .record(z.string().min(1).max(40), Attr)
  .refine((r) => Object.keys(r).length <= 20, 'at most 20 attributes');
export type EventAttrs = z.infer<typeof EventAttrs>;

export const EventInput = z.object({
  subject: z.string().trim().min(1).max(120),
  kind: EventKind,
  occurredAt: z.iso.datetime({ offset: true }).optional(),
  attrs: EventAttrs.default({}),
});
export type EventInput = z.infer<typeof EventInput>;

export const IngestRequest = z.object({ events: z.array(EventInput).min(1).max(100) });
export type IngestRequest = z.infer<typeof IngestRequest>;

export const TrustContribution = z.object({
  eventId: z.string(),
  kind: EventKind,
  stage: Stage,
  weight: z.number(),
  decayedWeight: z.number(),
});

export const TrustState = z.object({
  subject: z.string(),
  risk: z.number().int().min(0).max(100),
  level: TrustLevel,
  chain: z.object({ length: z.number().int(), stages: z.array(Stage) }),
  contributions: z.array(TrustContribution),
  reasons: z.array(z.string()),
  eventCount: z.number().int(),
  windowDays: z.number(),
  computedAt: z.string(),
});
export type TrustState = z.infer<typeof TrustState>;

export const IngestResponse = z.object({ accepted: z.number().int(), subjects: z.array(TrustState) });
export type IngestResponse = z.infer<typeof IngestResponse>;

export const TrustListResponse = z.object({ subjects: z.array(TrustState) });
export type TrustListResponse = z.infer<typeof TrustListResponse>;
