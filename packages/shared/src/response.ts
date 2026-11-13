import { z } from 'zod';

export const Trigger = z.enum(['trust.critical', 'gate.blocked', 'gate.held', 'verdict.malicious']);
export type Trigger = z.infer<typeof Trigger>;

export const WebhookEventType = z.enum([...Trigger.options, 'containment.requested', 'webhook.test']);
export type WebhookEventType = z.infer<typeof WebhookEventType>;

export const CreateWebhookRequest = z.object({
  url: z.string().trim().min(1).max(500),
  description: z.string().trim().max(200).optional(),
});
export type CreateWebhookRequest = z.infer<typeof CreateWebhookRequest>;

export const WebhookInfo = z.object({
  id: z.string(),
  url: z.string(),
  description: z.string().nullable(),
  createdAt: z.string(),
});
export type WebhookInfo = z.infer<typeof WebhookInfo>;

/** `secret` is the signing secret. It is returned exactly once, at creation. */
export const CreatedWebhook = WebhookInfo.extend({ secret: z.string() });
export type CreatedWebhook = z.infer<typeof CreatedWebhook>;

export const CreatePlaybookRequest = z
  .object({
    name: z.string().trim().min(1).max(80),
    triggers: z.array(Trigger).min(1),
    /** Empty means every subject. Matching is case-insensitive. */
    subjects: z.array(z.string().max(120)).max(100).default([]),
    webhookId: z.string().min(1),
    /** `containment` asks the customer's backend to cut off agent access; `alert` only notifies. */
    kind: z.enum(['alert', 'containment']).default('alert'),
    agentIds: z.array(z.string().min(1).max(120)).max(50).default([]),
    /** No repeat for the same playbook, subject and trigger inside this window. */
    cooldownSeconds: z.number().int().min(0).max(86_400).default(600),
  })
  .refine((p) => p.kind !== 'containment' || p.agentIds.length > 0, {
    message: 'agentIds is required for a containment playbook',
    path: ['agentIds'],
  });
export type CreatePlaybookRequest = z.infer<typeof CreatePlaybookRequest>;

export const Playbook = z.object({
  id: z.string(),
  name: z.string(),
  enabled: z.boolean(),
  triggers: z.array(Trigger),
  subjects: z.array(z.string()),
  webhookId: z.string(),
  kind: z.enum(['alert', 'containment']),
  agentIds: z.array(z.string()),
  cooldownSeconds: z.number().int(),
  createdAt: z.string(),
});
export type Playbook = z.infer<typeof Playbook>;

/** What a webhook receiver gets (JSON body). Verify the signature header before trusting it. */
export const WebhookEnvelope = z.object({
  id: z.string(),
  type: WebhookEventType,
  createdAt: z.string(),
  workspaceId: z.string(),
  data: z.record(z.string(), z.unknown()),
});
export type WebhookEnvelope = z.infer<typeof WebhookEnvelope>;

export const ContainmentAction = z.enum(['revoke_grants', 'prepare_freeze']);
export type ContainmentAction = z.infer<typeof ContainmentAction>;

export const ContainmentData = z.object({
  incidentId: z.string(),
  trigger: Trigger,
  subject: z.string(),
  reasons: z.array(z.string()),
  agentIds: z.array(z.string()),
  actions: z.array(ContainmentAction),
});
export type ContainmentData = z.infer<typeof ContainmentData>;

export const ResponseRun = z.object({
  id: z.string(),
  playbookId: z.string().nullable(),
  webhookId: z.string().nullable(),
  trigger: z.string(),
  subject: z.string(),
  eventType: z.string(),
  status: z.enum(['pending', 'delivered', 'failed']),
  attempts: z.number().int(),
  httpStatus: z.number().int().nullable(),
  error: z.string().nullable(),
  createdAt: z.string(),
  finishedAt: z.string().nullable(),
});
export type ResponseRun = z.infer<typeof ResponseRun>;

export const WEBHOOK_HEADERS = {
  signature: 'knk-signature',
  event: 'knk-event',
  delivery: 'knk-delivery',
} as const;
