import { randomUUID } from 'node:crypto';
import type { ContainmentData, Trigger, TrustState, WebhookEnvelope } from '@knk/shared';
import type { Store } from '../store/types.js';
import type { DeliveryResult, Dispatcher } from './dispatcher.js';
import type { SecretBox } from './secret-box.js';
import { getDefaultSecretBox } from './secret-box.js';
import { createDispatcher } from './dispatcher.js';
import type { Resolver, UrlPolicy } from './ssrf.js';
import { getEnv } from '../env.js';

/**
 * Turns incidents into signed webhooks. Runs in the background so a slow receiver can never delay
 * ingestion or a signing decision. KNK never holds the customer's Agent API key or grant tokens:
 * a containment playbook only asks the customer's own backend (via @knk/guard) to cut off access.
 */
export class ResponseEngine {
  private pending = new Set<Promise<void>>();

  constructor(
    private deps: { store: Store; dispatcher: Dispatcher; box: () => SecretBox | null; now?: () => Date },
  ) {}

  fire(workspaceId: string, trigger: Trigger, subject: string, data: Record<string, unknown>): void {
    const p: Promise<void> = this.run(workspaceId, trigger, subject, data)
      .catch((e) => console.error('response engine', e))
      .finally(() => this.pending.delete(p));
    this.pending.add(p);
  }

  /** Resolves when every in-flight response has finished (used by tests and graceful shutdown). */
  async idle(): Promise<void> {
    while (this.pending.size > 0) await Promise.all([...this.pending]);
  }

  private async run(workspaceId: string, trigger: Trigger, subject: string, data: Record<string, unknown>): Promise<void> {
    const { store, dispatcher } = this.deps;
    const now = this.deps.now?.() ?? new Date();
    const lower = subject.toLowerCase();
    const playbooks = (await store.listPlaybooks(workspaceId)).filter(
      (p) => p.enabled && p.triggers.includes(trigger) && (p.subjects.length === 0 || p.subjects.some((s) => s.toLowerCase() === lower)),
    );

    for (const p of playbooks) {
      // A failed delivery does not suppress the next attempt; pending and delivered ones do.
      if (p.cooldownSeconds > 0 && (await store.hasRecentRun(workspaceId, p.id, subject, trigger, new Date(now.getTime() - p.cooldownSeconds * 1000)))) continue;

      const incidentId = randomUUID();
      const reasons = Array.isArray(data.reasons) ? data.reasons.filter((r): r is string => typeof r === 'string').slice(0, 10) : [trigger];
      const containment = p.kind === 'containment';
      const envelope: WebhookEnvelope = {
        id: randomUUID(),
        type: containment ? 'containment.requested' : trigger,
        createdAt: now.toISOString(),
        workspaceId,
        data: containment
          ? ({ incidentId, trigger, subject, reasons, agentIds: p.agentIds, actions: ['revoke_grants', 'prepare_freeze'] } satisfies ContainmentData)
          : { incidentId, trigger, subject, ...data },
      };
      const runId = randomUUID();
      await store.insertRun({ id: runId, workspaceId, playbookId: p.id, webhookId: p.webhookId, trigger, subject, eventType: envelope.type, payload: envelope });

      const hook = await store.getWebhook(workspaceId, p.webhookId);
      const box = this.deps.box();
      if (!hook || !box) {
        await store.finishRun(workspaceId, runId, { ok: false, attempts: 0, httpStatus: null, error: !hook ? 'webhook_missing' : 'encryption_not_configured' });
        continue;
      }
      let result: DeliveryResult;
      try {
        result = await dispatcher.deliver({ url: hook.url, secret: box.decrypt(hook.secretEnc) }, envelope);
      } catch {
        result = { ok: false, attempts: 0, httpStatus: null, error: 'dispatch_error' }; // e.g. the secret can no longer be decrypted
      }
      await store.finishRun(workspaceId, runId, result);
    }
  }
}

/** Fires `trust.critical` only on the transition into critical, not on every event while already critical. */
export function fireTrustCritical(engine: ResponseEngine, workspaceId: string, before: TrustState[], after: TrustState[]): void {
  for (const s of after) {
    if (s.level !== 'critical') continue;
    if (before.find((b) => b.subject === s.subject)?.level === 'critical') continue;
    engine.fire(workspaceId, 'trust.critical', s.subject, { risk: s.risk, level: s.level, reasons: s.reasons, chain: s.chain });
  }
}

export interface ResponseKit {
  engine: ResponseEngine;
  dispatcher: Dispatcher;
  box: () => SecretBox | null;
  urlPolicy: UrlPolicy;
}

export function createResponseKit(
  store: Store,
  o: { box?: () => SecretBox | null; dispatcher?: Dispatcher; allowPrivate?: boolean; resolve?: Resolver } = {},
): ResponseKit {
  const allowPrivate = o.allowPrivate ?? getEnv().KNK_ALLOW_PRIVATE_WEBHOOKS;
  const dispatcher = o.dispatcher ?? createDispatcher({ allowPrivate, resolve: o.resolve });
  const box = o.box ?? getDefaultSecretBox;
  return { engine: new ResponseEngine({ store, dispatcher, box }), dispatcher, box, urlPolicy: { allowPrivate, resolve: o.resolve } };
}
