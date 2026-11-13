import { ContainmentData, WEBHOOK_HEADERS, WebhookEnvelope } from '@knk/shared';
import { verifyWebhook } from './signature.js';

/**
 * What the customer's backend implements. KNK never holds the customer's Agent API key or grant tokens:
 * these two calls run on the customer's side, where those secrets already live.
 */
export interface AgentGuardAdapter {
  /** Stop using (and delete or disable) every stored grant token for this agent. Instant, no signature needed. */
  revokeGrantTokens(agentId: string): Promise<void>;
  /** Prepare the owner's freeze for signing and tell the owner. The owner's wallet signs it; this cannot freeze alone. */
  prepareFreeze(agentId: string): Promise<{ correlationId: string }>;
}

export interface GuardRequest {
  headers: Record<string, string | string[] | undefined>;
  /** The raw request body exactly as received. Never re-serialise parsed JSON before verifying. */
  body: string;
}
export interface GuardResponse {
  status: number;
  body: Record<string, unknown>;
}

export interface AgentOutcome {
  agentId: string;
  grantsRevoked: boolean;
  freezePrepared: { correlationId: string } | null;
  errors: string[];
}

const header = (h: GuardRequest['headers'], name: string) => {
  const v = h[name] ?? h[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
};

/**
 * Framework-neutral receiver for KNK webhooks. Verifies the signature, then for `containment.requested`
 * cuts off each agent: grants first (instant), then prepares the freeze. Each incident runs once even if KNK retries.
 */
export function createGuardHandler(opts: {
  secret: string;
  adapter: AgentGuardAdapter;
  onEvent?: (e: WebhookEnvelope) => void | Promise<void>;
  toleranceSeconds?: number;
  nowMs?: () => number;
}) {
  const done = new Map<string, AgentOutcome[]>(); // incidentId -> outcome. Swap for durable storage in production.

  return async function handle(req: GuardRequest): Promise<GuardResponse> {
    const verified = verifyWebhook({
      secret: opts.secret,
      body: req.body,
      header: header(req.headers, WEBHOOK_HEADERS.signature),
      toleranceSeconds: opts.toleranceSeconds,
      nowMs: opts.nowMs?.(),
    });
    if (!verified.ok) return { status: 401, body: { error: `signature_${verified.reason}` } };

    let json: unknown;
    try {
      json = JSON.parse(req.body);
    } catch {
      return { status: 400, body: { error: 'invalid_json' } };
    }
    const env = WebhookEnvelope.safeParse(json);
    if (!env.success) return { status: 400, body: { error: 'invalid_envelope' } };
    await opts.onEvent?.(env.data);

    if (env.data.type !== 'containment.requested') return { status: 200, body: { ok: true, handled: false } };
    const data = ContainmentData.safeParse(env.data.data);
    if (!data.success) return { status: 400, body: { error: 'invalid_containment' } };

    const seen = done.get(data.data.incidentId);
    if (seen) return { status: 200, body: { ok: true, duplicate: true, agents: seen } };

    const agents: AgentOutcome[] = [];
    for (const agentId of data.data.agentIds) {
      const out: AgentOutcome = { agentId, grantsRevoked: false, freezePrepared: null, errors: [] };
      if (data.data.actions.includes('revoke_grants')) {
        try {
          await opts.adapter.revokeGrantTokens(agentId);
          out.grantsRevoked = true;
        } catch (e) {
          out.errors.push(`revoke_grants: ${e instanceof Error ? e.message : 'failed'}`);
        }
      }
      if (data.data.actions.includes('prepare_freeze')) {
        try {
          out.freezePrepared = await opts.adapter.prepareFreeze(agentId); // runs even if revoke failed: try both
        } catch (e) {
          out.errors.push(`prepare_freeze: ${e instanceof Error ? e.message : 'failed'}`);
        }
      }
      agents.push(out);
    }
    // Only remember fully successful incidents, so a retry after a partial failure tries again.
    if (agents.every((a) => a.errors.length === 0)) done.set(data.data.incidentId, agents);
    const failed = agents.some((a) => a.errors.length > 0);
    return { status: failed ? 500 : 200, body: { ok: !failed, agents } };
  };
}
