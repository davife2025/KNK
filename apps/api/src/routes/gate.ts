import { randomUUID } from 'node:crypto';
import { Hono } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import {
  ApproveRequest,
  DEFAULT_POLICY,
  GateCheckRequest,
  GateConfirmRequest,
  PolicyRules,
  type ConfirmResponse,
  type GateDecisionPayload,
  type GateDecisionView,
  type PolicyResponse,
} from '@knk/shared';
import { apiError } from '../lib/errors.js';
import { decodeTx, fingerprintTx } from '../lib/evm.js';
import { evaluateGate } from '../lib/gate-policy.js';
import { decisionState } from '../lib/gate-state.js';
import type { ResponseEngine } from '../lib/response.js';
import { getDefaultSigner, type VerdictSigner } from '../lib/signing.js';
import { trustSnapshot } from '../lib/trust-service.js';
import { requireApiKey, requireScope, type AppEnv } from '../middleware/auth.js';
import { meterUsage } from '../middleware/usage.js';
import type { ApprovalRecord, DecisionRecord, Store } from '../store/types.js';

const ALLOW_TTL_SECONDS = 300; // an immediate "allow" must be used within 5 minutes

const issues = (e: { issues: { path: PropertyKey[]; message: string }[] }) =>
  e.issues.map((i) => `${i.path.join('.') || 'body'}: ${i.message}`).join('; ');

export function gateRoutes(deps: { store: Store; engine: ResponseEngine; signer?: VerdictSigner | null }): Hono<AppEnv> {
  const { store } = deps;
  const r = new Hono<AppEnv>();
  for (const path of ['/v1/gate/*', '/v1/policy']) r.use(path, requireApiKey(store), meterUsage(store));
  const limit = bodyLimit({ maxSize: 128 * 1024, onError: (c) => apiError(c, 413, 'payload_too_large', 'Request body is too large') });

  const view = (rec: DecisionRecord, approvals: ApprovalRecord[], now = new Date()): GateDecisionView => ({
    payload: rec.payload,
    signature: rec.signature,
    alg: 'Ed25519',
    state: decisionState(rec, approvals.length, now),
    reasons: rec.hits,
    approvals,
    decoded: rec.summary,
  });

  // ---- policy ----
  r.get('/v1/policy', requireScope('gate:check'), async (c) => {
    const stored = await store.getPolicy(c.get('auth').workspaceId);
    const out: PolicyResponse = stored
      ? { rules: stored.rules, source: 'custom', updatedAt: stored.updatedAt }
      : { rules: DEFAULT_POLICY, source: 'default', updatedAt: null };
    return c.json(out);
  });

  r.put('/v1/policy', requireScope('admin'), limit, async (c) => {
    const body = PolicyRules.safeParse(await c.req.json().catch(() => null));
    if (!body.success) return apiError(c, 400, 'invalid_request', issues(body.error));
    const auth = c.get('auth');
    const { updatedAt } = await store.setPolicy(auth.workspaceId, body.data);
    await store.audit({ workspaceId: auth.workspaceId, actor: `key:${auth.keyPrefix}`, action: 'policy.updated' });
    const out: PolicyResponse = { rules: body.data, source: 'custom', updatedAt };
    return c.json(out);
  });

  // ---- check: ask before signing ----
  r.post('/v1/gate/check', requireScope('gate:check'), limit, async (c) => {
    const body = GateCheckRequest.safeParse(await c.req.json().catch(() => null));
    if (!body.success) return apiError(c, 400, 'invalid_request', issues(body.error));
    const signer = deps.signer === undefined ? getDefaultSigner() : deps.signer;
    if (!signer) return apiError(c, 503, 'signing_not_configured', 'Decision signing is not configured');

    const { subject, wallet, tx } = body.data;
    const { workspaceId } = c.get('auth');
    const policy = (await store.getPolicy(workspaceId))?.rules ?? DEFAULT_POLICY;
    const [trust] = await trustSnapshot(store, workspaceId, { subjects: [subject] });

    const decoded = decodeTx(tx);
    const evaluation = evaluateGate({
      decoded: decoded.ok ? decoded.tx : null,
      decodeError: decoded.ok ? undefined : decoded.reason,
      trust: trust!,
      policy,
    });

    const now = new Date();
    const releaseAt = evaluation.decision === 'hold' ? new Date(now.getTime() + policy.timelockSeconds * 1000) : null;
    const expiresAt =
      evaluation.decision === 'hold' && releaseAt
        ? new Date(releaseAt.getTime() + policy.confirmWindowSeconds * 1000)
        : evaluation.decision === 'allow'
          ? new Date(now.getTime() + ALLOW_TTL_SECONDS * 1000)
          : null;

    const payload: GateDecisionPayload = {
      id: randomUUID(),
      workspaceId,
      subject,
      wallet,
      decision: evaluation.decision,
      fingerprint: fingerprintTx(tx),
      kind: decoded.ok ? decoded.tx.kind : 'undecodable',
      trustRisk: trust!.risk,
      trustLevel: trust!.level,
      rules: evaluation.hits.map((h) => h.rule),
      approvalsRequired: policy.approvalsRequired,
      issuedAt: now.toISOString(),
      releaseAt: releaseAt?.toISOString() ?? null,
      expiresAt: expiresAt?.toISOString() ?? null,
      keyId: signer.keyId,
    };
    const signature = signer.sign(payload);
    const rec = {
      id: payload.id,
      workspaceId,
      subject,
      wallet,
      decision: payload.decision,
      fingerprint: payload.fingerprint,
      kind: payload.kind,
      summary: decoded.ok ? decoded.tx : null,
      hits: evaluation.hits,
      trustRisk: payload.trustRisk,
      trustLevel: payload.trustLevel,
      approvalsRequired: payload.approvalsRequired,
      releaseAt: payload.releaseAt,
      expiresAt: payload.expiresAt,
      payload,
      signature,
    };
    await store.insertDecision(rec);
    // Closes the loop: the signing request itself becomes an event (neutral weight) for this subject.
    await store.insertEvents(workspaceId, [
      { subject, kind: 'signing_request', attrs: { wallet, format: tx.format, kind: payload.kind, decision: payload.decision }, occurredAt: payload.issuedAt },
    ]);
    if (payload.decision !== 'allow') {
      deps.engine.fire(workspaceId, payload.decision === 'block' ? 'gate.blocked' : 'gate.held', subject, {
        decisionId: payload.id,
        wallet,
        kind: payload.kind,
        trustLevel: payload.trustLevel,
        trustRisk: payload.trustRisk,
        rules: payload.rules,
        reasons: evaluation.hits.map((h) => h.reason),
      });
    }
    return c.json(view({ ...rec, status: 'open', createdAt: payload.issuedAt }, [], now));
  });

  const load = async (workspaceId: string, id: string) => store.getDecision(workspaceId, id);

  r.get('/v1/gate/decisions/:id', requireScope('gate:check'), async (c) => {
    const found = await load(c.get('auth').workspaceId, c.req.param('id'));
    if (!found) return apiError(c, 404, 'not_found', 'Decision not found');
    return c.json(view(found.record, found.approvals));
  });

  // ---- approve / reject (humans, admin scope) ----
  r.post('/v1/gate/decisions/:id/approve', requireScope('admin'), async (c) => {
    const body = ApproveRequest.safeParse(await c.req.json().catch(() => null));
    if (!body.success) return apiError(c, 400, 'invalid_request', issues(body.error));
    const auth = c.get('auth');
    const found = await load(auth.workspaceId, c.req.param('id'));
    if (!found) return apiError(c, 404, 'not_found', 'Decision not found');
    const { record, approvals } = found;

    const state = decisionState(record, approvals.length, new Date());
    if (record.decision !== 'hold') return apiError(c, 409, 'not_holdable', 'Only held decisions can be approved');
    if (state === 'rejected' || state === 'consumed' || state === 'expired') return apiError(c, 409, 'not_open', `This decision is ${state}`);
    if (body.data.approver.toLowerCase() === record.subject.toLowerCase()) {
      return apiError(c, 403, 'self_approval', 'The requester cannot approve their own request');
    }
    const added = await store.addApproval(auth.workspaceId, record.id, { approver: body.data.approver, apiKeyId: auth.apiKeyId });
    if (added === 'duplicate') return apiError(c, 409, 'duplicate_approval', 'This approver or API key has already approved');
    await store.audit({ workspaceId: auth.workspaceId, actor: `key:${auth.keyPrefix}`, action: 'gate.approved', target: record.id, meta: { approver: body.data.approver } });

    const after = await load(auth.workspaceId, record.id);
    return c.json(view(after!.record, after!.approvals));
  });

  r.post('/v1/gate/decisions/:id/reject', requireScope('admin'), async (c) => {
    const body = ApproveRequest.safeParse(await c.req.json().catch(() => null));
    if (!body.success) return apiError(c, 400, 'invalid_request', issues(body.error));
    const auth = c.get('auth');
    const closed = await store.closeDecision(auth.workspaceId, c.req.param('id'), 'rejected');
    if (!closed) return apiError(c, 409, 'not_open', 'Decision not found or no longer open');
    await store.audit({ workspaceId: auth.workspaceId, actor: `key:${auth.keyPrefix}`, action: 'gate.rejected', target: c.req.param('id'), meta: { approver: body.data.approver } });
    const after = await load(auth.workspaceId, c.req.param('id'));
    return c.json(view(after!.record, after!.approvals));
  });

  // ---- confirm: the signer asks one last time, right before signing ----
  r.post('/v1/gate/decisions/:id/confirm', requireScope('gate:check'), limit, async (c) => {
    const body = GateConfirmRequest.safeParse(await c.req.json().catch(() => null));
    if (!body.success) return apiError(c, 400, 'invalid_request', issues(body.error));
    const { workspaceId } = c.get('auth');
    const found = await load(workspaceId, c.req.param('id'));
    if (!found) return apiError(c, 404, 'not_found', 'Decision not found');
    const { record, approvals } = found;

    const state = decisionState(record, approvals.length, new Date());
    const no = (reason: string): Response => c.json({ proceed: false, reason, state } satisfies ConfirmResponse);

    // The server fingerprints what the signer is about to sign, so a swapped transaction cannot ride an old approval.
    if (fingerprintTx(body.data.tx) !== record.fingerprint) return no('fingerprint_mismatch');
    if (state !== 'released') return no(state);

    // Time of use: trust may have collapsed since the decision was made.
    const policy = (await store.getPolicy(workspaceId))?.rules ?? DEFAULT_POLICY;
    const [trust] = await trustSnapshot(store, workspaceId, { subjects: [record.subject] });
    if (trust!.level !== 'normal' && policy.trust[trust!.level] === 'block') return no('trust_degraded');

    if (!(await store.closeDecision(workspaceId, record.id, 'consumed'))) return no('consumed'); // single use
    return c.json({ proceed: true, reason: 'released', state: 'consumed' } satisfies ConfirmResponse);
  });

  return r;
}
