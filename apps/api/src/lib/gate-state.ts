import type { GateState } from '@knk/shared';
import type { DecisionRecord } from '../store/types.js';

/** "released" means the signer may proceed, exactly once, by calling confirm. */
export function decisionState(
  r: Pick<DecisionRecord, 'decision' | 'status' | 'approvalsRequired' | 'releaseAt' | 'expiresAt'>,
  approvals: number,
  now: Date,
): GateState {
  if (r.status === 'rejected') return 'rejected';
  if (r.status === 'consumed') return 'consumed';
  if (r.decision === 'block') return 'blocked';
  const t = now.getTime();
  if (r.expiresAt && t > Date.parse(r.expiresAt)) return 'expired';
  if (r.decision === 'allow') return 'released';
  if (approvals < r.approvalsRequired) return 'pending_approval';
  if (r.releaseAt && t < Date.parse(r.releaseAt)) return 'timelocked';
  return 'released';
}
