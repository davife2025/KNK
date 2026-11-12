import type { DecodedTx, GateHit, Outcome, PolicyRules, TrustState } from '@knk/shared';

export interface GateEvaluation {
  decision: Outcome;
  hits: GateHit[];
}

const lc = (xs: string[]) => new Set(xs.map((x) => x.toLowerCase()));
const big = (s: string | undefined) => (s ? BigInt(s) : 0n);

/** Pure: same inputs, same decision. The most severe outcome wins (block over hold over allow). */
export function evaluateGate(input: {
  decoded: DecodedTx | null;
  decodeError?: string;
  trust: Pick<TrustState, 'risk' | 'level'>;
  policy: PolicyRules;
}): GateEvaluation {
  const { decoded, trust, policy } = input;
  if (!decoded) {
    return { decision: 'block', hits: [{ rule: 'decode.failed', outcome: 'block', reason: input.decodeError ?? 'The transaction could not be decoded' }] };
  }

  const hits: GateHit[] = [];
  const hit = (rule: string, outcome: 'hold' | 'block', reason: string) => hits.push({ rule, outcome, reason });

  if (trust.level !== 'normal') {
    const outcome = policy.trust[trust.level];
    if (outcome !== 'allow') hit(`trust.${trust.level}`, outcome, `The requester’s trust is ${trust.level} (risk ${trust.risk})`);
  }

  if (decoded.delegates?.length) {
    const allowed = lc(policy.allowedDelegates);
    for (const d of decoded.delegates) {
      const anyChain = d.chainId === 0 ? ' on any chain' : '';
      if (allowed.has(d.address)) {
        hit('delegation.allowlisted', 'hold', `Delegates this account to allowlisted contract ${d.address}${anyChain}; needs approval`);
      } else {
        hit('delegation.not_allowlisted', policy.delegation, `Delegates this account to ${d.address}${anyChain}, which hands that contract control of the account (EIP-7702)`);
      }
    }
  }

  const destination = decoded.recipient ?? decoded.to;
  if (policy.allowedDestinations.length > 0 && destination && decoded.kind !== 'delegation') {
    if (!lc(policy.allowedDestinations).has(destination.toLowerCase())) {
      hit('destination.unknown', policy.onUnknownDestination, `${destination} is not on the destination allowlist`);
    }
  }

  if (policy.maxNativeValueWei && big(decoded.nativeValue) > big(policy.maxNativeValueWei)) {
    hit('value.over_limit', 'hold', `Native value ${decoded.nativeValue} exceeds the limit ${policy.maxNativeValueWei}`);
  }

  if (decoded.amount && decoded.asset && (decoded.kind === 'token_transfer' || decoded.kind === 'transfer')) {
    const limits = Object.fromEntries(Object.entries(policy.maxTransferAmount).map(([k, v]) => [k.toLowerCase(), v]));
    const limit = limits[decoded.asset.toLowerCase()];
    if (limit && big(decoded.amount) > big(limit)) {
      hit('transfer.over_limit', 'hold', `Transfer of ${decoded.amount} ${decoded.asset} exceeds the limit ${limit}`);
    }
  }

  if ((decoded.kind === 'token_approval' || decoded.kind === 'approval_for_all') && decoded.unlimited) {
    hit('approval.unlimited', policy.unlimitedApproval, 'Grants unlimited spending or transfer rights to another address');
  }

  if ((decoded.kind === 'contract_call' || decoded.kind === 'contract_creation') && policy.onContractCall !== 'allow') {
    hit('contract_call.review', policy.onContractCall, decoded.kind === 'contract_creation' ? 'Deploys a contract' : `Calls an unrecognised function (${decoded.selector ?? 'unknown'})`);
  }

  const decision: Outcome = hits.some((h) => h.outcome === 'block') ? 'block' : hits.length ? 'hold' : 'allow';
  return { decision, hits };
}
