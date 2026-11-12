import { z } from 'zod';
import { TrustLevel } from './events.js';

const Dec = z.string().regex(/^\d{1,78}$/, 'decimal integer string');
export const Outcome = z.enum(['allow', 'hold', 'block']);
export type Outcome = z.infer<typeof Outcome>;

/** Per-workspace signing policy. PUT replaces it; fields left out revert to these defaults. */
export const PolicyRules = z.object({
  /** What each trust level of the requester does. Normal trust never triggers a rule. */
  trust: z
    .object({ watch: Outcome, elevated: Outcome, critical: Outcome })
    .default({ watch: 'allow', elevated: 'hold', critical: 'block' }),
  /** What happens to an EIP-7702 delegation whose delegate is NOT allowlisted. */
  delegation: z.enum(['hold', 'block']).default('block'),
  /** Allowlisted delegates still need approval (hold), never auto-allow. */
  allowedDelegates: z.array(z.string().max(100)).max(100).default([]),
  /** If non-empty, any other destination (or token recipient / spender) triggers onUnknownDestination. */
  allowedDestinations: z.array(z.string().max(100)).max(1000).default([]),
  onUnknownDestination: z.enum(['hold', 'block']).default('hold'),
  maxNativeValueWei: Dec.optional(),
  /** Per asset (token address or symbol), in the asset's smallest unit. Keys are matched case-insensitively. */
  maxTransferAmount: z.record(z.string().min(1).max(100), Dec).default({}),
  /** Unlimited token approvals and approval-for-all. */
  unlimitedApproval: z.enum(['hold', 'block']).default('hold'),
  /** Calls with an unrecognised selector, and contract creation. */
  onContractCall: Outcome.default('hold'),
  timelockSeconds: z.number().int().min(0).max(7 * 86_400).default(900),
  approvalsRequired: z.number().int().min(1).max(10).default(1),
  confirmWindowSeconds: z.number().int().min(60).max(86_400).default(3600),
});
export type PolicyRules = z.infer<typeof PolicyRules>;
export const DEFAULT_POLICY: PolicyRules = PolicyRules.parse({});

export const PolicyResponse = z.object({
  rules: PolicyRules,
  source: z.enum(['default', 'custom']),
  updatedAt: z.string().nullable(),
});
export type PolicyResponse = z.infer<typeof PolicyResponse>;

const Hex = z.string().regex(/^0x[0-9a-fA-F]*$/, 'hex string').max(40_000);
const Address = z.string().regex(/^0x[0-9a-fA-F]{40}$/, 'EVM address');

/** What a signer is about to sign. `evm_authorization` is a request to sign an EIP-7702 delegation. */
export const GateTx = z.discriminatedUnion('format', [
  z.object({ format: z.literal('evm_raw'), raw: Hex }),
  z.object({
    format: z.literal('evm_authorization'),
    chainId: z.number().int().nonnegative(),
    delegate: Address,
    nonce: z.number().int().nonnegative(),
  }),
  z.object({
    format: z.literal('transfer'),
    to: z.string().min(1).max(100),
    amount: Dec,
    asset: z.string().min(1).max(100),
    chain: z.string().max(40).optional(),
  }),
]);
export type GateTx = z.infer<typeof GateTx>;

export const GateCheckRequest = z.object({
  subject: z.string().trim().min(1).max(120),
  wallet: z.string().trim().min(1).max(120),
  tx: GateTx,
});
export type GateCheckRequest = z.infer<typeof GateCheckRequest>;

/** Confirm re-sends the tx the signer is about to sign; the server recomputes the fingerprint itself. */
export const GateConfirmRequest = z.object({ tx: GateTx });
export type GateConfirmRequest = z.infer<typeof GateConfirmRequest>;

export const ApproveRequest = z.object({ approver: z.string().trim().min(1).max(120) });
export type ApproveRequest = z.infer<typeof ApproveRequest>;

export const DecodedTx = z.object({
  format: z.enum(['evm_raw', 'evm_authorization', 'transfer']),
  kind: z.enum([
    'native_transfer',
    'token_transfer',
    'token_approval',
    'approval_for_all',
    'contract_call',
    'contract_creation',
    'delegation',
    'transfer',
  ]),
  chainId: z.number().int().optional(),
  to: z.string().optional(),
  recipient: z.string().optional(),
  amount: z.string().optional(),
  asset: z.string().optional(),
  nativeValue: z.string().optional(),
  selector: z.string().optional(),
  unlimited: z.boolean().optional(),
  delegates: z.array(z.object({ chainId: z.number().int(), address: z.string(), nonce: z.number().int() })).optional(),
});
export type DecodedTx = z.infer<typeof DecodedTx>;

export const GateHit = z.object({ rule: z.string(), outcome: z.enum(['hold', 'block']), reason: z.string() });
export type GateHit = z.infer<typeof GateHit>;

export const GateState = z.enum(['released', 'pending_approval', 'timelocked', 'blocked', 'rejected', 'consumed', 'expired']);
export type GateState = z.infer<typeof GateState>;

export const GateDecisionPayload = z.object({
  id: z.string(),
  workspaceId: z.string(),
  subject: z.string(),
  wallet: z.string(),
  decision: Outcome,
  fingerprint: z.string(),
  kind: z.string(),
  trustRisk: z.number().int(),
  trustLevel: TrustLevel,
  rules: z.array(z.string()),
  approvalsRequired: z.number().int(),
  issuedAt: z.string(),
  releaseAt: z.string().nullable(),
  expiresAt: z.string().nullable(),
  keyId: z.string(),
});
export type GateDecisionPayload = z.infer<typeof GateDecisionPayload>;

export const GateDecisionView = z.object({
  payload: GateDecisionPayload,
  signature: z.string(),
  alg: z.literal('Ed25519'),
  state: GateState,
  reasons: z.array(GateHit),
  approvals: z.array(z.object({ approver: z.string(), at: z.string() })),
  decoded: DecodedTx.nullable(),
});
export type GateDecisionView = z.infer<typeof GateDecisionView>;

export const ConfirmResponse = z.object({ proceed: z.boolean(), reason: z.string(), state: GateState });
export type ConfirmResponse = z.infer<typeof ConfirmResponse>;
