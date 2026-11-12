import { z } from 'zod';

export const Severity = z.enum(['info', 'low', 'medium', 'high', 'critical']);
export type Severity = z.infer<typeof Severity>;

export const ArtifactKind = z.enum(['install_script', 'repo_manifest', 'ai_tool_config', 'source_file']);
export type ArtifactKind = z.infer<typeof ArtifactKind>;

export const VerdictLabel = z.enum(['benign', 'suspicious', 'malicious']);
export type VerdictLabel = z.infer<typeof VerdictLabel>;

export const Finding = z.object({
  id: z.string(),
  title: z.string(),
  detail: z.string(),
  severity: Severity,
  source: z.enum(['static', 'model']),
  line: z.number().int().positive().optional(),
});
export type Finding = z.infer<typeof Finding>;

export const AnalyzeRequest = z.object({
  kind: ArtifactKind,
  content: z.string().min(1).max(40_000),
});
export type AnalyzeRequest = z.infer<typeof AnalyzeRequest>;

/**
 * The signed part. It deliberately holds a hash of the artifact, never the artifact itself.
 * `mode` says whether a model contributed: a signature proves KNK issued this verdict,
 * not that a model ran honestly.
 */
export const VerdictPayload = z.object({
  id: z.string(),
  workspaceId: z.string(),
  kind: ArtifactKind,
  artifactSha256: z.string(),
  verdict: VerdictLabel,
  riskScore: z.number().int().min(0).max(100),
  summary: z.string(),
  findings: z.array(Finding),
  mode: z.enum(['static_only', 'static+model']),
  model: z.string().nullable(),
  keyId: z.string(),
  issuedAt: z.string(),
});
export type VerdictPayload = z.infer<typeof VerdictPayload>;

export const SignedVerdict = z.object({
  payload: VerdictPayload,
  signature: z.string(),
  alg: z.literal('Ed25519'),
});
export type SignedVerdict = z.infer<typeof SignedVerdict>;

export const AnalyzeResponse = SignedVerdict.extend({
  redactions: z.array(z.object({ type: z.string(), count: z.number() })),
  warnings: z.array(z.string()),
});
export type AnalyzeResponse = z.infer<typeof AnalyzeResponse>;

export const SigningKeysResponse = z.object({
  keys: z.array(
    z.object({
      keyId: z.string(),
      algorithm: z.literal('Ed25519'),
      publicKey: z.string(),
      encoding: z.literal('base64 SPKI DER'),
      canonicalization: z.literal('JSON with recursively sorted keys'),
    }),
  ),
});
export type SigningKeysResponse = z.infer<typeof SigningKeysResponse>;
