import { createHash, randomUUID } from 'node:crypto';
import { Hono } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import {
  AnalyzeRequest,
  type AnalyzeResponse,
  type SignedVerdict,
  type SigningKeysResponse,
  type VerdictPayload,
} from '@knk/shared';
import { analyzeArtifact } from '../lib/analyzer.js';
import { apiError } from '../lib/errors.js';
import { getDefaultLlm, type LlmProvider } from '../lib/llm.js';
import { getDefaultSigner, type VerdictSigner } from '../lib/signing.js';
import { requireApiKey, requireScope, type AppEnv } from '../middleware/auth.js';
import { meterUsage } from '../middleware/usage.js';
import type { Store } from '../store/types.js';

// Metering weights per verdict. Placeholder values: a pricing decision, tune freely.
const UNITS = { static_only: 1, 'static+model': 5 } as const;

export interface AnalyzeDeps {
  store: Store;
  /** undefined = resolve from env, null = no model. */
  llm?: LlmProvider | null;
  /** undefined = resolve from env, null = signing unavailable. */
  signer?: VerdictSigner | null;
}

export function analyzeRoutes(deps: AnalyzeDeps): Hono<AppEnv> {
  const { store } = deps;
  const r = new Hono<AppEnv>();

  // Public: lets anyone verify a verdict without trusting our API.
  r.get('/v1/signing-keys', (c) => {
    const signer = deps.signer === undefined ? getDefaultSigner() : deps.signer;
    const out: SigningKeysResponse = {
      keys: signer
        ? [
            {
              keyId: signer.keyId,
              algorithm: 'Ed25519',
              publicKey: signer.publicKey,
              encoding: 'base64 SPKI DER',
              canonicalization: 'JSON with recursively sorted keys',
            },
          ]
        : [],
    };
    return c.json(out);
  });

  for (const path of ['/v1/analyze', '/v1/verdicts/*']) {
    r.use(path, requireApiKey(store), meterUsage(store));
  }

  r.post(
    '/v1/analyze',
    requireScope('analyze'),
    bodyLimit({
      maxSize: 128 * 1024,
      onError: (c) => apiError(c, 413, 'payload_too_large', 'Request body is too large'),
    }),
    async (c) => {
      const body = AnalyzeRequest.safeParse(await c.req.json().catch(() => null));
      if (!body.success) {
        const msg = body.error.issues.map((i) => `${i.path.join('.') || 'body'}: ${i.message}`).join('; ');
        return apiError(c, 400, 'invalid_request', msg);
      }
      const signer = deps.signer === undefined ? getDefaultSigner() : deps.signer;
      if (!signer) return apiError(c, 503, 'signing_not_configured', 'Verdict signing is not configured');
      const llm = deps.llm === undefined ? getDefaultLlm() : deps.llm;

      const { kind, content } = body.data;
      const result = await analyzeArtifact({ kind, content, llm });
      const auth = c.get('auth');

      const payload: VerdictPayload = {
        id: randomUUID(),
        workspaceId: auth.workspaceId,
        kind,
        artifactSha256: createHash('sha256').update(content).digest('hex'),
        verdict: result.verdict,
        riskScore: result.riskScore,
        summary: result.summary,
        findings: result.findings,
        mode: result.mode,
        model: result.model,
        keyId: signer.keyId,
        issuedAt: new Date().toISOString(),
      };
      const signature = signer.sign(payload);
      await store.insertVerdict({ payload, signature });

      c.set('units', UNITS[result.mode]);
      const out: AnalyzeResponse = {
        payload,
        signature,
        alg: 'Ed25519',
        redactions: result.redactions,
        warnings: result.warnings,
      };
      return c.json(out);
    },
  );

  r.get('/v1/verdicts/:id', requireScope('analyze'), async (c) => {
    const found = await store.getVerdict(c.get('auth').workspaceId, c.req.param('id'));
    if (!found) return apiError(c, 404, 'not_found', 'Verdict not found');
    const out: SignedVerdict = found;
    return c.json(out);
  });

  return r;
}
