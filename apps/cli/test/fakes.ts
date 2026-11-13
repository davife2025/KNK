import { randomUUID } from 'node:crypto';
import { labelFor, runStaticAnalysis } from '@knk/detect';
import type { AnalyzeResponse, ArtifactKind, EventInput, GateCheckRequest, GateDecisionView, IngestResponse, MeResponse, TrustState } from '@knk/shared';
import { ApiFailure, type KnkClient } from '../src/client.js';

export const trustState = (subject: string, risk = 0, level: TrustState['level'] = 'normal', reasons: string[] = []): TrustState => ({
  subject, risk, level, chain: { length: 0, stages: [] }, contributions: [], reasons, eventCount: 0, windowDays: 14, computedAt: new Date().toISOString(),
});

/** Answers like the real API's static checks, so scans behave realistically without a server. */
export function analyzeLikeApi(kind: ArtifactKind, content: string): AnalyzeResponse {
  const s = runStaticAnalysis(kind, content);
  return {
    payload: {
      id: randomUUID(), workspaceId: 'ws', kind, artifactSha256: 'x', verdict: labelFor(s.floor), riskScore: s.floor,
      summary: 'static', findings: s.findings, mode: 'static_only', model: null, keyId: 'k', issuedAt: new Date().toISOString(),
    },
    signature: 'sig', alg: 'Ed25519', redactions: [], warnings: ['model_not_configured'],
  };
}

export interface FakeClient extends KnkClient {
  analyzed: { kind: ArtifactKind; content: string; subject?: string }[];
  ingested: EventInput[][];
  trusts: string[];
  order: string[];
}

export function fakeClient(o: { analyze?: (kind: ArtifactKind, content: string) => AnalyzeResponse | Promise<AnalyzeResponse>; trust?: TrustState } = {}): FakeClient {
  const c: FakeClient = {
    analyzed: [], ingested: [], trusts: [], order: [],
    async me(): Promise<MeResponse> { return { workspace: { id: 'ws', name: 'Acme' }, apiKeyId: 'k', scopes: ['analyze', 'events:write', 'gate:check'] }; },
    async analyze(kind, content, subject) {
      c.order.push('analyze');
      c.analyzed.push({ kind, content, subject });
      return o.analyze ? o.analyze(kind, content) : analyzeLikeApi(kind, content);
    },
    async ingest(events): Promise<IngestResponse> {
      c.order.push('ingest');
      c.ingested.push(events);
      return { accepted: events.length, subjects: [] };
    },
    async trust(subject) {
      c.trusts.push(subject);
      return o.trust ?? trustState(subject);
    },
    async gateCheck(_req: GateCheckRequest): Promise<GateDecisionView> { throw new ApiFailure(500, 'unused', 'unused'); },
  };
  return c;
}
