import {
  AnalyzeResponse,
  GateDecisionView,
  IngestResponse,
  MeResponse,
  TrustState,
  type ArtifactKind,
  type EventInput,
  type GateCheckRequest,
} from '@knk/shared';
import type { ZodType } from 'zod';
import { assertSafeApiUrl } from './config.js';

export class ApiFailure extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'ApiFailure';
  }
}

export interface KnkClient {
  me(): Promise<MeResponse>;
  analyze(kind: ArtifactKind, content: string, subject?: string): Promise<AnalyzeResponse>;
  ingest(events: EventInput[]): Promise<IngestResponse>;
  trust(subject: string): Promise<TrustState>;
  gateCheck(req: GateCheckRequest): Promise<GateDecisionView>;
}

export function createClient(o: { baseUrl: string; key: string; fetchImpl?: typeof fetch; timeoutMs?: number }): KnkClient {
  const base = assertSafeApiUrl(o.baseUrl);
  const f = o.fetchImpl ?? fetch;

  async function call<T>(method: string, pathname: string, schema: ZodType<T>, body?: unknown, timeoutMs = o.timeoutMs ?? 15_000): Promise<T> {
    let res: Response;
    try {
      res = await f(new URL(pathname, base).toString(), {
        method,
        redirect: 'error', // never replay the Authorization header to somewhere else
        headers: { authorization: `Bearer ${o.key}`, 'content-type': 'application/json', 'user-agent': 'knk-cli/0.0.0' },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (e) {
      throw new ApiFailure(0, e instanceof Error && e.name === 'TimeoutError' ? 'timeout' : 'unreachable', 'Could not reach the KNK API');
    }
    const text = await res.text();
    let json: unknown;
    try {
      json = text ? JSON.parse(text) : undefined;
    } catch {
      /* handled below */
    }
    if (!res.ok) {
      const err = (json as { error?: { code?: string; message?: string } } | undefined)?.error;
      throw new ApiFailure(res.status, err?.code ?? 'http_error', err?.message ?? `HTTP ${res.status}`);
    }
    const parsed = schema.safeParse(json);
    if (!parsed.success) throw new ApiFailure(502, 'bad_response', 'The KNK API returned an unexpected response');
    return parsed.data;
  }

  return {
    me: () => call('GET', '/v1/me', MeResponse),
    analyze: (kind, content, subject) => call('POST', '/v1/analyze', AnalyzeResponse, { kind, content, ...(subject ? { subject } : {}) }, 60_000),
    ingest: (events) => call('POST', '/v1/events', IngestResponse, { events }),
    trust: (subject) => call('GET', `/v1/subjects/${encodeURIComponent(subject)}/trust`, TrustState),
    gateCheck: (req) => call('POST', '/v1/gate/check', GateDecisionView, req),
  };
}
