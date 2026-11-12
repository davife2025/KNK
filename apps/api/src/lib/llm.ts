import { getEnv } from '../env.js';

export interface LlmRequest {
  system: string;
  user: string;
  maxTokens?: number;
}

/** Provider-agnostic: Kimi K2 on Hugging Face today, anything OpenAI-compatible tomorrow. */
export interface LlmProvider {
  readonly name: string;
  readonly model: string;
  complete(req: LlmRequest): Promise<string>;
}

export class LlmError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = 'LlmError';
  }
}

export function createHfProvider(opts: {
  token: string;
  baseUrl: string;
  model: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}): LlmProvider {
  const f = opts.fetchImpl ?? fetch;
  const url = `${opts.baseUrl.replace(/\/$/, '')}/chat/completions`;
  return {
    name: 'huggingface',
    model: opts.model,
    async complete({ system, user, maxTokens }) {
      let res: Response;
      try {
        res = await f(url, {
          method: 'POST',
          headers: { authorization: `Bearer ${opts.token}`, 'content-type': 'application/json' },
          body: JSON.stringify({
            model: opts.model,
            messages: [
              { role: 'system', content: system },
              { role: 'user', content: user },
            ],
            temperature: 0,
            max_tokens: maxTokens ?? 1000,
            stream: false,
          }),
          signal: AbortSignal.timeout(opts.timeoutMs ?? 30_000),
        });
      } catch (e) {
        throw new LlmError(e instanceof Error && e.name === 'TimeoutError' ? 'LLM request timed out' : 'LLM request failed');
      }
      if (!res.ok) throw new LlmError(`LLM request failed (${res.status})`, res.status);
      const json = (await res.json()) as { choices?: { message?: { content?: string } }[] };
      const text = json.choices?.[0]?.message?.content;
      if (!text) throw new LlmError('LLM returned no content');
      return text;
    },
  };
}

let cached: LlmProvider | null | undefined;

export function getDefaultLlm(): LlmProvider | null {
  if (cached !== undefined) return cached;
  const { HF_TOKEN, HF_BASE_URL, HF_MODEL } = getEnv();
  cached = HF_TOKEN ? createHfProvider({ token: HF_TOKEN, baseUrl: HF_BASE_URL, model: HF_MODEL }) : null;
  return cached;
}
