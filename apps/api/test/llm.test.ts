import { describe, expect, it, vi } from 'vitest';
import { createHfProvider, LlmError } from '../src/lib/llm.js';

const opts = { token: 'hf_test', baseUrl: 'https://router.example/v1/', model: 'moonshotai/Kimi-K2-Instruct-0905' };

describe('Hugging Face provider', () => {
  it('calls the OpenAI-compatible chat endpoint and returns the content', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ choices: [{ message: { content: 'hello' } }] }), { status: 200 }));
    const llm = createHfProvider({ ...opts, fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(await llm.complete({ system: 's', user: 'u' })).toBe('hello');

    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://router.example/v1/chat/completions');
    expect((init.headers as Record<string, string>).authorization).toBe('Bearer hf_test');
    const body = JSON.parse(init.body as string);
    expect(body.model).toBe(opts.model);
    expect(body.temperature).toBe(0);
    expect(body.messages.map((m: { role: string }) => m.role)).toEqual(['system', 'user']);
  });

  it('turns HTTP errors and empty replies into LlmError', async () => {
    const bad = createHfProvider({ ...opts, fetchImpl: (async () => new Response('no', { status: 429 })) as unknown as typeof fetch });
    await expect(bad.complete({ system: 's', user: 'u' })).rejects.toMatchObject({ name: 'LlmError', status: 429 });
    const empty = createHfProvider({ ...opts, fetchImpl: (async () => new Response(JSON.stringify({ choices: [] }), { status: 200 })) as unknown as typeof fetch });
    await expect(empty.complete({ system: 's', user: 'u' })).rejects.toBeInstanceOf(LlmError);
  });
});
