import { z } from 'zod';

const Env = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().positive().default(8787),
  SUPABASE_URL: z.url().optional(),
  SUPABASE_SERVICE_ROLE_KEY: z.string().min(1).optional(),
  HF_TOKEN: z.string().min(1).optional(),
  HF_BASE_URL: z.url().default('https://router.huggingface.co/v1'),
  HF_MODEL: z.string().min(1).default('moonshotai/Kimi-K2-Instruct-0905'),
});
export type Env = z.infer<typeof Env>;

let cached: Env | undefined;

/** Parsed once. Integrations are optional in Session 1 so the API boots without secrets. */
export function getEnv(): Env {
  if (!cached) {
    const parsed = Env.safeParse(process.env);
    if (!parsed.success) {
      throw new Error(`Invalid environment: ${z.prettifyError(parsed.error)}`);
    }
    cached = parsed.data;
  }
  return cached;
}

export function resetEnvForTests(): void {
  cached = undefined;
}
