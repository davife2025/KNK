import { z } from 'zod';

/** Public API contract: GET /v1/status. Shared by apps/api and apps/web. */
export const StatusResponse = z.object({
  service: z.literal('knk-api'),
  version: z.string(),
  integrations: z.object({
    supabase: z.boolean(),
    llm: z.boolean(),
  }),
});
export type StatusResponse = z.infer<typeof StatusResponse>;

export const ApiError = z.object({
  error: z.object({ code: z.string(), message: z.string(), requestId: z.string().optional() }),
});
export type ApiError = z.infer<typeof ApiError>;
