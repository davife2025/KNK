import { z } from 'zod';

export const Scope = z.enum(['admin', 'events:write', 'analyze', 'gate:check']);
export type Scope = z.infer<typeof Scope>;
export const ALL_SCOPES: Scope[] = [...Scope.options];
export const DEFAULT_KEY_SCOPES: Scope[] = ['events:write', 'analyze', 'gate:check'];

export const CreateWorkspaceRequest = z.object({ name: z.string().trim().min(1).max(80) });
export type CreateWorkspaceRequest = z.infer<typeof CreateWorkspaceRequest>;

export const CreateKeyRequest = z.object({
  name: z.string().trim().min(1).max(80),
  scopes: z.array(Scope).min(1).default(DEFAULT_KEY_SCOPES),
});
export type CreateKeyRequest = z.infer<typeof CreateKeyRequest>;

export const ApiKeyInfo = z.object({
  id: z.string(),
  name: z.string(),
  prefix: z.string(),
  scopes: z.array(Scope),
  createdAt: z.string(),
  lastUsedAt: z.string().nullable(),
  revokedAt: z.string().nullable(),
});
export type ApiKeyInfo = z.infer<typeof ApiKeyInfo>;

/** `key` is the plaintext secret. It is returned exactly once, at creation. */
export const CreatedKey = ApiKeyInfo.extend({ key: z.string() });
export type CreatedKey = z.infer<typeof CreatedKey>;

const WorkspaceRef = z.object({ id: z.string(), name: z.string() });
export const WorkspaceWithKey = z.object({ workspace: WorkspaceRef, apiKey: CreatedKey });
export type WorkspaceWithKey = z.infer<typeof WorkspaceWithKey>;

export const MeResponse = z.object({
  workspace: WorkspaceRef,
  apiKeyId: z.string(),
  scopes: z.array(Scope),
});
export type MeResponse = z.infer<typeof MeResponse>;

export const UsageSummary = z.object({
  since: z.string(),
  total: z.number(),
  byEndpoint: z.array(z.object({ endpoint: z.string(), requests: z.number(), units: z.number() })),
});
export type UsageSummary = z.infer<typeof UsageSummary>;
