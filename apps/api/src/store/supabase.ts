import type { SupabaseClient } from '@supabase/supabase-js';
import { Scope } from '@knk/shared';
import { getSupabase } from '../lib/supabase.js';
import type { KeyRecord, Store } from './types.js';

interface KeyRow {
  id: string;
  workspace_id: string;
  name: string;
  prefix: string;
  key_hash: string;
  scopes: string[];
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

const validScopes = (raw: string[]): Scope[] =>
  raw.filter((s): s is Scope => Scope.safeParse(s).success);

const toKey = (r: KeyRow): KeyRecord => ({
  id: r.id,
  workspaceId: r.workspace_id,
  name: r.name,
  prefix: r.prefix,
  keyHash: r.key_hash,
  scopes: validScopes(r.scopes),
  createdAt: r.created_at,
  lastUsedAt: r.last_used_at,
  revokedAt: r.revoked_at,
});

/** The client is resolved lazily so the API can boot (and /health work) without Supabase configured. */
export function createSupabaseStore(client: () => SupabaseClient = getSupabase): Store {
  return {
    async createWorkspace({ name, prefix, keyHash, scopes }) {
      const { data, error } = await client().rpc('create_workspace', {
        p_name: name,
        p_prefix: prefix,
        p_key_hash: keyHash,
        p_scopes: scopes,
      });
      if (error) throw error;
      const key = toKey(data as KeyRow);
      return { workspace: { id: key.workspaceId, name }, key };
    },

    async getWorkspace(id) {
      const { data, error } = await client()
        .from('workspaces')
        .select('id,name')
        .eq('id', id)
        .maybeSingle();
      if (error) throw error;
      return data as { id: string; name: string } | null;
    },

    async findKeyByPrefix(prefix) {
      const { data, error } = await client()
        .from('api_keys')
        .select('*')
        .eq('prefix', prefix)
        .maybeSingle();
      if (error) throw error;
      return data ? toKey(data as KeyRow) : null;
    },

    async touchKey(id) {
      const { error } = await client()
        .from('api_keys')
        .update({ last_used_at: new Date().toISOString() })
        .eq('id', id);
      if (error) throw error;
    },

    async listKeys(workspaceId) {
      const { data, error } = await client()
        .from('api_keys')
        .select('*')
        .eq('workspace_id', workspaceId)
        .order('created_at', { ascending: false });
      if (error) throw error;
      return (data as KeyRow[]).map(toKey);
    },

    async insertKey({ workspaceId, name, prefix, keyHash, scopes }) {
      const { data, error } = await client()
        .from('api_keys')
        .insert({ workspace_id: workspaceId, name, prefix, key_hash: keyHash, scopes })
        .select('*')
        .single();
      if (error) throw error;
      return toKey(data as KeyRow);
    },

    async revokeKey(workspaceId, id) {
      const { data, error } = await client()
        .from('api_keys')
        .update({ revoked_at: new Date().toISOString() })
        .eq('id', id)
        .eq('workspace_id', workspaceId)
        .is('revoked_at', null)
        .select('id');
      if (error) throw error;
      return (data?.length ?? 0) > 0;
    },

    async recordUsage({ workspaceId, apiKeyId, endpoint, units }) {
      const { error } = await client()
        .from('usage_events')
        .insert({ workspace_id: workspaceId, api_key_id: apiKeyId, endpoint, units });
      if (error) throw error;
    },

    async usageSummary(workspaceId, since) {
      const { data, error } = await client().rpc('usage_by_endpoint', {
        p_workspace: workspaceId,
        p_since: since.toISOString(),
      });
      if (error) throw error;
      return (data as { endpoint: string; requests: number | string; units: number | string }[]).map(
        (r) => ({ endpoint: r.endpoint, requests: Number(r.requests), units: Number(r.units) }),
      );
    },

    async audit({ workspaceId, actor, action, target, meta }) {
      const { error } = await client()
        .from('audit_log')
        .insert({ workspace_id: workspaceId, actor, action, target: target ?? null, meta: meta ?? {} });
      if (error) throw error;
    },
  };
}
