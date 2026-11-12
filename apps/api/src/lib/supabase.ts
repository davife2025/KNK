import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import { getEnv } from '../env.js';

let client: SupabaseClient | undefined;

/** Server-side client (service role). Never expose this key to apps/web. */
export function getSupabase(): SupabaseClient {
  if (!client) {
    const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = getEnv();
    if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
      throw new Error('Supabase is not configured: set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY');
    }
    client = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
  }
  return client;
}
