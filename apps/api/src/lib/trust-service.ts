import type { TrustState } from '@knk/shared';
import type { Store, StoredEvent } from '../store/types.js';
import { computeTrust, TRUST_CONFIG } from './trust.js';

/** Trust is computed on read from raw events, so it can never drift out of sync with them. */
export async function trustSnapshot(
  store: Store,
  workspaceId: string,
  opts: { subjects?: string[]; limit?: number; now?: Date } = {},
): Promise<TrustState[]> {
  const now = opts.now ?? new Date();
  const since = new Date(now.getTime() - TRUST_CONFIG.windowDays * 86_400_000);
  const events = await store.listEvents(workspaceId, { since, limit: 2000 });

  const by = new Map<string, StoredEvent[]>();
  for (const e of events) by.set(e.subject, [...(by.get(e.subject) ?? []), e]);

  const subjects = opts.subjects ?? [...by.keys()];
  return subjects
    .map((s) => computeTrust(s, by.get(s) ?? [], now))
    .sort((a, b) => b.risk - a.risk)
    .slice(0, opts.limit ?? 50);
}
