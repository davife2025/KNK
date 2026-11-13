-- Session 6: webhooks, playbooks and the response log. Signing secrets are stored encrypted
-- (AES-256-GCM, key held by the API), never in plaintext. Writes happen only through the API (service role).

create table public.webhooks (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  url text not null,
  description text,
  secret_enc text not null,
  created_at timestamptz not null default now()
);

create table public.playbooks (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  name text not null,
  enabled boolean not null default true,
  triggers text[] not null,
  subjects text[] not null default '{}',
  webhook_id uuid not null references public.webhooks(id) on delete cascade,
  kind text not null check (kind in ('alert', 'containment')),
  agent_ids text[] not null default '{}',
  cooldown_seconds integer not null default 600 check (cooldown_seconds >= 0),
  created_at timestamptz not null default now(),
  check (kind <> 'containment' or cardinality(agent_ids) > 0)
);

create table public.response_runs (
  id uuid primary key,
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  playbook_id uuid references public.playbooks(id) on delete set null,
  webhook_id uuid references public.webhooks(id) on delete set null,
  trigger text not null,
  subject text not null,
  event_type text not null,
  status text not null default 'pending' check (status in ('pending', 'delivered', 'failed')),
  attempts integer not null default 0,
  http_status integer,
  error text,
  payload jsonb not null,
  created_at timestamptz not null default now(),
  finished_at timestamptz
);
create index response_runs_ws_time on public.response_runs (workspace_id, created_at desc);
create index response_runs_cooldown on public.response_runs (workspace_id, playbook_id, trigger, created_at desc);

alter table public.webhooks enable row level security;
alter table public.playbooks enable row level security;
alter table public.response_runs enable row level security;

-- webhooks has no policy on purpose: even encrypted secrets are never readable by clients.
create policy "members read playbooks" on public.playbooks
  for select using (public.is_workspace_member(workspace_id));
create policy "members read response runs" on public.response_runs
  for select using (public.is_workspace_member(workspace_id));
