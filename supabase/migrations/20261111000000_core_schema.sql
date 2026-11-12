-- KNK core schema (Session 2). Writes happen only through the API (service role).
-- RLS: workspace members may read their own workspace's data via Supabase Auth.

create table public.workspaces (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 80),
  created_at timestamptz not null default now()
);

create table public.workspace_members (
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'member' check (role in ('owner', 'admin', 'member')),
  created_at timestamptz not null default now(),
  primary key (workspace_id, user_id)
);

-- Only a SHA-256 hash of the key is stored. The plaintext is shown once at creation.
create table public.api_keys (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  name text not null,
  prefix text not null unique,
  key_hash text not null,
  scopes text[] not null default '{}',
  created_at timestamptz not null default now(),
  last_used_at timestamptz,
  revoked_at timestamptz
);

create table public.events (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  subject text not null,
  kind text not null,
  payload jsonb not null default '{}',
  occurred_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);
create index events_ws_time on public.events (workspace_id, occurred_at desc);

create table public.verdicts (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  event_id uuid references public.events(id) on delete set null,
  outcome text not null,
  summary text not null,
  model text,
  key_id text,
  signature text,
  created_at timestamptz not null default now()
);
create index verdicts_ws_time on public.verdicts (workspace_id, created_at desc);

create table public.policies (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  name text not null,
  rules jsonb not null default '{}',
  enabled boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.audit_log (
  id bigint generated always as identity primary key,
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  actor text not null,
  action text not null,
  target text,
  meta jsonb not null default '{}',
  created_at timestamptz not null default now()
);
create index audit_ws_time on public.audit_log (workspace_id, created_at desc);

create table public.usage_events (
  id bigint generated always as identity primary key,
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  api_key_id uuid references public.api_keys(id) on delete set null,
  endpoint text not null,
  units integer not null default 1,
  created_at timestamptz not null default now()
);
create index usage_ws_time on public.usage_events (workspace_id, created_at desc);

-- ---------- Row level security ----------
alter table public.workspaces enable row level security;
alter table public.workspace_members enable row level security;
alter table public.api_keys enable row level security;
alter table public.events enable row level security;
alter table public.verdicts enable row level security;
alter table public.policies enable row level security;
alter table public.audit_log enable row level security;
alter table public.usage_events enable row level security;

create function public.is_workspace_member(ws uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.workspace_members m where m.workspace_id = ws and m.user_id = auth.uid()
  );
$$;

create policy "members read own membership" on public.workspace_members
  for select using (user_id = auth.uid());
create policy "members read workspace" on public.workspaces
  for select using (public.is_workspace_member(id));
create policy "members read events" on public.events
  for select using (public.is_workspace_member(workspace_id));
create policy "members read verdicts" on public.verdicts
  for select using (public.is_workspace_member(workspace_id));
create policy "members read policies" on public.policies
  for select using (public.is_workspace_member(workspace_id));
create policy "members read audit log" on public.audit_log
  for select using (public.is_workspace_member(workspace_id));
create policy "members read usage" on public.usage_events
  for select using (public.is_workspace_member(workspace_id));
-- api_keys has no policy on purpose: keys (even hashed) are never readable by clients.
-- No insert/update/delete policies exist: only the service role (the API) can write.

-- ---------- Functions used by the API ----------
create function public.create_workspace(p_name text, p_prefix text, p_key_hash text, p_scopes text[])
returns public.api_keys language plpgsql security definer set search_path = public as $$
declare
  ws uuid;
  k public.api_keys;
begin
  insert into public.workspaces (name) values (p_name) returning id into ws;
  insert into public.api_keys (workspace_id, name, prefix, key_hash, scopes)
    values (ws, 'Default', p_prefix, p_key_hash, p_scopes) returning * into k;
  insert into public.audit_log (workspace_id, actor, action, target)
    values (ws, 'system', 'workspace.created', ws::text);
  return k;
end;
$$;

create function public.usage_by_endpoint(p_workspace uuid, p_since timestamptz)
returns table (endpoint text, requests bigint, units bigint)
language sql stable security definer set search_path = public as $$
  select u.endpoint, count(*), coalesce(sum(u.units), 0)
  from public.usage_events u
  where u.workspace_id = p_workspace and u.created_at >= p_since
  group by u.endpoint order by 2 desc;
$$;

revoke all on function public.create_workspace(text, text, text, text[]) from public, anon, authenticated;
revoke all on function public.usage_by_endpoint(uuid, timestamptz) from public, anon, authenticated;
grant execute on function public.create_workspace(text, text, text, text[]) to service_role;
grant execute on function public.usage_by_endpoint(uuid, timestamptz) to service_role;
