-- Session 5: signing gate decisions and approvals. Raw transactions are never stored: only the
-- fingerprint (hash) and a decoded summary. Writes happen only through the API (service role).

-- One active policy per workspace (name = 'default').
create unique index policies_ws_name on public.policies (workspace_id, name);

create table public.gate_decisions (
  id uuid primary key,
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  subject text not null,
  wallet text not null,
  decision text not null check (decision in ('allow', 'hold', 'block')),
  fingerprint text not null,
  kind text not null,
  summary jsonb,
  hits jsonb not null default '[]',
  trust_risk integer not null,
  trust_level text not null,
  approvals_required integer not null default 1,
  release_at timestamptz,
  expires_at timestamptz,
  status text not null default 'open' check (status in ('open', 'rejected', 'consumed')),
  consumed_at timestamptz,
  payload jsonb not null,
  signature text not null,
  created_at timestamptz not null default now()
);
create index gate_decisions_ws_time on public.gate_decisions (workspace_id, created_at desc);

create table public.gate_approvals (
  id bigint generated always as identity primary key,
  decision_id uuid not null references public.gate_decisions(id) on delete cascade,
  api_key_id uuid references public.api_keys(id) on delete set null,
  approver text not null,
  created_at timestamptz not null default now()
);
-- Atomic duplicate protection: one approval per approver name and per API key (two-person rule).
create unique index gate_approvals_approver on public.gate_approvals (decision_id, lower(approver));
create unique index gate_approvals_key on public.gate_approvals (decision_id, api_key_id);

alter table public.gate_decisions enable row level security;
alter table public.gate_approvals enable row level security;

create policy "members read gate decisions" on public.gate_decisions
  for select using (public.is_workspace_member(workspace_id));
create policy "members read gate approvals" on public.gate_approvals
  for select using (
    exists (
      select 1 from public.gate_decisions d
      where d.id = decision_id and public.is_workspace_member(d.workspace_id)
    )
  );
