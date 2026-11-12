-- Session 4: per-subject lookups for trust computation.
create index if not exists events_ws_subject_time
  on public.events (workspace_id, subject, occurred_at desc);
