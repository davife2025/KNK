-- Session 3: richer verdicts. The analysed artifact is never stored, only its hash.
alter table public.verdicts
  add column kind text,
  add column artifact_sha256 text,
  add column risk_score integer check (risk_score between 0 and 100),
  add column findings jsonb not null default '[]',
  add column mode text,
  add column payload jsonb;

comment on column public.verdicts.artifact_sha256 is 'SHA-256 of the analysed artifact. The artifact itself is never stored.';
comment on column public.verdicts.payload is 'The exact signed payload; signature verifies against it.';
