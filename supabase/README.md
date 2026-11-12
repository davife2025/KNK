# Supabase

Schema changes live in `supabase/migrations/` as timestamped SQL files (Session 2 adds the first).

Setup: create a project, then copy `SUPABASE_URL` and the service role key into `.env`.
To manage migrations locally, install the Supabase CLI and run `supabase init` here, then
`supabase link` and `supabase db push`.
