# KNK

pnpm + Turborepo monorepo (TypeScript, Node 22).

```
apps/api         Hono API (public KNK API; every client talks to this)
apps/web         Next.js app (landing, onboarding, console)
packages/shared  zod contracts shared by api and web
supabase/        migrations
docs/            session plan
```

## Run

```bash
cp .env.example .env
pnpm install
pnpm build        # builds @knk/shared first (turbo handles order)
pnpm dev          # api on :8787, web on :3000
pnpm typecheck && pnpm test
```

Check it: `curl localhost:8787/health` and `curl localhost:8787/v1/status`.

## Session 2: first API key

1. Create a Supabase project, put `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` in `.env`, and set
   `KNK_BOOTSTRAP_TOKEN` (`openssl rand -hex 24`).
2. Apply the schema: install the Supabase CLI, then `supabase link` and `supabase db push`
   (or paste `supabase/migrations/20261111000000_core_schema.sql` into the SQL editor).
3. Create a workspace and its first admin key (the key is shown once):

```bash
curl -X POST localhost:8787/v1/workspaces \
  -H "x-bootstrap-token: $KNK_BOOTSTRAP_TOKEN" -H "content-type: application/json" \
  -d '{"name":"My Team"}'
```

4. Use it: `curl localhost:8787/v1/me -H "Authorization: Bearer knk_..."`

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /v1/workspaces` | bootstrap token | Create workspace + first admin key |
| `GET /v1/me` | API key | Who am I (workspace, scopes) |
| `GET /v1/usage?days=30` | API key | Metered usage by endpoint |
| `GET/POST /v1/keys`, `DELETE /v1/keys/:id` | admin scope | List, create, revoke keys |

Keys are stored as SHA-256 hashes; the plaintext is never retrievable. Every authenticated call is metered.
The SQL has been syntax-checked but not yet run against a live Supabase project.
