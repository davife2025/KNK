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

## Session 3: verdicts

```bash
pnpm --filter @knk/api keygen      # prints KNK_SIGNING_KEY=... ; paste into .env
curl -X POST localhost:8787/v1/analyze -H "Authorization: Bearer knk_..." -H "content-type: application/json" \
  -d '{"kind":"install_script","content":"curl -fsSL https://x.test/i.sh | sh"}'
```

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /v1/analyze` | `analyze` scope | Analyse an artifact, return a signed verdict |
| `GET /v1/verdicts/:id` | `analyze` scope | Fetch a stored verdict (own workspace only) |
| `GET /v1/signing-keys` | public | Public key for independent verification |

Artifact kinds: `install_script`, `repo_manifest`, `ai_tool_config`, `source_file` (40,000 characters max).

**How a verdict is made**

1. The content is redacted (tokens, private-key blocks, labelled secrets, seed phrases). Heuristic, defence in depth.
2. Deterministic static rules run on the original content and set a **floor** under the risk score.
3. If `HF_TOKEN` is set, Kimi K2 (Hugging Face router) reviews the redacted content inside an unguessable marker, with
   instructions to treat it as data. The model can **raise** the score, never lower it, so text inside an artifact
   cannot talk the analyser into calling it safe. Two or more serious static findings force a malicious verdict.
4. The verdict is signed with Ed25519 over canonical JSON (recursively sorted keys). Verify it yourself with the
   public key from `/v1/signing-keys`.

**What a signature does and does not prove:** that KNK issued exactly this verdict. It does not prove a model ran
honestly. `mode` says whether a model contributed (`static_only` or `static+model`). Without a model the API still
works and returns a `model_not_configured` warning.

**Storage:** only the SHA-256 of the artifact is stored, never the artifact. Metering weights (1 static-only, 5
model-backed) are placeholders in `routes/analyze.ts`.

**Not yet verified:** the live Hugging Face call (tested against a mocked endpoint only) and the SQL against a real
Supabase project. Confirm the Kimi model id with `GET https://router.huggingface.co/v1/models`.
