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
