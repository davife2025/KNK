# KNK build sessions

| # | Session | What gets built |
|---|---|---|
| 1 | Core infrastructure (DONE) | pnpm + Turborepo monorepo, shared TS config, `@knk/shared` contracts, Hono API skeleton (health, status, error shape), Next.js skeleton, Supabase client wiring, env schema, tests |
| 2 | Data model and API-key auth (DONE) | Supabase schema + RLS (workspaces, members, API keys, events, verdicts, policies, audit log), hashed API-key middleware, usage metering |
| 3 | Verdict engine (DONE) | Kimi K2 via Hugging Face client behind a provider interface, local redaction, structured verdicts (zod), KNK-signed verdicts, analyze endpoint |
| 4 | Correlation and trust state (DONE) | Event ingestion, per-person/device time-window correlation, trust scoring |
| 5 | Signing Gate | gate check endpoint, policy evaluation, transaction decoding (incl. EIP-7702 delegations), allow / hold / block, timelock + approval flow |
| 6 | NEAR integration and response | Agent API policy + freeze demo, playbooks, webhooks (token revoke, alerts) |
| 7 | KNK CLI sensor | `knk init`, `knk scan`: install-script, repo-hook, token-on-disk and AI-tool/MCP permission detectors |
| 8 | Web: landing and onboarding | Landing page with onboarding cards, resource and API navigation, docs pages |
| 9 | Web: team console | Events timeline, verdicts, policies, approvals, audit log |
| 10 | Demo, stretch and polish | Simulated Binance-style chain (inert indicators), Dependency Watch (stretch), README, pitch assets |
