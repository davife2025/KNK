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

## Session 4: events and trust

```bash
curl -X POST localhost:8787/v1/events -H "Authorization: Bearer knk_..." -H "content-type: application/json" \
  -d '{"events":[{"subject":"alice@laptop","kind":"credential_read","attrs":{"target":"ssh"}}]}'
curl localhost:8787/v1/subjects/alice%40laptop/trust -H "Authorization: Bearer knk_..."
```

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /v1/events` | `events:write` | Ingest up to 100 events; returns each subject's trust state |
| `GET /v1/trust` | `gate:check` | All subjects in the window, riskiest first |
| `GET /v1/subjects/:subject/trust` | `gate:check` | One subject's trust state with reasons |
| `POST /v1/analyze` + `"subject"` | `analyze` | Also records the verdict as an event and returns trust |

Event kinds map to kill-chain stages (see `EVENT_STAGE` in `@knk/shared`): `untrusted_repo_opened`,
`install_script_executed`, `unverified_installer_used`, `artifact_verdict` (initial access);
`credential_read`, `deploy_token_on_disk` (credential access); `ai_tool_permission_change`,
`ai_tool_cross_host_action` (privilege escalation); `signing_request` (signing path, neutral on its own).
Events carry metadata only, never file or code content, and string attributes are redacted anyway.

**How trust is computed** (`apps/api/src/lib/trust.ts`, pure and deterministic, computed on read from raw events):

1. Each event has a base weight (a malicious verdict 55, a wallet or deploy-token read 35, a routine install script 10).
2. Weight halves every 72 hours and drops out after 14 days.
3. If events form a chain with strictly increasing stages over time (initial access, then credential access, then
   privilege escalation), a bonus is added: +10 for two stages, +25 for three, itself faded by the chain's freshness.
4. Risk is the sum, capped at 100: below 25 normal, 25-49 watch, 50-74 elevated, 75+ critical.
5. Every state lists its contributions and plain-English reasons.

**These weights and thresholds are judgement calls, not measurements.** They live in one place so they can be tuned
against real data. Events accept timestamps up to 30 days old and 5 minutes in the future. The window query reads at
most 2,000 events per workspace. There is no rate limiting yet.

## Session 5: the signing gate

The signer asks KNK before it signs, and again immediately before it signs.

```bash
# 1. ask: is this OK to sign?
curl -X POST localhost:8787/v1/gate/check -H "Authorization: Bearer knk_..." -H "content-type: application/json" \
  -d '{"subject":"alice@laptop","wallet":"hot-3","tx":{"format":"evm_authorization","chainId":1,"delegate":"0x2222222222222222222222222222222222222222","nonce":0}}'
# 2. if held: a different person approves (admin key), then wait out the timelock
curl -X POST localhost:8787/v1/gate/decisions/$ID/approve -H "Authorization: Bearer $ADMIN_KEY" -H "content-type: application/json" -d '{"approver":"carol"}'
# 3. right before signing: re-send the tx being signed. proceed:true is returned once.
curl -X POST localhost:8787/v1/gate/decisions/$ID/confirm -H "Authorization: Bearer knk_..." -H "content-type: application/json" -d '{"tx":{...}}'
```

| Endpoint | Scope | Purpose |
|---|---|---|
| `POST /v1/gate/check` | `gate:check` | Decide allow / hold / block; signed decision returned |
| `GET /v1/gate/decisions/:id` | `gate:check` | Current state and approvals |
| `POST /v1/gate/decisions/:id/approve` | `admin` | Approve a held decision |
| `POST /v1/gate/decisions/:id/reject` | `admin` | Reject it for good |
| `POST /v1/gate/decisions/:id/confirm` | `gate:check` | Final check before signing; single use |
| `GET /v1/policy`, `PUT /v1/policy` | `gate:check`, `admin` | Read or replace the workspace policy |

**Transaction formats:** `evm_raw` (a serialised transaction, decoded with viem: native transfers, ERC-20
transfer/transferFrom/approve/increaseAllowance, setApprovalForAll, contract calls and creation, and EIP-7702
transactions with their authorization lists), `evm_authorization` (a request to sign an EIP-7702 delegation, the
step that mattered at Binance), and `transfer` (generic structured transfer, e.g. for NEAR). NEAR transactions are
**not** decoded; a structured `transfer` is judged on its stated destination and amount.

**How a decision is made** (`lib/gate-policy.ts`, pure): the most severe outcome wins. Default policy: undecodable
input blocks; a delegation to a non-allowlisted contract blocks, and an allowlisted one is still held for approval;
requester trust `elevated` holds and `critical` blocks; unlimited approvals and unrecognised contract calls hold.
Optional: destination allowlist, native value limit, per-asset transfer limits. Every hit is returned with a reason.

**Safety properties (each has a test that fails without it):**
- A hold needs approval, then a timelock (default 15 minutes), and a release is valid for a window.
- The requester cannot approve their own request. Each approver name and each API key counts once, so two-person
  approval needs two distinct admin keys.
- `confirm` re-sends the transaction; the server fingerprints it and compares, so a swapped transaction cannot ride
  an old approval.
- A release is single use, enforced atomically, including under simultaneous requests.
- `confirm` re-checks the requester's trust at the moment of use.
- Raw transactions are never stored: only a fingerprint and a decoded summary. Decisions are Ed25519-signed.

**Limits to know:** approver names are asserted by the admin key holder and are not authenticated identities (real
identities arrive with the console and Supabase Auth). A signer that skips `confirm` is not protected; the gate only
works if the signing service calls it. Policy weights are judgement calls. Unlimited means 2^255 or more. The SQL and
atomic constraints have been syntax-checked but not run against a live Supabase project.
