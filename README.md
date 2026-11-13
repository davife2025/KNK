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

## Session 6: response (webhooks, playbooks, containment)

KNK turns incidents into **signed webhooks**. It does not freeze anything itself: see `docs/agent-guard.md` for why
(on the NEAR Intents Agent API the owner's wallet signs a freeze) and for the customer-side receiver.

| Endpoint (all `admin`) | Purpose |
|---|---|
| `POST /v1/webhooks` | Register an HTTPS endpoint. Returns the signing secret once |
| `GET /v1/webhooks`, `DELETE /v1/webhooks/:id` | List (never shows secrets), delete (its playbooks go too) |
| `POST /v1/webhooks/:id/test` | Send a signed `webhook.test` now and report the result |
| `POST /v1/playbooks`, `GET /v1/playbooks`, `DELETE /v1/playbooks/:id` | When X happens, notify or contain |
| `GET /v1/responses` | Delivery log: status, attempts, HTTP status, error |

**Triggers:** `trust.critical` (only on the transition into critical), `gate.blocked`, `gate.held`,
`verdict.malicious`. A playbook of kind `alert` sends that event; kind `containment` sends `containment.requested`
with the agent ids to cut off. Optional subject filter (case-insensitive) and a cooldown (default 10 minutes) per
playbook, subject and trigger. A failed delivery does not start a cooldown, so the next incident retries.

**Delivery:** `POST` with `knk-signature: t=<unix>,v1=<HMAC-SHA256 of "t.body">`, `knk-event`, `knk-delivery`.
Retried on timeouts, 5xx, 408 and 429 (3 attempts, 1s then 4s); 4xx and redirects are final. Delivery runs in the
background, so a slow receiver can never delay ingestion or a signing decision. Verify with `@knk/guard`.

**Security properties (each has a test that fails without it):**
- **SSRF:** https only; no credentials in URLs; private, loopback, link-local (cloud metadata), multicast and reserved
  addresses refused, including IPv4-mapped IPv6 and decimal/hex literals. Checked at registration, before each
  delivery, and again at connect time (defeats DNS rebinding). Redirects are never followed.
- Signing secrets are encrypted at rest (AES-256-GCM) and shown once. They cannot be hashed because KNK must sign with them.
- The webhook payload carries no agent credentials, because KNK has none.
- `KNK_ALLOW_PRIVATE_WEBHOOKS` (dev only) makes the API refuse to start in production.

**Limits:** deliveries run in-process, so a crash mid-delivery can leave a run `pending` and a restart does not resume
it (no durable queue yet). The cooldown is checked then written, so two simultaneous identical incidents could both
send. The SQL (including the cascade and the encrypted secret column) is syntax-checked, not run on a live Supabase.

## Session 7: the KNK CLI (`apps/cli`)

```bash
export KNK_API_KEY=knk_...            # never a flag: flags end up in shell history
knk init --api-url https://your-knk-host --subject alice@laptop
knk scan ./coding-test --untrusted    # read-only; nothing in the repo is executed
knk gate check hot-wallet-3 --raw "$TX"
knk status
```

| Command | What it does | Exit codes |
|---|---|---|
| `knk init` | Verifies your key, stores config owner-only (`~/.config/knk/config.json`, mode 600). Key from `KNK_API_KEY` or `--key-stdin` only | 0 / 1 |
| `knk scan [path]` | Finds code that runs on its own, reviews it, prints findings | 0 clean, 2 suspicious, 3 malicious |
| `knk gate check <wallet>` | `--raw HEX`, `--delegate ADDR`, or `--transfer TO --amount N --asset SYM` | 0 allow, 4 hold, 5 block |
| `knk status` | Workspace, scopes and your trust state | 0 |

`scan` flags: `--untrusted` (records that this repo came from outside the team), `--offline` (nothing leaves the
machine; local checks only), `--machine` (also list well-known credential files, names and permissions only),
`--report-tokens` (with `--machine`: send ONE summary event of credential types, opt-in), `--max-send N`, `--json`.
Without configuration, `scan` still runs, local-only.

**What it looks for** (`src/detectors.ts`): npm lifecycle scripts and the files they run; installer-named files and
`setup.py`; git hooks and git config entries that can run commands (git-lfs filters excluded); VS Code tasks set to
run on folder open; dev container commands (host-side `initializeCommand` is rated higher); AI tool configs
(`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.claude/settings*.json`) and assistant instruction files
(`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.github/copilot-instructions.md`) that try to override the assistant;
secrets in the repo (type and count only); symlinks that leave the repo.

**Safe to point at a hostile repository (each property has a test that fails without it):**
- Read-only. Never executes, installs or modifies anything.
- Never follows symlinks, including symlinked parent directories such as a `.git` that points elsewhere. FIFOs,
  devices and binaries are skipped. A script reference that leaves the repo is flagged, not read.
- Every untrusted string is stripped of terminal escapes, bidi controls and zero-width characters before printing.
- **Minimal disclosure:** only code that runs on its own, or anything already suspicious, is sent, and only after
  redaction. For a manifest, only the lifecycle scripts go, not the whole file. `.env` contents, secrets and anything
  behind a symlink are never sent.
- The API URL must be https (http only for localhost), redirects are never followed, and the key is never echoed.
- `--machine` results are shown locally. They are **not** sent unless you pass `--report-tokens`, because ordinary
  developers legitimately have these files and reporting each would raise everyone's trust score.

**Limits:** detection is heuristic and name-based. The AI-tool file names and the VS Code and dev container keys come
from my knowledge of those tools' current conventions and may be incomplete or out of date, so check them against
the tools your team uses. A clean scan is not proof of safety. The CLI is advisory: it cannot stop you running
something. The subject defaults to `username@hostname`, which is sent to KNK; set `--subject` if that is a concern.
Not tested on Windows. The package is not published; `@knk/cli` is a placeholder name.
