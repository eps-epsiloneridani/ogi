# Agent Notes

Before running tests, linters, builds, or package-manager commands:

- Determine the correct project root first.
- For Python commands such as `uv` and `pytest`, run from the nearest directory containing `pyproject.toml`.
- For Node commands such as `pnpm`, `npm`, and `vite`, run from the nearest directory containing `package.json`.
- Do not assume the repository root is the package root in this monorepo.
- If a command fails with errors such as `program not found` or `--extra ... has no effect outside of a project`, verify the working directory before changing the command.

# Using Gemini CLI for Large Codebase Analysis

When analyzing large codebases or multiple files that might exceed context limits, use the Gemini CLI with its massive
context window. Use `gemini -p` to leverage Google Gemini's large context capacity.

## File and Directory Inclusion Syntax

Use the `@` syntax to include files and directories in your Gemini prompts. The paths should be relative to WHERE you run the
gemini command:

### Examples:

**Single file analysis:**
gemini -p "@src/main.py Explain this file's purpose and structure"

Multiple files:
gemini -p "@package.json @src/index.js Analyze the dependencies used in the code"

Entire directory:
gemini -p "@src/ Summarize the architecture of this codebase"

Multiple directories:
gemini -p "@src/ @tests/ Analyze test coverage for the source code"

Current directory and subdirectories:
gemini -p "@./ Give me an overview of this entire project"

# Or use --all_files flag:

gemini --all_files -p "Analyze the project structure and dependencies"

Implementation Verification Examples

Check if a feature is implemented:
gemini -p "@src/ @lib/ Has dark mode been implemented in this codebase? Show me the relevant files and functions"

Verify authentication implementation:
gemini -p "@src/ @middleware/ Is JWT authentication implemented? List all auth-related endpoints and middleware"

Check for specific patterns:
gemini -p "@src/ Are there any React hooks that handle WebSocket connections? List them with file paths"

Verify error handling:
gemini -p "@src/ @api/ Is proper error handling implemented for all API endpoints? Show examples of try-catch blocks"

Check for rate limiting:
gemini -p "@backend/ @middleware/ Is rate limiting implemented for the API? Show the implementation details"

Verify caching strategy:
gemini -p "@src/ @lib/ @services/ Is Redis caching implemented? List all cache-related functions and their usage"

Check for specific security measures:
gemini -p "@src/ @api/ Are SQL injection protections implemented? Show how user inputs are sanitized"

Verify test coverage for features:
gemini -p "@src/payment/ @tests/ Is the payment processing module fully tested? List all test cases"

When to Use Gemini CLI

Use gemini -p when:

- Analyzing entire codebases or large directories
- Comparing multiple large files
- Need to understand project-wide patterns or architecture
- Current context window is insufficient for the task
- Working with files totaling more than 100KB
- Verifying if specific features, patterns, or security measures are implemented
- Checking for the presence of certain coding patterns across the entire codebase

Important Notes

- Paths in @ syntax are relative to your current working directory when invoking gemini
- The CLI will include file contents directly in the context
- No need for --yolo flag for read-only analysis
- Gemini's context window can handle entire codebases that would overflow Claude's context
- When checking implementations, be specific about what you're looking for to get accurate results

---

# Fork addendum — eps-epsiloneridani deployment notes (added by the operator's agent)

The section above is upstream agent guidance and stands unchanged. What follows
is fork- and deployment-specific: this fork carries deployment fixes for the
operator's Dockhand host and is what actually runs.

## What this fork is

Upstream is `khashashin/ogi`. This fork exists **only to carry deployment
fixes** for the operator's network — it is the deployed source, not a feature
fork.

### House rules

- Agent-authored commits carry the disclosure paragraph verbatim:
  *"Generated autonomously by an AI agent (Hermes) during deployment
  debugging, without human code review."*
- No upstream PRs without explicit operator consent (decision 2026-10-25: the
  upstream maintainer's appetite for agentic contributions is unknown —
  fork-only, offer, don't file).
- Fix **in the fork**, debug on the host. Dockhand re-clones fresh on every
  deploy — host-side hand-edits to the stack do not survive.
- Verify a mode-fix push by reading the tree back
  (`git ls-tree HEAD <path>` → `100755`); an empty tree diff is not a fix.

### Deploy environment (operator's network)

- Docker work on this network = **Dockhand stacks only**. Dockhand UI:
  `192.168.1.3:3000` (dockhand.pro); docker host 192.168.1.3 (hostname
  `dockerHost`); the operator's agent has SSH (`root@192.168.1.3`,
  BatchMode) for docker work.
- Dockhand clones this repo fresh into
  `/var/lib/docker/volumes/dockhand_data/_data/stacks/Proxmox/ogi/`
  (= `/app/data/stacks/Proxmox/ogi` inside the dockhand container) and runs
  `docker compose` there. Project name: `ogi`.
- Host ports: **3000 = Dockhand itself — never bind here**, **8080 occupied**;
  OGI uses **frontend 9901**, **backend API 8000**. Check `ss -ltn` before
  introducing any new published port.

### Permission model (measured)

- Fresh clones are root-owned; containers run as unprivileged `ogi` and
  **cannot create or write files under bind-mounted host paths**. An
  in-container `chown -R ... || true` may silently no-op on those mounts —
  never trust it as a fix.
- Any app path the stack writes to must be a **named volume** shadowing the
  bind mount (`ogi_media:/app/media` over `./backend:/app` works; the
  entrypoint's root-phase chown DOES apply to volumes).

### Fixes carried by this fork (do not revert)

1. **`77dc477` — entrypoint exec bits.** `backend/entrypoint.sh` and
   `frontend/docker-entrypoint.d/40-env.sh` committed `100755`. With
   `./backend:/app` bound, containers execute the HOST file, so image-side
   `RUN chmod` is inert and a 644 mode yields
   `exec: /app/entrypoint.sh: permission denied`. The nginx script fails
   SILENTLY (nginx only sources executable `*.sh`), so no error to see.
2. **`98fd1be` — named `ogi_media` volume.** The app boots with
   `settings.abs_media_path.mkdir()` (main.py:178) → `/app/media` under the
   mount → `PermissionError` → backend exit (1) → whole dependency chain
   stalls. Volume shadows the path on backend/worker/agent-worker.
3. **`c8b6896` — frontend port default 9901.** Upstream default 3000 collides
   with Dockhand on this host. Fixed in the committed `.env`; compose reads it
   at container CREATION — `docker start` does NOT re-read `.env`. Recreate
   changed services:
   `docker compose --project-directory <stack-dir> -p ogi up -d <service>`.

### Deploy / verify checklist

1. Deploy from Dockhand (or `docker compose -p ogi up -d` in the stack dir).
2. `docker ps` → backend **healthy**; db/redis healthy.
3. `curl http://127.0.0.1:8000/health` → 200; `curl http://127.0.0.1:9901/` → 200.
4. LAN check: `http://<host>:9901` from a phone/desktop browser.

### Known sharp edges

- **`/app/plugins` is still a host bind mount.** Installing plugins/transforms
  from the UI may hit the same write-permission wall. If it bites: same
  named-volume treatment (trade-off: installed plugins then live in the
  volume, not the repo clone).
- **Transcript secrets are masked.** Logs may show `postgres:***@db…` where
  the file interpolates real values — `grep -c '\*\*\*' <file>` on the real
  file distinguishes file truth from masked-transcript truth.
- **RQ workers log "warm shut down" and exit 0 when signalled** — not a bug.
- Do not disturb other dockerHost residents (mosquitto :1883, Homebridge).

## Local passkey auth (added 2026-10-25, commits e98a82c…b478bc8)

OGI supports three backend auth modes by env, in priority order:
`supabase` (OGI_SUPABASE_URL + ANON_KEY) → `local` (OGI_LOCAL_AUTH_ENABLED=true)
→ `anonymous` (fresh installs/dev). **Local mode is the deployed mode here.**

- **Passkey login is the primary path** (WebAuthn, RP ID = osi.61cygni.co.uk,
  discoverable credentials, UserVerification preferred). Sessions are
  stateless HMAC tokens (OGI_SESSION_SECRET) delivered as HttpOnly cookie
  `ogi_session` and accepted equally as `Authorization: Bearer`.
- **Accounts are invite-only after first run**: the FIRST user claims an admin
  email with the single-use OGI_SETUP_TOKEN (bootstrap rejected once any local
  user exists — this is what prevents self-admin via OGI_ADMIN_EMAILS). The
  setup token was consumed 2026-10-25 and REMOVED from the live env; the
  session secret's copy lives in `pass ogi/ogi-session-secret`, not in files.
- Every subsequent account = admin-minted one-time invite link
  (UI: /invites; API: /api/v1/auth/invites) → invitee registers a passkey to
  activate. No email delivery needed.
- Admin gating: require_admin_user checks the email against OGI_ADMIN_EMAILS
  in BOTH supabase and local modes.
- Enrolment MUST chain after account creation — the bootstrap page shows a
  dedicated "Register your passkey" step (PasskeyAuthPage), driven by an
  explicit button (fresh user gesture keeps credentials.create() reliable).
  A regression test pins this: a successful bootstrap must NOT enter the app
  before the ceremony (PasskeyAuthPage.test.tsx).
- WebAuthn config: OGI_WEBAUTHN_RPID + OGI_PUBLIC_ORIGIN (+ optional
  OGI_EXTRA_ALLOWED_ORIGINS). Passkeys need a secure context: the TLS edge
  (this hostname) or localhost. The transports payload arrives as plain JSON
  strings from @simplewebauthn (and may arrive as enums elsewhere) —
  `_transports_from_attestation()` accepts both; do not "simplify" it back to
  a `.value` call.
- Tests: backend tests/test_local_auth.py (~25 tests); backend suite 277
  green. Frontend: tsc clean; vitest green except 13 pre-existing
  graphStore.test.ts jsdom failures (reproduce on the pre-change tree).
- Password fallback: argon2, OFF by default (OGI_PASSWORD_AUTH_ENABLED) —
  enable explicitly if wanted.
- Stated assumptions: SameSite=Lax + origin checks (no per-request CSRF
  token) acceptable single-tenant; challenge table rows TTL 5 min.

## Email + password + TOTP fallback (added 2026-10-25, commits 61412f0 + e762c8d)

The LAN-friendly sibling of passkey login: usable over plain HTTP where
WebAuthn cannot run. Shipped ENABLED on this deployment:
`OGI_PASSWORD_AUTH_ENABLED=true`, `OGI_TOTP_REQUIRED=true` (a password login
is blocked until the account enrolls TOTP; disable per-account policy via
env).

- **Login** = /api/v1/auth/password/login with email + password + either a
  6-digit TOTP code or a valid unused **recovery code**. Codes verified
  constant-time (compare_digest) with ±1 window (90 s clock-drift tolerance);
  TOTP math = stdlib hmac RFC 6238, secrets 160-bit base32, RFC test vectors
  in the suite.
- **Enrolment** = /security (SecurityPage): set/replace password (argon2),
  enroll TOTP (QR + otpauth URI + verify-one-code), regenerate the 10 hashed
  one-time recovery codes, add another passkey (ceremony reuses the session).
  Remove-TOTP requires confirmation; /totp/status exposes enrollment state.
- **Abuse control**: DB-backed per-email progressive backoff — after
  login_max_attempts failures the next attempt gets 429 + Retry-After,
  exponential (base × 2^n) capped at login_backoff_cap_seconds. Verified on
  the live stack (5 cumulative failures → 429).
- A full e2e was run with a throwaway account (set → enroll → login 200 →
  recovery login 200 → code reuse 401 → lockout 429) and every trace deleted;
  the operator's passkey admin account was untouched throughout.
- Backend suite 306 green (29 new TOTP tests); qrcode (pure-Python SVG) added
  as a runtime dep for QR rendering.
