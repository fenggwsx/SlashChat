SlashChat Agent Brief

Project Snapshot (v1.0.0)
- SlashChat v1.0.0 delivers a TCP chat stack with a Go server, Bubbletea TUI client, JWT auth, room messaging, file sharing, and a live protocol inspector.
- The project targets Go 1.25.3 with CGO-disabled builds for Linux, macOS, and Windows; binaries live under `build/` when built via the Makefile.
- Length-prefixed JSON envelopes move over raw TCP, keeping the stack dependency-light and portable.

Code Layout & Dependencies
- Entrypoints: `cmd/server` spins up the TCP daemon; `cmd/client` launches the Bubbletea UI.
- Core packages: `internal/server` (sessions, routing, file IO), `internal/client` (state machine, views, commands), `internal/protocol` (framing + payloads), `internal/auth` (JWT + bcrypt), `internal/storage` (interfaces + models), `internal/storage/sqlite` (GORM driver), and `internal/config` (env parsing).
- Keep new dependencies CGO-free; storage relies on `github.com/glebarez/sqlite` stacked on modernc sqlite.

Server Responsibilities
- Accepts TCP connections, spawns dedicated read/write goroutines, and routes envelopes through the room hub.
- Automatically migrates the SQLite schema on startup and ensures `uploads/` exists (overridable via `GOSLASH_UPLOAD_DIR`).
- Acknowledges commands with `ack` envelopes: `ok`, `error`, or `upload_required` (file fast-path) and logs notable events with remote address context.

Client Experience
- Bubbletea UI runs in alt screen with command/insert modes, ANSI transcript, status bar, and scrollback; idle view shows the ASCII "SLASH CHAT" banner.
- `/pipe` view mirrors live protocol traffic with optional `/pipe clear`; `/chat` swaps back to the chat history.
- Command palette supports tab-completion, history hints, and auto-switching back to chat after sending messages from other views.

Authentication & Security
- `/register` and `/login` issue bcrypt-backed credentials; JWTs (golang-jwt v5) embed the user ID as subject and reuse across subsequent envelopes via the `token` field.
- Secrets derive from env vars (`GOSLASH_JWT_SECRET`, issuer, expiration). Ship releases with non-default secrets and rotate regularly.
- Rough rate-limiting hooks exist on the server; extend for production hardening.

Persistence & File Handling
- SQLite file path `goslash.db` (configurable) stores `users` and `messages` with UTC timestamps; GORM suppresses noisy "record not found" errors.
- File messages store the original filename in `content` with SHA-256 in `file_sha`. Binaries land in `uploads/<sha>` with `0600` perms.
- Upload flow: client issues `file_upload_prepare` (SHA, room, filename). If the SHA already exists, server responds `ack:ok` and persists metadata; otherwise it returns `upload_required`, expecting a follow-up `file_upload` payload with base64 data. Hash mismatch aborts the write.
- `/download` resolves a stored message ID to fetch base64 data back to the client; caller must still be in the originating room.

Protocol & Messaging Flow
- Envelopes carry `id`, `type`, `timestamp`, optional `token`, metadata, and typed payloads. Message kinds (`text`, `file`) drive rendering on the client.
- Room joins fetch the latest 100 messages via `chat_history` events, then every persisted message broadcasts as `chat_message`.
- `MessageTypeFileChunk` exists but is unused; new work should either remove or implement streaming uploads.

Command Reference (client)
- `/connect [addr]` — open a TCP session (defaults from `GOSLASH_SERVER_ADDR`).
- `/register <username> <password>` / `/login <username> <password>` — manage credentials and cache the JWT locally.
- `/join <room>` / `/leave [room]` — subscribe/unsubscribe to rooms and load history.
- `/upload <path>` — SHA-256 the file, attempt fast-path reuse, then send data if needed.
- `/download <message_id>` — pull a previously shared file into the current working directory.
- `/pipe [clear]` — inspect live protocol traffic or reset the inspector buffer.
- `/chat` / `/help` / `/quit` — switch view, show inline help, or exit. Typing without a prefix sends a chat event when connected.

Configuration Defaults
- Server: `GOSLASH_LISTEN_ADDR=:9000`, `GOSLASH_DB_PATH=goslash.db`, `GOSLASH_UPLOAD_DIR=uploads`, `GOSLASH_READ_TIMEOUT=15s`, `GOSLASH_WRITE_TIMEOUT=15s`, `GOSLASH_MAX_FRAME_BYTES=1048576`.
- Client: `GOSLASH_SERVER_ADDR=localhost:9000`, `GOSLASH_COMMAND_PREFIX=/`. Only the first rune of the prefix is honored.

Build, Test & QA
- Run `go fmt ./...` (or `gofmt` via your editor) before commits; no tests currently ship, so `go test ./...` returns immediately.
- `make build` builds CGO-disabled server and client under `build/`; direct `go build ./cmd/server` / `./cmd/client` also supported.
- Manual smoke before releasing: clean `goslash.db`/`uploads/`, start server, register/login two users, join shared room, exchange chat, upload + download a file (with SHA reuse), and exercise `/pipe`.

Release Workflow
- Tag `vX.Y.Z` (e.g., `v1.0.0`) to trigger `.github/workflows/build-release.yml`; the matrix builds linux/macos/windows binaries with `-trimpath -s -w` and uploads artifacts.
- Manual dispatch accepts a `tag` input for ad-hoc rebuilds; ensure the tag matches the intended release name.
- Before tagging, update changelog/README, verify configs (non-default JWT secret), run lint/build steps, and capture manual QA notes.

Logging & Observability
- Server logs startup address, auth outcomes, room joins/leaves, broadcast ids, and file transfers with remote address context.
- Client logs connect/disconnect, command errors, and `/pipe` actions in the footer/status bar. Consider redirecting to a file when debugging long sessions.

Known Limitations & Follow-ups
- Transport is plaintext TCP (no TLS) and reconnect logic is basic; consider adding exponential backoff and connection health checks.
- No `/users` command yet—membership events only surface through room broadcasts.
- Lacking automated tests; prioritize end-to-end smoke coverage around auth, chat, upload/download.
- Large files move in a single frame; chunked transfers (`file_chunk`) remain unused pending future work.
