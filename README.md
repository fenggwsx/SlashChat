# SlashChat

English | [中文](README_zh.md)

Current release: `v1.0.0`

SlashChat is a socket-driven chat system built in Go. A Bubbletea-powered terminal client talks to a TCP server through a custom length-prefixed JSON protocol that keeps the stack dependency-light while enabling authentication, room-based messaging, and SHA-verified file sharing.

## Highlights
- CGO-free Go TCP server with JWT-authenticated sessions, room hub broadcasting, SQLite persistence, and structured logging plus ack-based command responses.
- Bubbletea TUI client with command/insert modes, ANSI-styled transcript, tab-completed commands, status bar, and an ASCII banner when idle.
- File sharing pipeline that reuses binaries by SHA-256, stores uploads under `uploads/`, and persists metadata so `/download <message_id>` can retrieve shared files.
- `/pipe` transport inspector renders live JSON envelopes and supports quick history clearing for debugging the protocol.
- GitHub Actions workflow builds linux/macos/windows binaries on tags and publishes release artifacts via `softprops/action-gh-release`.

## Requirements
- Go 1.25 or later (module target: Go 1.25.3).
- CGO-disabled toolchains (`CGO_ENABLED=0`) to support cross-platform builds.
- No external database dependencies; the server uses SQLite via the pure-Go driver.
- Optional: GNU Make for the provided build targets.

## Getting Started
1. Clone the repository and enter the project directory.
2. Optionally remove any existing `goslash.db` file or `uploads/` directory to start fresh.
3. Build both server and client:
   ```
   make build
   ```
   Binaries are emitted into `build/` (`goslash-server`, `goslash-client`). Alternatively, run `go build ./cmd/server` and `go build ./cmd/client`.
4. Start the server (defaults to `:9000`, `goslash.db`, and `uploads/`):
   ```
   ./build/goslash-server
   ```
5. Launch the client (defaults to `localhost:9000`):
   ```
   ./build/goslash-client
   ```

Open a second terminal for additional clients. All interaction happens through slash commands and chat input inside the TUI.

## Configuration
Both binaries read environment variables for customization:

| Variable | Default | Description |
|----------|---------|-------------|
| `GOSLASH_LISTEN_ADDR` | `:9000` | Server listen address. |
| `GOSLASH_DB_PATH` | `goslash.db` | SQLite file path. |
| `GOSLASH_UPLOAD_DIR` | `uploads` | Directory where uploaded files are stored (SHA-256 filenames). |
| `GOSLASH_JWT_SECRET` | `replace-me` | Signing key for JWTs; change in production. |
| `GOSLASH_JWT_ISSUER` | `goslash` | JWT issuer claim. |
| `GOSLASH_JWT_EXPIRATION` | `24h` | Token lifetime. |
| `GOSLASH_READ_TIMEOUT` / `GOSLASH_WRITE_TIMEOUT` | `15s` | Socket deadlines. |
| `GOSLASH_MAX_FRAME_BYTES` | `1048576` | Maximum frame size in bytes. |
| `GOSLASH_SERVER_ADDR` | `localhost:9000` | Client default server address. |
| `GOSLASH_COMMAND_PREFIX` | `/` | Client slash command prefix (first rune used). |

## Using the Client
- `/connect [addr]` – Connect to the TCP server (uses configured address when omitted).
- `/register <username> <password>` – Create an account (hashed with bcrypt).
- `/login <username> <password>` – Authenticate and cache the JWT for future commands.
- `/join <room>` / `/leave [room]` – Enter or exit a chat room; joining loads recent history and begins receiving broadcasts.
- `/upload <path>` – Share a file. The client sends the SHA-256 first for instant reuse; otherwise the file is encoded and uploaded via `file_upload`.
- `/download <message_id>` – Download a file that was posted in chat; files save to the current working directory.
- `/pipe [clear]` – Switch to the transport inspector; view raw JSON frames or clear the buffer when debugging.
- `/chat` / `/help` / `/quit` – Switch view, show built-in help, or exit the program.
- Typing text while connected and in insert mode sends a room message. The status bar distinguishes regular updates from errors using ANSI colors.

## Manual QA Checklist
- Build fresh binaries with `make build` and remove any leftover `goslash.db`/`uploads/` artifacts.
- Start the server, connect two clients, and register/login distinct accounts.
- Join the same room, confirm history delivery, and exchange text messages.
- Upload a file from one client, verify the reusable SHA path (`upload_required` vs `ok`), and broadcast metadata to the other client.
- Use `/download <message_id>` on the receiving client to retrieve the file and confirm contents on disk.
- Exercise `/pipe` to watch the `file_upload_prepare`, `file_upload`, `chat_message`, and ack envelopes during the flow.

## Release Workflow
- Ensure documentation (README, AGENTS) and configs are up to date, run `go fmt ./...`, and perform the manual QA checklist.
- Tag the release (`git tag vX.Y.Z && git push origin vX.Y.Z`) to trigger `.github/workflows/build-release.yml`.
- The workflow builds CGO-disabled binaries for linux/macos/windows, uploads them as artifacts, and publishes a GitHub release via `softprops/action-gh-release`.
- For manual rebuilds without a tag ref, dispatch the workflow with the `tag` input set to the intended release name.

## Development Notes
- Run `go fmt ./...` (or rely on editor integration) before committing changes.
- `go test ./...` currently returns immediately because no automated tests ship; add coverage alongside new functionality whenever possible.
- `make build` is a convenience for producing CGO-disabled binaries; direct `go build ./cmd/server` and `go build ./cmd/client` are equivalent.
- Server logs include startup, auth outcomes, joins/leaves, and file transfers with remote addresses; the client logs notable events in the footer/status bar.

## Known Limitations
- Transport is plaintext TCP with minimal reconnect logic—no TLS, backoff, or health checks yet.
- `/users` is not implemented; membership updates surface only via chat events.
- File uploads transfer whole files in a single frame; the `file_chunk` message type is unused until streaming support lands.
- Automated integration tests are missing; rely on the manual QA checklist or extend with smoke tests.

## Roadmap Ideas
- Add TLS transport, richer rate limiting, and reconnect/backoff strategies for production deployments.
- Implement room presence commands (e.g., `/users`), history pagination, and search capabilities.
- Introduce automated end-to-end tests that script client/server interactions, including upload/download flows.
- Explore streaming uploads/downloads using the existing `file_chunk` envelope type for large files.
