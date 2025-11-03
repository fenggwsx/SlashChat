SlashChat Agent Brief

Overview
- SlashChat ships a TCP chat stack with a Go server, Bubbletea TUI client, authentication, room-based messaging, and basic file sharing.
- The codebase follows the Go module layout (`cmd/server`, `cmd/client`, `internal/...`) and targets CGO-free builds for Linux, macOS, and Windows.
- Real-time communication uses a custom JSON protocol over raw TCP with length-prefixed frames; both client and server keep asynchronous loops to remain responsive.

Core Architecture
- Server (`internal/server`): Manages TCP sessions, JWT-authenticated users, room membership, message persistence, and file uploads/downloads. Each client has dedicated read/write goroutines coordinated through a hub.
- Client (`internal/client`): Bubbletea single-view interface with command and insert modes, chat history viewport, and ANSI color styling. Displays an ASCII “SLASH CHAT” banner (go-figure) until the user joins a room.
- Protocol (`internal/protocol`): Defines envelopes, command payloads, message kinds, and length-prefixed framing helpers.

Authentication & Identity
- Registration and login are handled through `/register` and `/login`; passwords are hashed with `bcrypt`.
- On success the server issues JWTs (golang-jwt) whose subject is the user ID; the client reuses the token in subsequent requests.
- Sessions log authentication attempts and include basic rate-limiting hooks (extend if brute-force mitigation is needed).

Persistence
- SQLite (modernc.org/sqlite via GORM) stores `users` and `messages`. Messages carry `kind` (`text` or `file`), `content` (text body or original filename), and optional `file_sha`.
- File binaries live in `uploads/` and are named after their SHA-256 digest. GORM is configured to suppress “record not found” errors in logs.
- Migrations run at startup; all timestamps use UTC.

Messaging & File Flow
- Every frame is a JSON envelope with `id`, `type`, `timestamp`, optional `token`, and `payload`.
- Text messages persist the raw content. File messages require the client to send the SHA first: existing files are acknowledged immediately, otherwise the full payload is base64-encoded and written to disk before persistence.
- `/download <message_id>` requests the stored file via message ID; chat history includes IDs (especially for file entries) so users can target downloads.

Client Experience
- Chat and home views were merged: the default screen shows the ASCII banner and quick tips; joining a room swaps in the scrolling transcript.
- Commands support history/completion hints. Message list shows sender, room, timestamp, and message ID when relevant.
- Status bar reflects connection state, current room, and last log message; connect/disconnect events log to the TUI footer.

Command Reference
- `/connect [addr]` — open a TCP session (defaults to configured server).
- `/register <username> <password>` — create an account.
- `/login <username> <password>` — authenticate and cache the JWT.
- `/join <room>` / `/leave` — enter or exit a chat room.
- `/upload <path>` — send a file (performs SHA quick check).
- `/download <message_id>` — fetch a previously shared file.
- `/users` — list room members (via server event).
- `/chat` / `/help` / `/quit` — switch view, show help, or exit.
- Regular text (without slash) posts a message to the active room.

Logging & Observability
- Server prints startup address, authentication results, joins/leaves, message broadcasts, and file transfers with remote addresses.
- Client logs connect/disconnect lifecycle and notable errors.
- Consider shipping logs to a centralized sink or adding structured JSON if deploying beyond local setups.

Build & Release
- `make` targets wrap gofmt/goimports, vet, and build tasks (extend as needed).
- GitHub Actions workflow (`.github/workflows/build-release.yml`) builds CGO-disabled binaries for linux/amd64, macos/amd64, and windows/amd64. It triggers on tags and supports manual dispatch with an explicit tag input, publishing artifacts via `softprops/action-gh-release`.
- Recommended local checks: `go fmt ./...` on both server and client.

Future Opportunities
- Improve transport security (TLS or SSH tunnel), add backoff/retry on reconnect, and enforce stricter password/command rate limits.
- Expand `/users` to show presence metadata, add pagination/search for history, and surface upload progress for large files.
- Integration tests currently limited; consider automated client/server smoke tests around upload/download and auth flows.
