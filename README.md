# SlashChat

SlashChat is a socket-driven chat system built in Go. A Bubbletea-powered terminal client talks to a TCP server through a custom length-prefixed JSON protocol that supports authentication, room-based messaging, and file sharing.

## Highlights
- Go TCP server with JWT-authenticated sessions, room membership, persistent SQLite storage, and structured logging.
- Bubbletea TUI client with command/insert modes, ANSI-styled transcript view, chat IDs, auto-wrapping messages, tab-completed commands, and an ASCII splash screen when idle.
- File uploads store binaries under `uploads/` by SHA-256; `/download <message_id>` retrieves shared files on demand with contextual hints when authentication or room membership is missing.
- `/pipe` transport inspector renders the live JSON protocol feed with pretty-printed frames and quick history clearing.
- GitHub Actions pipeline builds CGO-free binaries for Linux, macOS, and Windows whenever a tag (or manual tag input) is provided.

## Requirements
- Go 1.25 or later (module target: Go 1.25.3).
- No external database dependencies; the server uses SQLite via the pure-Go driver.
- Optional: GNU Make for the provided build targets.

## Getting Started
1. Clone the repository and enter the project directory.
2. Build both server and client:
   ```
   make build
   ```
   Binaries are emitted into `build/` (`goslash-server`, `goslash-client`). Alternatively, run `go build ./cmd/server` and `go build ./cmd/client`.
3. Start the server (defaults to `:9000`, `goslash.db`, and `uploads/`):
   ```
   ./build/goslash-server
   ```
4. Launch the client (defaults to `localhost:9000`):
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
- `/join <room>` / `/leave` – Enter or exit a chat room; joining loads recent history.
- `/upload <path>` – Share a file. The client sends the SHA-256 first for instant reuse; otherwise the file is encoded and uploaded.
- `/download <message_id>` – Download a file that was posted in chat; files save to the current working directory.
- `/pipe` – Switch to the transport inspector; view raw JSON frames and use built-in commands to clear the feed.
- `/chat` / `/help` / `/quit` – Switch view, show built-in help, or exit the program.
- Typing text while connected and in insert mode sends a room message.
- Command input supports tab completion for the longest common prefix of matching commands. When trying to chat from outside the `/chat` view, the client will automatically switch back after sending (excluding `/pipe`).
- Status messages under the input box distinguish regular updates from errors using ANSI colors.

Message history shows timestamps, senders, and message IDs (useful for `/download`). File entries display the original filename alongside the SHA-derived storage key.

## Development Notes
- The codebase is organized into `cmd/` for entrypoints and `internal/` packages for client, server, protocol, config, and storage logic.
- Run `go test ./...` to execute unit tests. Build with `go build ./...` or the provided Makefile targets.
- Server logs include startup address, authentication outcomes, room membership events, and file transfers; the client logs connect/disconnect status in the footer.
- Releases are driven by `.github/workflows/build-release.yml`. Tagging (or manually dispatching with the `tag` input) compiles platform binaries and publishes them to a GitHub release via `softprops/action-gh-release`.

## Roadmap Ideas
- Add TLS transport, richer rate limiting, and offline message queues.
- Expand command set (e.g., room user listing, search, history pagination).
- Introduce automated end-to-end tests that script client/server interactions.
