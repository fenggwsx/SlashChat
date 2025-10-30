GoSlash Project Brief

Purpose
- Build a socket-driven terminal chat system that highlights custom protocol design, concurrent processing, authentication, persistence, and command-centric interaction.
- Deliver a concise but complete showcase for real-time messaging and file exchange from a command-first TUI client.

Core Components
- Server: Listens on TCP sockets, multiplexes authenticated sessions, enforces room membership, and coordinates message plus file routing.
- Client: Bubbletea-powered terminal UI with modal editing inspired by Vim; command palette accepts slash-prefixed actions.
- Shared Protocol: Pure JSON envelopes with explicit framing and identifier fields to prevent delimiter-based parsing issues.

Protocol Overview
- Transport: Raw TCP with length-prefixed JSON frames (e.g., 4-byte big-endian unsigned integer indicating upcoming JSON byte length).
- Envelope Fields: Unique message id, message type, timestamp, auth token (when applicable), payload object, optional metadata for file chunks.
- File Transfer: Payload includes filename, MIME hint, chunk index, total chunks, and Base64-encoded data length that respects max frame size.
- Reliability: Each client acknowledges actionable events; server may retransmit or mark delivery status when acknowledgements are missing.

Authentication and Identity
- Registration: Client submits username and password; server salts and hashes using bcrypt before persisting via GORM into SQLite.
- Login Flow: Successful credentials return a JWT signed with a server-side secret; subsequent client requests include the token in the protocol header.
- Authorization: JWT subject pins to account id; server validates token before processing room joins, message sends, or file transfers.

Persistence Model
- SQLite database accessed through GORM with connection pooling tuned for concurrent goroutines.
- Tables for users, rooms, room memberships, and message/file logs; migrations managed at startup.
- Audit-friendly timestamps stored in UTC, with soft-delete fields when practical.

Client Experience
- Dual-pane layout: left pane for room roster or context list, right pane for streaming messages, bottom command line for slash commands.
- Modes: command mode (navigation, completion, history) and insert mode (free text composition). Immediate hints for available commands as the user types.
- Slash Commands: `/join <room>`, `/leave`, `/upload <path>`, `/download <file>`, `/users`, `/help`, plus extensible hook for future actions.
- Autocompletion: Context-sensitive suggestions for room names, files, and command arguments.

Concurrency Strategy
- Server goroutines manage per-client read/write loops, authentication handlers, and room broadcasters; coordinate access with channels or synchronized maps.
- Client uses asynchronous subscriptions to handle inbound updates without blocking user input; Bubbletea tea.Cmd pattern keeps UI responsive.
- Background workers handle file chunk assembly and integrity verification.

Dependencies
- Pure Go SQLite driver (modernc.org/sqlite recommended for CGO-free builds).
- GORM for ORM abstractions and migration management.
- Bubbletea (github.com/charmbracelet/bubbletea) plus supporting lipgloss/bubbles libraries for TUI styling and interaction.
- bcrypt via golang.org/x/crypto/bcrypt for password hashing.
- JWT library (github.com/golang-jwt/jwt/v5 or equivalent) for token generation and validation.

Development Guidelines
- Stick to standard Go project layout (`cmd/server`, `cmd/client`, `internal/...`) and keep shared protocol structures in dedicated packages.
- Implement context-aware logging with structured fields; ensure sensitive data (password hashes, JWT secrets) never logged.
- Wrap socket operations with deadlines or cancellation contexts to prevent goroutine leaks.
- Validate and sanitize all client-supplied data before storage or broadcast; enforce payload size limits.
- Keep platform dependencies minimal to maintain cross-platform builds; use Go modules for dependency control.

Commit Conventions
- Use conventional prefixes (`feat`, `fix`, `docs`, `chore`, `test`, etc.) followed by a concise description in lowercase.
- Prefer imperative mood; omit trailing punctuation; amend commits when necessary to comply before merging.

Testing and Tooling
- Unit-test protocol marshalling, authentication flows, and database interactions with in-memory SQLite.
- Integration tests spawn ephemeral server and scripted client sessions to verify join, messaging, and file transfer.
- Use linting (golangci-lint) and gofmt/goimports; automate with simple make targets.

Security and Secrets
- Store JWT signing keys and database paths via environment variables or config files outside version control.
- Enforce strong password requirements and rate-limit login attempts to reduce brute-force attacks.
- Consider TLS termination or SSH tunnelling for transport security during deployment.

Future Extensions
- Message search, offline delivery queues, and richer room administration commands.
- Plugin interface for custom slash commands and bot integrations.
- Optional WebSocket bridge or REST API for non-terminal clients.
