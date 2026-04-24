# mgb-panel

Go monorepo for a `sing-box` control plane with two install profiles:

- `panel`: HTTPS admin panel + JSON API + tokenized user portal + PKI/CA + config compiler
- `node-agent`: lightweight node runtime that enrolls with the panel, fetches desired config over `mTLS`, validates it with `sing-box check`, and applies it with rollback support

## What is implemented

- SQLite-backed domain model for:
  - nodes with address/IP, enroll tokens, node certificates, node status
  - users, subscriptions, subscription tokens
  - inbound profiles, node inbound bindings
  - topology links, config revisions, audit events
- HTTPS panel with self-managed CA and server certificate
- Node enrollment flow:
  - bootstrap token
  - local CSR generation on node
  - panel-side certificate signing
  - further communication over `mTLS`
- Server-rendered admin dashboard with forms for:
  - nodes
  - users
  - subscriptions
  - inbound profiles
  - node/profile bindings
  - topology links
- Dark Russian-language UI with per-entity pages and node bootstrap commands
- Tokenized user portal and plaintext subscription feed
- `sing-box` config compiler for:
  - `vless`
  - `trojan`
  - `hysteria2`
  - `shadowsocks`
  - `wireguard` topology outbounds
- `node-agent` reconcile loop with:
  - heartbeat
  - config fetch
  - `sing-box check`
  - staged apply
  - rollback to last known good config
- Docker-first install artifacts for:
  - panel
  - node-only agent
  - optional local node as a separate `local-node` Docker Compose service

## Repository layout

```text
cmd/panel
cmd/node-agent
internal/controlplane
internal/database
internal/nodeagent
internal/pki
internal/singbox
internal/subscriptions
internal/topology
deploy/panel
deploy/node
scripts
```

## Local development

Requirements:

- Go 1.22+
- external `sing-box` binary available in `PATH` if you want to run a node locally

Run tests:

```bash
GOCACHE=/tmp/go-build-cache GOPATH=/tmp/go go test ./...
```

Run panel:

```bash
go run ./cmd/panel \
  -listen :8443 \
  -base-url https://localhost:8443 \
  -data-dir ./var/panel
```

Open:

- dashboard: `https://localhost:8443/`
- CA bundle: `https://localhost:8443/api/pki/ca`

The panel generates its own CA and server certificate under `./var/panel/pki`.

## Panel workflow

1. Start the panel.
2. Create a node from the dashboard or `POST /api/admin/nodes`.
3. Set the node address/IP during creation.
4. Copy the node `enroll_token` or use the generated install command on the Nodes page.
5. Download the CA bundle from `/api/pki/ca` or let the installer fetch it by fingerprint.
6. Start `node-agent` with the panel URL and CA.
7. Bind inbound profiles to the node.
8. Create users and subscriptions.
9. The node will fetch and apply the generated `sing-box` config automatically.

## Run node-agent manually

```bash
go run ./cmd/node-agent \
  -panel-url https://localhost:8443 \
  -state-dir ./var/node \
  -bootstrap-token <ENROLL_TOKEN> \
  -panel-ca-file ./var/panel/pki/ca.pem \
  -singbox-binary sing-box
```

## Docker-first installs

Panel:

```bash
./scripts/install-panel.sh
```

Node-only:

```bash
./scripts/install-node.sh
```

If the panel is already running, it also exposes:

```bash
curl -fsSL https://your-panel.example.com/install/node.sh | bash
```

The node installer prompts for:

- git repository URL
- panel URL
- bootstrap token
- panel CA SHA-256 fingerprint

Then it downloads the CA certificate from the panel, verifies the fingerprint, writes the env file, and starts `node-agent` via Docker Compose.

Defaults:

- repository URL: `https://github.com/Beykus-Y/mgb-panel`
- branch/ref: `main`

If the installer detects an existing installation in the target directory, it asks whether to:

- update
- remove
- cancel

Notes:

- `Dockerfile.node` copies `sing-box` from `ghcr.io/sagernet/sing-box:v1.13.11` by default.
- If that image exposes the binary at a different path in your environment, override `SINGBOX_BINARY_PATH`.
- `deploy/node/docker-compose.yml` uses `network_mode: host` and `NET_ADMIN` because node deployments commonly need direct networking control.
- Local node mode no longer runs `sing-box` inside the panel process. Compose starts a separate dormant `local-node` service with host networking; click "Включить локальный узел" in the panel to write its bootstrap token and enroll it.

## HTTP surfaces

Admin/UI:

- `GET /`
- `POST /admin/nodes`
- `POST /admin/users`
- `POST /admin/subscriptions`
- `POST /admin/inbounds`
- `POST /admin/bindings`
- `POST /admin/topology`

Admin JSON API:

- `GET|POST /api/admin/nodes`
- `GET|POST /api/admin/users`
- `GET|POST /api/admin/subscriptions`
- `GET|POST /api/admin/inbounds`
- `GET|POST /api/admin/bindings`
- `GET|POST /api/admin/topology`
- `GET /api/admin/revisions`

Node API:

- `GET /api/pki/ca`
- `GET /install/panel.sh`
- `GET /install/node.sh`
- `POST /api/node/enroll`
- `POST /api/node/heartbeat`
- `GET /api/node/config`
- `POST /api/node/ack`

User portal:

- `GET /portal/{subscription_token}`
- `GET /subscription/{subscription_token}`

## Current scope limits

- SQLite only
- no billing
- no auth system for admins yet
- no PostgreSQL
- no cluster scheduler or background queue
- topology model is `WireGuard`-oriented and intentionally narrower than full mesh orchestration
- `sing-box` is managed as an external binary, not embedded as a Go library
