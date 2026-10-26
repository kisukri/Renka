# Renka

> A lightweight [Matrix](https://matrix.org) homeserver written in Go.
> One static binary + one SQLite file, ~10–25MB RAM, runs on small x86 / ARM Linux boxes.

[日本語](README.md) · **English**

---

In renga (連歌), one poet writes a verse, the next adds another, and it passes on from there —
a poem no one could write alone, born from everyone's words. Renka is named after it.

Renka is a lightweight Matrix homeserver written in Go, about 13,000 lines. One executable plus one
SQLite database file, ~10–25MB idle, well suited to low-end Linux servers (x86 / ARM).

It works with standard Matrix clients such as Element, FluffyChat and Cinny, with push notifications
while the app is in the background. Federation with other servers (Synapse included) is supported and off
by default (see below).

## How Matrix works (in brief)

**1. Everything is "an event in a room."**
DMs and group chats are all rooms. Everything that happens in a room is a JSON event: sending a
message is `m.room.message`, renaming the room is `m.room.name`, someone joining is
`m.room.member`. Each event has a unique `event_id`, a sender, a timestamp and content.

**2. Events come in two kinds.**
- **Message events**: chat messages, reactions, etc. — just appended to the timeline.
- **State events**: carry a `state_key` and describe "what the room is like now" — its name, who is
  a member, who has how much power. For a given `(type, state_key)` the newest one wins. The latest
  values of all state events together = the room's current state.

**3. Permissions use power levels.**
The `m.room.power_levels` state event sets each person's level (owner 100, ordinary user 0) and how
much is needed for each action (rename 50, kick 50, change power 100…). For every event it receives
the server checks against current state: is the sender in the room? high enough? You cannot grant
anyone more power than you have.

**4. How clients receive messages: /sync long-polling.**
A client calls `GET /sync?since=<last token>&timeout=30000`. If something is new it returns at once;
otherwise it hangs for up to 30 seconds. The reply carries new messages, membership changes, read
receipts, typing, key changes and so on, plus a new token `next_batch`. This implementation numbers
every change with **one global incrementing counter**, so a token `s123` means "you already have
everything up to 123."

**5. End-to-end encryption: the server is only a postman.**
Encryption happens on the client (Olm/Megolm). The server only stores each device's public keys
(`/keys/upload`, `/keys/query`), hands out one-time keys (`/keys/claim`), relays encrypted
"to-device" messages between devices (`/sendToDevice`), and keeps the client-encrypted key backup.
The server never sees plaintext.

**6. Federation (off by default).**
True decentralization comes from federation: each server signs events, room state is maintained
jointly by several servers, events are linked by `prev_events` into a directed acyclic graph, and
forks are merged with "state resolution v2." This is the most complex part of Matrix and the main
reason Synapse and tuwunel are so large. Renka does all of it: rooms can be shared with other
servers (Synapse included), with state resolution checked against Synapse's own implementation,
and end-to-end encryption works with users of other servers too.

## Code layout

```
cmd/renka/        the tiny main that starts it
internal/server/  the server itself (table below) and its tests
deploy/           example config, Docker / systemd / Caddy / Nginx files, install scripts
test/             API tests (Python), the test server config, Synapse test-data scripts
```

Go keeps one package per directory, so the server lives together in `internal/server/`.

| `internal/server/` | Contents |
|---|---|
| `main.go` | config file, command line (run / add user / change password) |
| `server.go` | database schema, write transactions, global counter, routing table, status page |
| `auth.go` | registration, login, devices, password hashing (PBKDF2), login rate-limiting |
| `events.go` | event storage, renka's own send rules, redaction |
| `pdu.go` | room authorization rules (room versions 10/11), signed events, event graph |
| `rooms.go` | create/join/invite/kick/ban, send, state, history, threads, aliases, room directory |
| `sync.go` | `/sync` long-polling, filters, encrypted device-list changes |
| `account.go` | profile, account data, push rules, typing, read receipts |
| `e2ee.go` | device keys, one-time keys, cross-signing, to-device messages, key backup |
| `media.go` | file upload/download, thumbnails |
| `push.go` | pushers, push rule evaluation, delivery to push gateways |
| `admin.go` | admin commands, `renka admin` socket, admin room bot |
| `federation.go` | canonical JSON, signing, server keys, discovery, signed requests |
| `fedkeys.go` | other servers' keys (current and retired), notary lookups |
| `stateres.go` | state resolution v2 |
| `fedstate.go` | room state after each event (state groups), current state |
| `fedin.go` | receiving events: checks, fetching missing events and state, storage |
| `fedserver.go` | federation endpoints: transactions, events, state, joins, leaves, invites |
| `fedout.go` | sending to other servers; joining and inviting across servers |
| `fede2ee.go` | end-to-end encryption across servers: device lists, keys, to-device messages |
| `fedmedia.go` | files across servers: serving, fetching, caching |

## Install

There are two ways. Either way you **copy and paste the commands below as they are**; the script asks for
your domain and the admin's username and password, and there's nothing else to edit.

Before you start, point your domain's DNS (A record) at this server's IP address.

### A. Docker (recommended)

Needs Docker and Docker Compose v2 (`docker compose`).

```bash
git clone https://github.com/kisukri/Renka.git
cd Renka
sudo sh deploy/docker-setup.sh
```

What the script does:
1. Writes `data/renka.conf`: your domain, plus the container paths `/data/...` and `listen = 0.0.0.0:8008`.
2. Gives `data` to the container's user (uid 10001).
3. Builds and starts the image, and checks that it's up.
4. Creates the admin user.
5. Prints the commands for HTTPS.

- **Update**: `cd Renka && git pull && sudo sh deploy/docker-setup.sh` (config and data are kept)
- **Logs**: `docker compose logs -f renka`
- **Backup**: `docker compose stop`, then copy the `data` directory.

The image is built from the empty `scratch`: just the binary and CA roots (~19MB, no libc, no shell). The
container runs as non-root (uid 10001), with a read-only root filesystem and all capabilities dropped
(see `docker-compose.yml`).

### B. Directly on Linux (systemd)

Needs systemd and Go 1.27+ ([go.dev/dl](https://go.dev/dl/)).

```bash
git clone https://github.com/kisukri/Renka.git
cd Renka
sudo sh deploy/install.sh
```

What the script does:
1. Builds renka and installs it to `/usr/local/bin/renka`.
2. Creates the `renka` user plus `/etc/renka` and `/var/lib/renka`, and writes `/etc/renka/renka.conf`.
3. Installs and starts the systemd service, and checks that it's up.
4. Creates the admin user.
5. Prints the commands for HTTPS.

- **Update**: `cd Renka && git pull && sudo sh deploy/install.sh` (config and data are kept)
- **Logs**: `journalctl -u renka -f`
- **Backup**: `sudo systemctl stop renka`, then copy `/var/lib/renka`.

### Forgot a password

```bash
# Docker (in the Renka directory)
docker compose exec renka /renka passwd -config /data/renka.conf -u USERNAME
# systemd
sudo runuser -u renka -- renka passwd -config /etc/renka/renka.conf -u USERNAME
```

It asks for the new password twice (nothing is shown while you type) and logs that user out everywhere.

### Troubleshooting

| Symptom / log | Cause and fix |
|---|---|
| `public_base_url ... must start with https://` | `public_base_url` needs `https://`; `server_name` is just the domain |
| `mkdir /var: read-only file system` | In Docker, `database` / `media_dir` must be under `/data/...` |
| `permission denied` | Docker: `sudo chown -R 10001:10001 data`; systemd: `sudo chown -R renka:renka /var/lib/renka` |
| Port 8008 is in use | Check you're not running both the Docker and the systemd version |

If a hand-edited config got you into trouble, delete `data/renka.conf` (systemd: `/etc/renka/renka.conf`) and
run the script again; it writes a fresh one.

## Configuration

The config file is `key = value` lines; lines starting with `#` are comments (not allowed at the end of
a line). It lives at `data/renka.conf` (Docker) or `/etc/renka/renka.conf` (systemd). Restart Renka
after changing it (`docker compose restart` or `sudo systemctl restart renka`).

| Key | Default | Meaning |
|---|---|---|
| `server_name` | (required) | Just the domain, no `https://`. User IDs become `@name:domain`, so **never change it later** |
| `public_base_url` | `https://` + `server_name` | The URL apps connect to. Starts with `https://` |
| `listen` | `127.0.0.1:8008` | Listen address. `0.0.0.0:8008` in Docker (`docker-compose.yml` still publishes it on 127.0.0.1 only) |
| `database` | `data/renka.db` | Database file. `/data/renka.db` in Docker |
| `media_dir` | `data/media` | Where uploads are stored. `/data/media` in Docker |
| `registration` | `false` | Allow sign-up from apps. Better left off; create accounts with `renka adduser` |
| `registration_token` | none | Invite code required to sign up when registration is on (8+ characters) |
| `max_upload_mb` | `50` | Per-file limit. Keep the proxy limit (Caddy `max_size`, Nginx `client_max_body_size`) at least this big |
| `media_quota_mb` | `1024` | Total upload size per user; admins are exempt. `0` = unlimited |
| `remote_media_cache_mb` | `1024` | How much of other servers' files (images, voice, video) to keep locally; oldest go first. `0` = no cap |
| `push` | `true` | Push notifications (see below). `false` means Renka makes no outbound requests for push |
| `federation` | `false` | Share rooms with other servers (see below) |
| `trusted_key_servers` | `matrix.org` | Where to verify other servers' signing keys when they don't answer themselves. Comma-separated; empty trusts only keys from the server itself |
| `federation_address` | host of `public_base_url`:443 | Where other servers should connect to you |
| `search_all_users` | `false` | Let user search list everyone. Off: only people sharing a room or in public rooms (a full ID always works) |
| `memory_limit_mb` | `0` | Soft memory limit; on small machines Go returns memory more eagerly. `0` = none |
| `trust_proxy` | `false` | Set `true` behind a reverse proxy so the login rate limit counts real client IPs |

## Reverse proxy & HTTPS

Renka listens on `127.0.0.1:8008` and speaks plain HTTP; put Caddy or Nginx in front for TLS.
Proxy `/_matrix/*` and `/.well-known/matrix/*` (and `/` for the status page) to it.

**Caddy** (`deploy/Caddyfile`): gets and renews HTTPS certificates automatically. The install script ends
by printing a command that writes it to `/etc/caddy/Caddyfile` with your domain filled in
([installing Caddy](https://caddyserver.com/docs/install)).

**Nginx** (`deploy/renka.nginx.conf.example`): replace `matrix.example.com` with your domain, put it in
`/etc/nginx/sites-available/` and link it into `sites-enabled/`. Get the certificate first with
`sudo certbot --nginx -d your-domain`, then `sudo nginx -t && sudo systemctl reload nginx`. What it covers:
`client_max_body_size` for uploads, `X-Forwarded-For` for `trust_proxy`, a long `proxy_read_timeout` for
`/sync` long-polls, and the `/` status page. On nginx older than 1.25.1, drop `http2 on;` and use
`listen 443 ssl http2;`.

**Split domains**: if `server_name` is `example.com` but the server runs at `matrix.example.com`, serve
`{"m.homeserver":{"base_url":"https://matrix.example.com"}}` at `/.well-known/matrix/client` on
`example.com` (and, for federation, `{"m.server":"matrix.example.com:443"}` at `/.well-known/matrix/server`).
With Caddy:

```
example.com {
	header /.well-known/matrix/* Access-Control-Allow-Origin *
	respond /.well-known/matrix/client `{"m.homeserver":{"base_url":"https://matrix.example.com"}}`
	respond /.well-known/matrix/server `{"m.server":"matrix.example.com:443"}`
}
```

Renka has **no web chat UI** — opening the domain in a browser just shows a tiny plain-text page
confirming the server is up. To chat, point a Matrix client (Element, etc.) at `https://your-domain`.

## Push notifications

Phones get notified while the app is in the background. When a message arrives that the user's
notification settings say should alert them, Renka tells their push gateway (Element uses
matrix.org's), which wakes the app through Apple / Google.

Only the event ID, room ID and unread count leave your server; the gateway and Apple / Google never
see the message or who sent it. The app fetches the message from your server itself. The gateway
address comes from the app, so Renka refuses to connect to private or internal addresses.
`push = false` turns all of this off.

## Admin commands

Server admins (`renka adduser -admin`, or `users make-admin`) can manage the server two ways:

- **On the server**: `renka admin -config /etc/renka/renka.conf users list` (run as the renka user or
  root; Docker: `docker compose exec renka /renka admin -config /data/renka.conf users list`). It
  talks to the running server through a socket only that user can open.
- **In the admin room**: every admin is invited to "Renka admin" by the bot @renka. Type commands
  there, e.g. `users list` or `!admin rooms list`. Only current admins are obeyed; replies that
  contain a password are deleted after 10 minutes.

`help` lists everything: accounts (list, info, create, reset password, log out, deactivate, grant /
revoke admin), rooms (list, info, shut down), media (usage, delete) and server stats.

## Federation (experimental, off by default)

With `federation = true` your users can share rooms with users of any other Matrix server:

- **Join rooms elsewhere** by ID or alias (`#room:matrix.org`), and accept invites from other servers.
- **Invite people from other servers** into your rooms; their servers can join, leave, be kicked or banned.
- **Messages, state changes, typing and read receipts** go both ways. Scrolling up in a room you
  joined fetches its older history from the other servers.
- **End-to-end encryption** with users of other servers: device keys, one-time keys, cross-signing
  keys and to-device messages (how room keys travel) go across servers, and clients are told when
  someone's devices change. Device names are never shared with other servers.
- **Forks are merged** with state resolution v2 when servers change things at the same time.
  Synapse and renka reach the same state; this is tested against a real Synapse.
- **Missing events are fetched** after an outage, and delivery to unreachable servers is retried with
  backoff (up to six hours), without losing anything across restarts.
- **Every event is checked**: its signature (keys fetched from its server, or from the notary in
  `trusted_key_servers`, `matrix.org` by default like Synapse), its content hash (tampered events are
  kept only in redacted form) and the room's authorization rules. Events failing only the current state
  are "soft-failed": kept in the graph, never shown.
- **Images, voice and video**: other servers' files are fetched the first time someone opens them and
  kept locally (up to `remote_media_cache_mb`). Ours are served to other servers too (Matrix 1.11
  authenticated media, with the legacy path for older servers).
- **Privacy**: servers only see rooms they have users in. Messages from before they joined are served
  redacted when the room's history is members-only. Server ACLs (`m.room.server_acl`) are honoured.
- **Limits**: rooms whose state is larger than 20,000 events (or 32 MB) are too big to join.

Rooms created with `"m.federate": false`, and rooms from before you turned federation on, stay local.
Federated rooms only allow integers in event content, as signed events require (Synapse does the same).

**Not yet:** presence (online status), room upgrades, and the room directory of other servers.

Other servers find you at `https://your-domain/.well-known/matrix/server` (served by Renka), which
points them to port 443, so no extra port is needed. Your reverse proxy already forwards `/_matrix/*`
and `/.well-known/matrix/*`. Set `federation_address` if they should connect somewhere else.

Leave it off if you don't need it: federation means accepting requests from servers you don't
control.

## Build it yourself

Needs Go 1.27+. You can cross-compile a Linux build from any OS:

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o renka-linux-arm64 ./cmd/renka
```

## Test

```bash
go test -race ./...                   # unit tests, plus the fuzz seed corpus
go test -run='^$' -fuzz=FuzzEndpoints ./internal/server # fuzz ~40 endpoints with random input (Ctrl-C to stop)

./renka -config test/test.conf     # start a test server
python test/api_test.py               # in another terminal: ~70 API tests
python test/edge_test.py              # ~100 edge-case / abuse / regression checks
```

`internal/server/testdata/synapse_vectors.json.gz` holds cases generated by Synapse's own code
(`test/synapse_vectors.py`); `go test` checks renka's auth rules, redaction, hashes, signatures
and event IDs give the same results. `test/check_pdus.py` has Synapse verify events signed by renka.
`internal/server/testdata/stateres_vectors.json.gz` (`test/stateres_vectors.py`) holds forked rooms resolved by
Synapse. `TestSynapseInterop` shares rooms with a real Synapse in both directions; see
`test/synapse_interop.md` to run it.

`edge_test.py` ends by tripping the login rate limit for your IP, so restart the
test server before running the suites again.

## Release

Push a tag starting with `v`; GitHub Actions builds the x86 and ARM binaries and publishes a release:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

## Supported

Registration (optional token), login, multiple devices, password change · create rooms (DM / group
/ public), invite, join, leave, kick, ban · send, edit, reactions, redaction · threads · history
pagination, jump to an event · read receipts, unread counts, typing · room aliases, public room
directory, user search · avatar & display name · end-to-end encryption (key upload/query/claim,
cross-signing, to-device messages, key backup) · file & image upload, thumbnails · push rules and
**push notifications** · **admin commands** (CLI and admin room) · per-user media quota ·
restricted rooms (join through membership of another room) · **federation**: rooms shared with other
servers (joins, invites, messages, state, history, typing, receipts, state resolution, end-to-end
encryption, images / voice / video), profile and alias queries

## Not yet

- Presence (online status), and browsing other servers' room directories
- Message search (`/search`), Spaces hierarchy APIs, knocking, room upgrades
- An HTTP admin API (Synapse-compatible) for web admin panels
- TURN server config for voice/video calls
- History visibility only distinguishes "members see all history / can't see new messages after
  leaving"; it does not separate the `joined` / `invited` modes

---

## License

[MIT](LICENSE) — Copyright (c) 2026 Renka contributors.

Free to use, modify and distribute; provided "as is", without warranty. See the [LICENSE](LICENSE)
file for the full text.
