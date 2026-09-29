# iroh-lighthouse

Topic rendezvous and address lookup for [iroh](https://iroh.computer) nodes.

Run a lighthouse at a plain URL such as `https://iroh.ichor.io`. Point nodes at
it with a topic and a TTL, and each node gets back every other node currently
on that topic, in one round trip. Announcements are signed with the node's own
iroh key, topics are protected by a keypair derived from a shared secret, and
the same server speaks HTTPS and native iroh over one protocol.

```
            ┌──────────┐   ┌──────────┐
  clients → │ HTTP/axum│   │ iroh ALPN│ ← clients
            └────┬─────┘   └────┬─────┘
                 │ Request      │ Request
                 ▼              ▼
            ┌─────────────────────────┐
            │ handle(Request)->Response│  signatures, TTLs,
            │        Registry         │  limits, snapshot
            └─────────────────────────┘
```

## Crates

| Crate | What it is |
|---|---|
| `iroh-lighthouse` | Library: protocol types, topic keys, the `Lighthouse` client, self-refreshing `Session`, and `LighthouseLookup` (an iroh `AddressLookup`). Feature `cli` adds the `lighthouse` binary. |
| `iroh-lighthouse-server` | The server binary, also usable as a library for embedding and tests. |

Requires Rust 1.91 or newer and iroh 1.2.

## Quick start

Run a lighthouse locally:

```sh
cargo run -p iroh-lighthouse-server -- --no-relays
```

It listens on `127.0.0.1:8080` for HTTP, binds an iroh endpoint, creates
`lighthouse.key` and `lighthouse.snapshot.json` in the working directory, and
prints its endpoint id. Drop `--no-relays` for anything that should be reachable
from other machines.

Join a topic from two terminals:

```sh
cargo run -p iroh-lighthouse --features cli --bin lighthouse -- \
    --url 127.0.0.1:8080 --no-relays join --topic demo --secret hunter2
```

`--url` takes a full URL or a bare host. A bare host gets `https://`, except
`localhost` and IP addresses, which get `http://`.

Each `join` prints the other members and keeps printing as they come, go, or
change address, polling the topic every 10 seconds by default (`--poll` adjusts
it). `lookup` reads without joining, `resolve <ENDPOINT_ID>` queries the directory,
`info` describes the server, and `--via-iroh` switches any command to the iroh
carrier after learning the lighthouse's address over HTTP.

## Using the library

```rust
use std::time::Duration;
use iroh::{Endpoint, endpoint::presets};
use iroh_lighthouse::{Lighthouse, LighthouseLookup, Topic};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let url: url::Url = "https://iroh.ichor.io".parse()?;

// Optional: let iroh resolve any published peer by id through the lighthouse,
// and publish this endpoint's own address to the lighthouse directory.
let endpoint = Endpoint::builder(presets::N0)
    .address_lookup(LighthouseLookup::http(url.clone()))
    .bind()
    .await?;

// Join a topic. The session re-announces at half the granted TTL, re-announces
// when the endpoint's address changes, polls the topic every 10 seconds for
// membership changes (`join_with` sets the interval), and unregisters on `leave`.
let lighthouse = Lighthouse::http(url);
let topic = Topic::with_secret("my-app/cluster-1", b"shared secret");
let session = lighthouse.join(&endpoint, topic, Duration::from_secs(3600)).await?;

for peer in session.peers() {
    // peer.addr is a full iroh EndpointAddr: dial it directly.
    let _conn = endpoint.connect(peer.addr.clone(), b"my-app/1").await?;
}

// Or watch for changes: wakes when a member joins, leaves, or moves.
let mut peers = session.watch_peers();
peers.changed().await?;

session.leave().await?;
# Ok(()) }
```

One-shot calls are available too: `lighthouse.announce(..)`, `lookup(..)`,
`resolve(..)`, and `info()`. `Lighthouse::iroh(endpoint, lighthouse_addr)`
gives the same API over the iroh carrier.

## How it works

**Topics.** A topic is a name plus an optional secret. The client derives an
ed25519 keypair from both with BLAKE3 (derive-key mode). The public key is the
wire topic id, so the server never sees names or secrets and topic ids are safe
to log. A topic with an empty secret is public: anyone who knows the name can
derive the same key.

**Announce.** A node sends its full `EndpointAddr`, a TTL, and a timestamp,
signed by its own key and by the topic key. The server verifies both, clamps
the TTL to its configured range, stores the entry with expiry `timestamp + ttl`,
and replies with the other members. A TTL of zero unregisters. Announcing with
no topic publishes to the directory instead, which is what `LighthouseLookup`
uses so peers can be resolved by id.

**Lookup** reads a topic with only the topic signature. **Resolve** reads the
directory with no signature, like any public discovery service. **Info**
returns the server's iroh address and limits.

**Carriers.** Over HTTP the routes are `POST /v1/announce`, `POST /v1/lookup`,
`GET /v1/resolve/{id}`, `GET /v1/info`, and `GET /v1/health`. Over iroh the
ALPN is `iroh-lighthouse/1`, one JSON request per bidirectional stream. Both
carry the same JSON messages and hit the same handler.

**Persistence.** The registry lives in memory and is written atomically to a
JSON snapshot when it changes, and on shutdown. Entries carry absolute expiry
times, so a restart of any length behaves correctly.

## Server configuration

Every flag has an environment variable prefixed `LIGHTHOUSE_`, and durations
accept humantime syntax such as `30s`, `5m`, `7d`.

| Flag | Default | Meaning |
|---|---|---|
| `--http-listen` | `127.0.0.1:8080` | HTTP bind address. `--no-http` disables. |
| `--iroh-port` | `0` | UDP port for the iroh carrier on IPv4. `--no-iroh` disables, `--no-relays` skips the n0 relay infrastructure. |
| `--iroh-external-addr` | none | Public `IP:PORT` to advertise for the iroh carrier when iroh cannot discover it, such as behind a Docker port mapping. Repeatable; the environment variable takes a comma-separated list. |
| `--secret-key-file` | `lighthouse.key` | iroh secret key, created with mode 0600 if missing. Keeps the endpoint id stable. |
| `--snapshot` | `lighthouse.snapshot.json` | Registry snapshot. `--no-snapshot` keeps everything in memory. |
| `--snapshot-interval` | `5s` | How often to write when dirty. |
| `--sweep-interval` | `30s` | How often to drop expired entries. |
| `--min-ttl` / `--max-ttl` | `10s` / `7d` | Range a node's TTL is clamped to. |
| `--max-skew` | `5m` | Tolerated timestamp drift. |
| `--max-peers-per-topic` | `256` | New members beyond this get `topic_full`. |
| `--max-topics` | `10000` | New topics beyond this get `too_many_topics`. |

## Deploying at iroh.ichor.io

The server speaks plain HTTP. Terminate TLS in front of it.

Caddyfile:

```
iroh.ichor.io {
    reverse_proxy 127.0.0.1:8080
}
```

systemd unit (`/etc/systemd/system/iroh-lighthouse.service`):

```ini
[Unit]
Description=iroh lighthouse
After=network-online.target
Wants=network-online.target

[Service]
User=lighthouse
StateDirectory=iroh-lighthouse
WorkingDirectory=/var/lib/iroh-lighthouse
ExecStart=/usr/local/bin/iroh-lighthouse-server --iroh-port 4433
Environment=RUST_LOG=info
Restart=on-failure
KillSignal=SIGTERM
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
```

Open UDP 4433 for the iroh carrier. The key and snapshot live in the state
directory. On SIGTERM the server writes a final snapshot before exiting.

### Docker

On a bridge network iroh only sees the container's own address, and it can
only learn the host's public address through the relay if outbound UDP works
from the container. Pin the UDP port, publish it, and state the public address
so peers can dial directly either way:

```yaml
services:
  lighthouse:
    build: .
    ports:
      - "8080:8080"
      - "4433:4433/udp"
    environment:
      LIGHTHOUSE_HTTP_LISTEN: 0.0.0.0:8080
      LIGHTHOUSE_IROH_PORT: "4433"
      LIGHTHOUSE_IROH_EXTERNAL_ADDR: 203.0.113.5:4433
    volumes:
      - lighthouse:/data
    working_dir: /data
volumes:
  lighthouse:
```

Open UDP 4433 in the host or cloud firewall too. Once it works, `GET /v1/info`
lists the public address and a relay-less dial to it succeeds. `network_mode:
host` is the alternative that needs neither the port mapping nor the flag.

Clients then use `https://iroh.ichor.io` as the lighthouse URL. Anyone who
wants the iroh carrier calls `info` first, or is handed the lighthouse
`EndpointAddr` another way.

## Development

```sh
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features
```

Integration tests start a real server in-process with relays disabled and run
real iroh endpoints against it over both carriers.

## License

MIT or Apache-2.0, at your option.
