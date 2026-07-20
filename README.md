# Chat Store

Persistence for group-chat users' key packages — the **chat-store** HTTP service
(formerly `keypackage-registry`), extracted from
[libchat](https://github.com/logos-messaging/libchat) so it can be deployed on
its own.

Standalone service that caches MLS KeyPackages keyed by **`device_id`**, so a
client can fetch a contact's keypackage without an out-of-band exchange.
Throwaway by design: scheduled to be replaced by a λLEZ-based service in v0.3,
with no libchat-core dependency (the embedded logos-delivery node comes from the
sibling libchat checkout's transport crate).

Submissions arrive on either of two write paths feeding the same verification +
storage pipeline:

- **HTTP POST** (`/v0/keypackage`, `/v0/account`) — synchronous and acknowledged;
- **logos-delivery subscription** — clients publish the same JSON bodies on the
  store's content topics and the server picks them up from the network (see
  [Delivery ingestion](#delivery-ingestion)).

The query API is HTTP only.

`device_id` is the hex-encoded 32-byte Ed25519 verifying key of a device.

It also runs a minimal **account service**: one signed blob per **`account_pub`**
mapping an Account to its set of device (LocalIdentity) public keys, so clients
can invite every LocalIdentity of an account. `account_pub` is the hex-encoded
32-byte Ed25519 AccountAddress verifying key. See
[Account device-list endpoints](#account-device-list-endpoints).

## Trust model

A bundle is an opaque **payload** plus its **signature**, published under a
**`device_id`** (the hex of the device's 32-byte Ed25519 verifying key).
The signed bytes and the wire bytes are identical, so a verifier checks the
signature over exactly what it received, no reconstruction.

The **server treats `payload` as a black box**: it never decodes it. It only
verifies that `signature` over the payload bytes is valid under `device_id`'s
key, then stores it. A valid signature is proof-of-possession — only the holder
of `device_id`'s key can publish under it — so an adversary can't publish under
a `device_id` it doesn't control, and junk is dropped before storage. The server
is not a trusted authority, so **consumers MUST also verify on retrieve**, and a
valid signature does not prove the device is authorized for any account (that
binding arrives with λLEZ in v0.3).

Consumers define the payload layout. Today it is:

```text
payload = timestamp_ms_le[8] || key_package[..]
```

Fixed-width field first with the variable `key_package` last makes it parse
exactly one way — no delimiter, even though `key_package` is arbitrary bytes.

## Building & running

```bash
cargo build --release
./target/release/chat-store   # binds 0.0.0.0:8080, db ./chat-store.db
```

| Flag | Default | Description |
|------|---------|-------------|
| `--bind <addr>` | `0.0.0.0:8080` | HTTP bind address |
| `--db <path>` | `chat-store.db` | SQLite database path |
| `--max-per-identity <n>` | `100` | Bundles retained per `device_id` |
| `--retention-days <n>` | `30` | Drop bundles older than this |
| `--prune-interval-secs <n>` | `3600` | How often the prune task runs |
| `--no-delivery` | off | Disable the logos-delivery subscriber (HTTP POST ingestion only) |
| `--preset <name>` | `logos.dev` | logos-delivery network preset the subscriber joins |
| `--p2p-port <port>` | `0` | TCP + discv5 UDP port for the embedded node (0 = OS-assigned) |

Logs via `RUST_LOG` (default `info`).

Building a runnable binary links the native `liblogosdelivery`; enter the
libchat dev shell (`nix develop` in the sibling checkout) or set
`LOGOS_DELIVERY_LIB_DIR` to the directory containing the library.

## Delivery ingestion

Unless `--no-delivery` is given, the server runs an embedded logos-delivery
node and subscribes to two content topics:

```text
/logos-chat/1/store-keypackage-v0/proto   keypackage submissions
/logos-chat/1/store-account-v0/proto      account device-list submissions
```

Each received message is the same JSON body as the corresponding POST endpoint
(below) and goes through identical signature verification and storage rules.
Publishing is fire-and-forget on the client side: rejected submissions are only
logged by the server, which the trust model can afford because consumers verify
every bundle on retrieval anyway. libchat's `DeliveryRegistry` publishes on
these topics when its publish mode is set to delivery.

## Docker

```bash
# Build the image
docker build -t chat-store .

# Run it, persisting the SQLite db on a named volume and exposing port 8080
docker run --rm -p 8080:8080 -v chat-store-data:/data chat-store
```

The image runs the binary with `--bind 0.0.0.0:8080 --db /data/chat-store.db`
by default; override the `CMD` to change flags, e.g.:

```bash
docker run --rm -p 9000:9000 -v chat-store-data:/data chat-store \
  --bind 0.0.0.0:9000 --db /data/registry.db --retention-days 14
```

## API

### `POST /v0/keypackage`

```json
{
  "device_id": "hex(32-byte ed25519 verifying key)",
  "payload":   "base64(opaque signed bytes)",
  "signature": "base64(64-byte ed25519 signature over payload)"
}
```

The server verifies `signature` over the (opaque) `payload` bytes under
`device_id`'s key before storing, keyed by `device_id`. It does not decode
`payload`. Returns `204` on success, `400` on malformed input or a signature
that fails to verify.

### `GET /v0/keypackage/{device_id}`

Returns the most recently submitted bundle for that `device_id`, or `404`:

```json
{
  "payload":   "base64(...)",
  "signature": "base64(64-byte ed25519 signature)"
}
```

Consumers verify `signature` over the `payload` bytes using the key recovered
from `device_id`, then read `key_package` out of the payload. A bundle that
fails verification must be treated as not found.

## Account device-list endpoints

The account service stores **exactly one blob per `account_pub`** mapping an
Account to its LocalIdentity device keys. Same trust model as keypackages: the
server verifies `signature` over `payload` under `account_pub`'s key
(proof-of-possession), and consumers MUST re-verify on retrieve. Clients encode
a lamport-timestamped list of device public keys in `payload`; the rest of the
payload stays opaque to the server.

> Anti-replay: the server reads the lamport from the (signature-verified)
> `payload` and replaces the stored bundle only when the incoming lamport is
> strictly higher, returning `409` otherwise. Because the lamport is covered by
> the account signature it cannot be forged, so a replayed older-but-still-valid
> bundle cannot downgrade the device list, nor refresh the retention clock.
> Consumers should still compare lamports themselves as defence in depth.

### `POST /v0/account`

Upsert the device-list bundle for an account; replaces any previous value.

```json
{
  "account_pub": "hex(32-byte ed25519 AccountAddress verifying key)",
  "payload":     "base64(opaque signed bytes: lamport-ts + device pubkeys)",
  "signature":   "base64(64-byte ed25519 signature over payload by the account key)"
}
```

Returns `204` on success, `400` on malformed input or a signature that fails to
verify, and `409` when the bundle's lamport is not newer than the stored one
(replay / stale publish).

### `GET /v0/account/{account_pub}`

Returns the stored bundle for that account, or `404`:

```json
{
  "payload":    "base64(...)",
  "signature":  "base64(64-byte ed25519 signature)",
  "updated_at": 1700000000000
}
```

`updated_at` is the server's last-upsert time in Unix ms. Consumers verify
`signature` over `payload` under `account_pub`'s key, then decode the device list.

## Storage & retention

Two SQLite tables: `keypackages` keyed by `device_id`, and `account_bundles`
(one row per `account_pub`). A background task runs every `--prune-interval-secs`,
dropping keypackage bundles older than `--retention-days` (keeping at most
`--max-per-identity` per `device_id`) and dropping account bundles not refreshed
within `--retention-days`. The schema is an internal detail and may change.

## Smoke test

The quickest end-to-end check is the bundled [`smoke_test`](examples/smoke_test.rs)
example. It generates throwaway Ed25519 keys, signs and publishes a keypackage and
an account bundle, fetches both back, and confirms the replay guard:

```bash
# Terminal 1 — start a server with a fresh db
cargo run -- --bind 127.0.0.1:8080 --db tmp/chat-store.db

# Terminal 2 — run the example against it (defaults to http://127.0.0.1:8080)
cargo run --example smoke_test
# or point it elsewhere:
cargo run --example smoke_test -- http://127.0.0.1:8080
```

Expected output:

```text
POST /v0/keypackage        -> 204 No Content (expect 204)
GET  /v0/keypackage/<id>   -> 200 OK (expect 200) {"payload":...,"signature":...}
POST /v0/account           -> 204 No Content (expect 204)
GET  /v0/account/<id>      -> 200 OK (expect 200) {"payload":...,"signature":...,"updated_at":...}
POST /v0/account (replay)  -> 409 Conflict (expect 409)
```

The delivery write path has its own smoke test,
[`delivery_smoke_test`](examples/delivery_smoke_test.rs): it starts a publisher
node, publishes a signed keypackage and account bundle on the store's content
topics, and polls the query API until both appear:

```bash
# Terminal 1 — start a server (delivery ingestion is on by default)
cargo run -- --bind 127.0.0.1:8080 --db tmp/chat-store.db

# Terminal 2 — publish over the network and poll the query API
cargo run --example delivery_smoke_test
```

You can also exercise it with the real `chat-cli` (which lives in the
[libchat](https://github.com/logos-messaging/libchat) repo) against a running
server:

```bash
# In this repo: start the server on a test port with a fresh db
cargo run -- --bind 127.0.0.1:18080 --db tmp/registry.db

# In a libchat checkout: register two identities (--smoketest exits after registering)
cargo build -p chat-cli
./target/debug/chat-cli --name alice --transport file --data tmp/alice \
  --registry-url http://127.0.0.1:18080 --smoketest    # exits 0 on success
./target/debug/chat-cli --name bob   --transport file --data tmp/bob \
  --registry-url http://127.0.0.1:18080 --smoketest

# Confirm both bundles landed
sqlite3 tmp/registry.db "SELECT substr(device_id,1,12), length(payload) FROM keypackages;"
```

A non-zero exit from `chat-cli` means the server rejected the submission — e.g.
the signature failed verification. `GET /v0/keypackage/{device_id}` returns `200`
for a registered device and `404` otherwise.

## Benchmark

The bundled [`benchmark`](examples/benchmark.rs) performs an end-to-end load
test without touching a deployed server. It starts its own `chat-store` binary
on a loopback-only random port with a uniquely named temporary SQLite database,
then deletes the database afterward. It has no remote URL option.

Each business-flow operation publishes and fetches a signature-verified
keypackage; publishes and fetches an account bundle; confirms that a repeated
lamport is rejected with `409`; then publishes, fetches, and verifies a newer
account version. Before the measured flow it also checks both unknown-resource
`404` paths and a malformed-request `400` path.

```bash
cargo build --release
cargo run --release --example benchmark -- --operations 1000 --concurrency 16
```

Useful options:

```text
--payload-bytes <n>  Opaque bytes appended to each benchmark payload (default: 512)
--server-bin <path>  Local binary to launch (default: target/release/chat-store)
--keep-db            Keep the temporary SQLite database for post-run inspection
```

Do not point benchmark traffic at the production deployment. To measure a
network deployment, provision a separate chat-store instance and database for
benchmarking, then use a load-test runner configured only for that isolated
environment.

## Lifecycle

Exists to unblock contact-by-id flows on testnet; removed once λLEZ-based
discovery lands in v0.3. The seam is the `RegistrationService` trait in libchat
(`core/conversations/src/service_traits.rs`) — swapping implementations does not
touch the chat protocol.
