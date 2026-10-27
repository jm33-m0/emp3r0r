# C2 protocol specification

This document is the normative wire specification; the C headers in
[`include/`](include/) are its machine-readable form. Anything not marked
_PROPOSED_ must be implemented byte-for-byte by an interoperating agent.
Changes to implemented behaviour must update this document, the headers and
the Go side in the same commit.

## C agent headers

Everything here is a transcription of a Go constant or struct:

| Header         | Go source                                                                  |
| -------------- | -------------------------------------------------------------------------- |
| `common.h`     | `core/internal/def/{config,def,msg_auth}.go`, §2/§4                        |
| `crypto.h`     | `core/lib/crypto/aes.go`, `core/internal/transport/keyexchange.go`         |
| `secureconn.h` | `core/internal/transport/crypto.go` (`SecureConn`)                         |
| `messages.h`   | `core/internal/def/{msg_auth,agent,token}.go`                              |
| `transport.h`  | `core/internal/def/config.go`, `core/internal/transport/c2channel_http.go` |

CBOR is provided by vendored [Intel tinycbor](https://github.com/intel/tinycbor)
(MIT, version 7.0) under `vendor/tinycbor/`; there is no hand-rolled codec.

When the Go side changes, this document and the headers change in the same
commit. All peers are built from the same batch, so there is no
back-compatibility shim.

## 1. Conventions

| Term            | Meaning                                                          |
| --------------- | ---------------------------------------------------------------- |
| **C2 / server** | The operator-side server (`core/internal/cc`). Trust root.       |
| **agent**       | The remote payload talking to the C2.                            |
| **channel**     | The outer transport wrapper (HTTP-poll, HTTP/2, QUIC, KCP, ...). |
| **stream**      | A bidirectional byte stream produced by a channel.               |
| **frame**       | One length-prefixed, encrypted unit inside a stream (see §4).    |
| **envelope**    | One CBOR message, carried inside exactly one frame.              |

Encoding rules:

- **CBOR** is [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html). Struct
  fields use **integer map keys** (`keyasint`), never text keys. Maps are
  definite-length; arrays are definite-length. A decoder MUST accept any valid
  ordering and both definite and indefinite lengths (the Go decoder does).
- **Integers are big-endian** wherever raw bytes carry them (§4, §5.1).
- **Base64** is URL-safe **with** padding: Go `base64.URLEncoding`
  (`A–Z a–z 0–9 - _`, `=` padding).
- **ECDSA** is P-256 (secp256r1). Signatures are **ASN.1 DER**-encoded
  `SEQUENCE { INTEGER r, INTEGER s }` over `SHA-256(message)`.
- **HMAC/KDF** is HKDF-SHA256.
- Strings are UTF-8.
- The word _must_ is normative.

---

## 2. Constants and key material

### 2.1 Per-build pre-shared key (PSK)

Both sides share a per-build PSK derived from the build-time `MagicString`:

```text
hexMD5      = lowercase hex string of MD5(MagicString)   # 32 ASCII chars
PSK         = ASCII bytes of hexMD5[0:32]                # exactly 32 bytes
```

Note this is the **hex text**, not the raw 16-byte digest. In Go:

```go
func GenAESKey(seed string) []byte {          // core/internal/def/util.go
    md5sum := fmt.Sprintf("%x", md5.Sum([]byte(seed)))
    return []byte(md5sum)[:32]
}
AESPassword = GenAESKey(MagicString)
```

The C2 patches `MagicString` (and optionally `QUICKey`) at build time with
`-ldflags -X`. An interoperating agent **must** be built with the same
`MagicString`.

### 2.2 Route names

Routing is carried in `MsgAuth.Capabilities` (§5), not in the URL path. The five
route names are configuration values with these defaults:

| Config field       | Default      | Purpose                              |
| ------------------ | ------------ | ------------------------------------ |
| `C2Routes.Checkin` | `c2-checkin` | identity enrollment + system report  |
| `C2Routes.Msg`     | `c2-msg`     | persistent message tunnel, PFS, jobs |
| `C2Routes.FTP`     | `c2-ftp`     | agent → operator file upload         |
| `C2Routes.WWW`     | `c2-www`     | operator/C2 → agent file download    |
| `C2Routes.Proxy`   | `c2-proxy`   | SOCKS5 relay                         |

An operator may randomize these. An agent reads them from its config. Route
matching on the server is trimmed + case-insensitive.

### 2.3 Message tags

`MsgTunData.Tag` carries a routing/type label. Defined values:

| Tag                            | Direction     | Meaning                                            |
| ------------------------------ | ------------- | -------------------------------------------------- |
| `checkin-ok`                   | C2 → agent    | check-in accepted (the ACK)                        |
| `handshake`                    | C2 → agent    | hello reply, carries server ephemeral public key   |
| `peer_list`                    | C2 → agent    | `MsgTunData.EnrichedPeerList` push                 |
| `agent_token`                  | C2 → agent    | CBOR `AgentToken` push (mesh router authorization) |
| `ftp_relay_data:<token>` etc.  | C2 ↔ operator | operator-tunnel relay frames (not agent wire)      |
| `proxy_relay_*`, `www_relay_*` | C2 ↔ operator | operator-tunnel relay frames (not agent wire)      |

Any other tag on the agent tunnel is interpreted as the agent's own tag and is
**not trusted** by the server.

### 2.4 Limits

| Limit                          | Value                                            | Where enforced               |
| ------------------------------ | ------------------------------------------------ | ---------------------------- |
| `MsgAuth` first frame          | ≤ 8192 bytes; must fit one frame                 | server dispatch              |
| Encrypted frame length         | 1 .. 10 MiB                                      | `SecureConn.Read`            |
| Random frame padding           | normal `Write` frames, if configured             | `SecureConn.Write`           |
| Replay window                  | ±60 s                                            | server                       |
| Initial handshake timeout      | 10 s (server closes pre-auth stream)             | server dispatch              |
| Message tunnel silence timeout | 10 min                                           | server `handleMessageTunnel` |
| HTTP-poll request body         | 50 MiB                                           | server                       |
| HTTP-poll unauth first body    | 10 s read deadline                               | server                       |
| HTTP-poll rate limit           | 10 rps/IP (burst 20), 100 rps global (burst 200) | server                       |

---

## 3. Transport layer

### 3.1 Abstract contract

A channel turns a URL (or peer) into a bidirectional byte stream. The protocol
layers above it see only `Read`/`Write`/`Close`. The **only** thing that selects
protocol behaviour is the CBOR `MsgAuth` envelope; no wrapper metadata is
trusted.

Two transport classes exist:

1. **Duplex** — one long-lived connection carries the stream. Examples:
   `h2conn` (HTTP/2), `quic`, `kcp`, `smb`. Every route works naturally.
2. **Virtual stream over request/response** — `http_poll` (default). A stream is
   simulated with an init POST, GET long-polls for reads, POSTs for writes, and
   a closing POST. Covered in §3.2.

The agent's `C2ChannelMode` selects the wrapper. A Go agent ships all wrappers;
a minimal C agent only needs `http_poll` (§3.2) and/or one duplex wrapper.

### 3.2 `http_poll` (default channel)

Configuration (malleable profile):

| Field                            | Meaning                                                                                         |
| -------------------------------- | ----------------------------------------------------------------------------------------------- |
| `C2Path`                         | path appended to the C2 base URL, e.g. `/api/v1/telemetry`                                      |
| `SessionHeader` / `SessionValue` | header or cookie carrying the session id. `%s` in `SessionValue` is replaced by the session id. |
| `InitHeader` / `InitValue`       | marks the init request                                                                          |
| `CloseHeader` / `CloseValue`     | marks the close request                                                                         |
| `CustomHeaders`                  | static headers (e.g. `User-Agent`)                                                              |

Session id: the client generates a fresh random UUID string per stream.

All requests carry `SessionHeader` first (the server identifies the stream by
it); `Cookie` values are merged with `; `.

| Step      | Request                                                                          | Server response                                                                                                                              |
| --------- | -------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| **Init**  | `POST <base><C2Path>` with `InitHeader` set and `SessionHeader` set. Empty body. | `200` on success; `429` on rate limit; `404` for unknown paths.                                                                              |
| **Read**  | `GET <base><C2Path>` with `SessionHeader`.                                       | Long-poll (35–70 s random). On data: `200` + body = raw bytes to feed the read side. On timeout: `200` empty. `404` = session gone.          |
| **Write** | `POST <base><C2Path>` with `SessionHeader`, body = raw bytes.                    | `200` on accept; body, if non-empty, is additional read-side data. `404` = session gone; `413` body too large; `503` server read queue full. |
| **Close** | `POST <base><C2Path>` with `CloseHeader` set.                                    | `200`. Fire-and-forget.                                                                                                                      |

The body of a request/response is an opaque **byte stream**: it is exactly the
concatenation of frames described in §4. The transport does not frame; the
`SecureConn` layer does. A single HTTP response may contain many frames, or a
partial frame; a single frame may span responses. The read side must treat the
body bytes as a continuous stream (the Go client buffers them).

Notes:

- Server sessions idle out after **10 minutes**; GET then returns `404`.
- The POST body limit is **50 MiB**; the server may coalesce multiple buffered
  write-frames into one GET response (capped at 50 MiB).
- An unauthenticated session must deliver its request body within 10 s.
- Read cadence includes a randomized sleep interval and jitter (config
  `PollInterval` seconds, `Jitter` percent) after an empty poll; after data is
  received it performs a short randomized "blink" and polls again immediately.

### 3.3 Other channels

`h2conn` uses an HTTP/2 duplex POST stream. `quic` is stock QUIC/HTTP-3 (ALPN
`h3`) optionally with a keyed datagram obfuscation seeded from `QUICKey`/PSK.
`kcp` is a KCP-over-UDP wrapper. `smb` is a named-pipe transport. All of them
expose a byte stream identical to §3.1, so §4–§10 apply unchanged.

A new C agent SHOULD implement `http_poll` first (works through CDNs/proxies),
then a duplex channel.

---

## 4. SecureConn — framing and encryption

Every byte stream is wrapped in `SecureConn` before any CBOR is written.

### 4.1 Frame layout

```text
frame  := uint32_be(enc_len) || enc_blob
enc_blob := AES-256-GCM(key, nonce, plaintext)
plaintext := uint32_be(payload_len) || payload || padding
nonce  := 12 random bytes, prepended to the GCM output (inside enc_blob)
tag    := 16-byte GCM tag (appended, standard AEAD)
```

So `enc_len = 12 + len(plaintext) + 16`. There is **no AAD**.

`payload_len` is the number of meaningful payload bytes; `padding` is 0 or more
random bytes that the receiver must strip. Because `payload_len` is inside the
authenticated plaintext, a tampered length fails the GCM tag.

Receiver rules (MUST):

- Read the 4-byte big-endian length, then exactly that many encrypted bytes.
- Reject `enc_len <= 0` or `enc_len > 10 MiB`.
- Decrypt, reject if `len(plaintext) < 4`.
- `payload_len` must satisfy `0 <= payload_len <= len(plaintext) - 4`; else fail.
- If `payload_len == 0`, skip the frame (do not surface it as EOF).
- Strip padding, return only `payload`.

Sender rules (MUST):

- One CBOR message per frame: encode the whole CBOR item, then `Write` it once.
- Normal writes may be padded with random bytes up to a configured range,
  regardless of payload size. Explicit bulk relays use a separate writer that
  opts out of padding.
- The 4-byte encrypted-length prefix is not encrypted but is not trusted either:
  the length it protects is authenticated. A hostile peer can only cause an
  early error, never a misparse.

### 4.2 Key lifecycle

1. A stream starts on the **PSK** (§2.1).
2. The `checkin` and `msg` bootstrap routes stay on the PSK until the `msg`
   ECDH handshake completes.
3. After ECDH, the `msg` stream switches to the **session key** (§7.2).
4. Auxiliary routes (`ftp`, `www`, `proxy`) opened _after_ that handshake send
   their `MsgAuth` under the PSK (the server must route/authenticate it) and then
   immediately switch to the session key. In practice the agent re-keys the
   `SecureConn` right after writing the `MsgAuth` frame, before any payload.
5. A new `msg` tunnel discards any stale session key and starts again on the
   PSK.

The key is a plain 32-byte AES-256 key in both directions (no separate
direction keys, no per-frame counter). GCM nonces are random 12 bytes per frame.

---

## 5. MsgAuth — the first envelope

The **first** CBOR message on every new stream MUST be a `MsgAuth`. The server
reads it as a single frame (≤ 8192 bytes), then routes.

### 5.1 Schema

| Key | Name              | CBOR type     | Notes                                                          |
| --- | ----------------- | ------------- | -------------------------------------------------------------- |
| 11  | `Type`            | text          | must equal `auth_v1`                                           |
| 12  | `AgentUUID`       | text          | agent UUID                                                     |
| 13  | `IdentityToken`   | text          | base64url(CA signature over `AgentUUID`)                       |
| 14  | `Timestamp`       | int           | Unix seconds                                                   |
| 15  | `Nonce`           | text          | fresh random, anti-replay                                      |
| 16  | `Capabilities`    | array of text | must contain exactly one route name                            |
| 17  | `AgentProof`      | text          | base64url(ECDSA agent-key signature over the canonical string) |
| 18  | `EphemPublicKey`  | bytes         | optional; unused by current flows                              |
| 19  | `StreamID`        | text          | optional; FTP token / WWW filename / proxy token               |
| 20  | `ProtocolVersion` | int           | must equal `1` (current version)                               |

### 5.2 Canonical auth string

```text
caps      = copy of Capabilities, sorted lexicographically (duplicates kept)
canonical = AgentUUID || "\n" || decimal(Timestamp) || "\n" || Nonce || "\n" || join(caps, ",")
```

Exact Go definition (`core/internal/transport/auth.go`):

```go
caps := append([]string(nil), capabilities...)
sort.Strings(caps)
strings.Join([]string{
    agentUUID,
    strconv.FormatInt(timestamp, 10),
    nonce,
    strings.Join(caps, ","),
}, "\n")
```

The agent signs `SHA-256(canonical)` with its P-256 key; the result is DER and
base64url-encoded into `AgentProof`.

### 5.3 IdentityToken

`IdentityToken` is `base64url(CA_signature)` where `CA_signature` is the CA's
P-256 ECDSA/DER signature over the raw `AgentUUID` bytes (not the canonical
string). It is issued at provision time (operator `sign_agent`, or embedded in
the agent build). The agent presents the same token on every `MsgAuth`.

### 5.4 Server verification order

1. Structural checks: type, `ProtocolVersion == 1`, non-empty
   UUID/token/nonce, `Timestamp > 0`.
2. Replay window: `|now - Timestamp| <= 60`.
3. `IdentityToken` verifies against the CA public key over `AgentUUID`.
4. Routing: exactly one recognized route capability. Missing or multiple known
   routes are rejected.
5. TOFU lookup by `AgentUUID`:
   - **known**: `AgentProof` must verify against the pinned agent public key.
   - **unknown**: only the `checkin` route is allowed, and `AgentProof` must
     verify against the `PublicKey` in the check-in body.
6. Replay cache: reject a repeated `AgentUUID:Nonce` within the window.
7. Operator presence/idle gate (server-wide).

Trust is DB-authoritative; the server pins the agent's public key on first
check-in and **rejects key rotation** (an operator must `forget_agent` to reset).

---

## 6. Routes

The single recognized route capability selects the handler:

| Route     | Handler         | Direction / lifetime                                                   |
| --------- | --------------- | ---------------------------------------------------------------------- |
| `checkin` | one-shot        | agent sends `Emp3r0rAgent`, server replies `checkin-ok`, stream closes |
| `msg`     | persistent      | bidirectional CBOR `MsgTunData`, PFS handshake, job dispatch           |
| `ftp`     | one-shot stream | agent → operator; `StreamID` = FTP token. Body is **gzip**-compressed. |
| `www`     | one-shot stream | operator/C2 → agent; `StreamID` = file name. Body is raw bytes.        |
| `proxy`   | one-shot stream | bidirectional SOCKS5 relay; `StreamID` = proxy token                   |

Rules:

- Auxiliary routes (`ftp`, `www`, `proxy`) require the agent to already be
  enrolled and to have a live session; they are sub-operations of the `msg`
  session. They are re-keyed to the current PFS session key (§4.2).
- `StreamID` is route-specific and must be non-empty for `ftp`/`www`/`proxy`.
- One agent UUID may have exactly one live session at a time; a duplicate live
  session is refused.
- **FTP uploads are gzip streams.** The agent writes `gzip(file bytes)` onto the
  SecureConn; the C2 relays the stream verbatim and the operator decompresses it
  (`core/internal/cc/base/ftp/handler_ftp.go`). Compression is a wire requirement,
  not a convention: an uncompressed FTP stream is rejected by the operator.
- **WWW downloads are raw bytes.** The agent reads the SecureConn until EOF. The
  operator may serve a file that is itself a `.gz` payload (that is how
  `!custom_module` hosts a module), but the route applies no transformation.

---

## 7. Message schemas

All messages below are CBOR map items with integer keys, carried one-per-frame.

### 7.1 `MsgTunData`

The universal agent↔C2 message.

| Key | Name               | Type          | Notes                                                                |
| --- | ------------------ | ------------- | -------------------------------------------------------------------- |
| 1   | `JobID`            | text          | job correlation                                                      |
| 2   | `CmdSlice`         | array of text | command argv; empty for non-commands                                 |
| 3   | `Response`         | bytes         | command output / payload                                             |
| 4   | `Tag`              | text          | see §2.3                                                             |
| 5   | `Time`             | int (Unix ms) | agent clock, used for RTT                                            |
| 8   | `EphemPublicKey`   | bytes         | agent ephemeral P-256 pubkey on the first hello                      |
| 10  | `EnrichedPeerList` | map           | C2 push: peers (see §7.4; keys 6, 7, 9 retired)                      |

Field 10 is delivered inside a `peer_list` tagged message and is the
`EnrichedPeerList` structure in §7.4. It is authenticated by the PFS tunnel and
carries no separate signature.

### 7.2 `Emp3r0rAgent` (check-in body)

Sent as the single payload after the `checkin` `MsgAuth`. The server treats
every field as hostile, sanitizes strings, derives `Tag` from the verified UUID,
and ignores/overwrites fields it computes itself. Minimum required by the server:
`UUID` (27), `PublicKey` (29), `UUIDSig` (28), and enough to display. `PublicKey`
is a PEM-encoded PKIX P-256 public key; `UUIDSig` is the base64url CA
`IdentityToken`.

| Key | Name                       | Key | Name                                    |
| --- | -------------------------- | --- | --------------------------------------- |
| 1   | `Tag`                      | 23  | `Process` (`AgentProcess`)              |
| 2   | `Name`                     | 24  | `Exes` (array)                          |
| 3   | `Version`                  | 25  | `CWD`                                   |
| 4   | `Transport`                | 26  | `Product` (any)                         |
| 5   | `Hostname`                 | 27  | `UUID`                                  |
| 6   | `Hardware`                 | 28  | `UUIDSig`                               |
| 7   | `Container`                | 29  | `PublicKey` (PEM)                       |
| 8   | `CPU`                      | 30  | `C2Host`                                |
| 9   | `GPU`                      | 31  | `LastSeen` (time; server overwrites)    |
| 10  | `Mem`                      | 32  | `LastSeenRTT` (duration; omit)          |
| 11  | `OS`                       | 33  | `Uptime`                                |
| 12  | `GOOS`                     | 34  | `Groups`                                |
| 13  | `Kernel`                   | 36  | `AgentToken`                            |
| 14  | `Arch`                     | 37  | `MeshRoute`                             |
| 15  | `From` (server overwrites) | 38  | `P2PRelayPort`                          |
| 16  | `IPs` (array)              | 39  | `MeshGossipPort`                        |
| 17  | `ARP` (array)              | 40  | `Files` (array)                         |
| 18  | `User`                     | 41  | `GOArch`                                |
| 19  | `HasRoot`                  | 42  | `P2PTransport`                          |
| 20  | `HasTor`                   | 43  | `Owner`                                 |
| 21  | `HasInternet`              | 44  | `OfflineGrace` (seconds; 0 = immediate) |
| 22  | `NCSIEnabled`              |     |                                         |

`AgentProcess`:

| Key | Name      |
| --- | --------- |
| 1   | `PID`     |
| 2   | `PPID`    |
| 3   | `Cmdline` |
| 4   | `Parent`  |

Omit `LastSeen` (31) and `LastSeenRTT` (32) to avoid Go `time.Time`/`Duration`
CBOR tag subtleties; the server sets `LastSeen` from the connection anyway.
`OfflineGrace` (44) is the agent-chosen removal deadline in seconds; zero means
remove on disconnect. The Go C2 also has a C2-derived `Sleeping` snapshot flag
(key 45), but that is not part of the check-in body.

### 7.3 `AgentToken`

Pushed as `agent_token` after PFS is established.

| Key | Name         | Type            |
| --- | ------------ | --------------- |
| 1   | `AgentID`    | text            |
| 2   | `IP`         | text            |
| 3   | `Capability` | text (`router`) |
| 4   | `ExpiresAt`  | int (Unix)      |
| 5   | `Signature`  | bytes           |

### 7.4 `EnrichedPeerList`

Pushed as `peer_list` after PFS is established.

| Key | Name        | Type                          |
| --- | ----------- | ----------------------------- |
| 1   | `Peers`     | array of `EnrichedPeer`       |

`EnrichedPeer`:

| Key | Name             | Type          |
| --- | ---------------- | ------------- |
| 1   | `UUID`           | text          |
| 2   | `IPs`            | array of text |
| 3   | `From`           | text          |
| 4   | `P2PRelayPort`   | text          |
| 5   | `MeshGossipPort` | text          |
| 6   | `Files`          | array of text |
| 7   | `LastSeen`       | int (Unix)    |
| 8   | `P2PTransport`   | text          |

---

## 8. Check-in flow

```text
agent                                              C2
  |-- channel connect (init/poll or duplex) -------->|
  |-- frame: MsgAuth(caps=[c2-checkin]) ------------>|  PSK-encrypted
  |                                                  |  verify CA + TOFU + replay
  |                                                  |  rate-limit per UUID
  |-- frame: CBOR Emp3r0rAgent --------------------->|  sanitize, pin key, persist
  |                                                  |  session admission
  |<-- frame: CBOR MsgTunData{Tag:"checkin-ok"} -----|
  |-- close ---------------------------------------->|
```

Notes:

- The `MsgAuth` frame and the `Emp3r0rAgent` frame are distinct frames.
- On first enrollment, `AgentProof` is verified against `Emp3r0rAgent.PublicKey`;
  the server then persists the pinned identity.
- The agent should not consider itself checked in until it decodes the
  `checkin-ok` ACK (important for polling transports).
- A `403` on the channel means the server rejected the stream (e.g. no operator,
  duplicate session); an agent may treat a specific 403 as self-destruct.
- Check-ins are rate-limited to 10/minute per UUID; excess attempts are silently
  dropped.

---

## 9. Message tunnel and PFS

```text
agent                                              C2
  |-- frame: MsgAuth(caps=[c2-msg]) --------------->|  PSK-encrypted, routed
  |-- frame: MsgTunData hello --------------------->|  Tag=agent tag, CmdSlice=[random],
  |     JobID=uuid, EphemPublicKey=agent_pub, Time   |  Response=nil,
  |                                                  |  EphemPublicKey present
  |                                                  |  ECDH(P-256), derive session key
  |                                                  |  reply, then switch SecureConn key
  |<-- frame: MsgTunData{Tag:"handshake", -----------|  Response = server_pub (64 bytes)
  |           JobID=<hello JobID>, Response=pub}     |
  |                                                  |  (both sides now on session key)
  |<-- frame: MsgTunData{Tag:"peer_list", ...} ------|
  |<-- frame: MsgTunData{Tag:"agent_token", ...} ----|
  |-- frame: MsgTunData (keepalive hello / commands)->|
  |<-- frame: MsgTunData (jobs / handshake keepalive)-|
```

### 9.1 Hello detection

The server treats a `MsgTunData` as a **hello** iff
`Response == nil && len(CmdSlice) > 0`. The first hello of a session MUST carry
`EphemPublicKey` (64 bytes: `X || Y`, each 32-byte big-endian, **not** SEC1
compressed). Later hellos MUST omit it; a mid-session re-key offer is rejected.

### 9.2 Public key serialization

```text
pub := X[32] || Y[32]     # each coordinate left-padded to 32 bytes
```

### 9.3 Session key derivation

```text
shared = X coordinate of (peer_pub * own_priv), left-padded to 32 bytes
salt   = "session-key-salt-v1"
info   = "client-session:" + AgentUUID          # note: client-side info string
key    = HKDF-SHA256(ikm=shared, salt, info, L=32)
```

Both sides use the **same** `info` (`client-session:<uuid>`); the server does not
flip the label for its own role.

### 9.4 Key switch ordering

The server writes the `handshake` reply **still under the PSK**, then switches
its `SecureConn` to the session key. The agent must therefore read the
`handshake` reply under the PSK, then switch to the session key before reading
the subsequent `peer_list` / `agent_token` frames. Any frame after `handshake`
is session-key encrypted.

### 9.5 Keepalive

An interoperating agent may re-send a hello periodically and wait for a
`handshake`-tagged reply under `CCTimeout`. The reply carries random bytes
rather than a public key once PFS is established. A hello whose
`EphemPublicKey` is omitted once PFS is active is a pure keepalive; the server
answers it with a random-bytes `handshake` reply. The server additionally
accepts a fresh `MsgAuth` frame on the tunnel as a keepalive (it updates
presence but sends no reply). Any authenticated frame resets the 10-minute
silence timer.

The reference C agent does not keep a tunnel alive across sleep: it reads for
the configured poll window, closes the tunnel, masks itself for the beacon
interval, then opens a fresh tunnel and sends a hello. Commands queued during
sleep are delivered after that hello.

### 9.6 Jobs

Commands are `MsgTunData` with a non-empty `CmdSlice`. The server assigns a
`JobID`; the agent replies with the same `JobID`, `CmdSlice=[commandName, ...]`,
and `Response` = output bytes. Job ownership is immutable on the server.

---

## 10. Command and module semantics

The CBOR wire protocol is generic. Command names and payload delivery follow
[`core/modules/module_development_guide.md`](../modules/module_development_guide.md).
Summary of what a minimal agent must support:

- **Built-in commands** referenced by name, e.g. `!ls_dir`, `!stat`. A C agent
  implements file management directly.
- **`!custom_module`** delivers an in-memory payload. The server hosts a gzipped
  file (with SHA-256) and sends the agent:

  ```text
  !custom_module --mod_name <name> --type <coff|dll|so|starlark> \
    --file_to_download <hosted.gz> --checksum <sha256> \
    --invocation <base64 CBOR ResolvedInvocation> [--peer <ip>]
  ```

  The agent downloads the payload over the `www` route (§6; the file name is the
  `StreamID`), verifies SHA-256, gunzips, and dispatches by type. DLL/SO
  dependencies are mapped on use and unmapped on return (see the guide §8).

A minimal first-generation C agent can implement: `checkin`, `msg`, `www`
download, `ftp` upload, `!ls_dir`/`!stat`, and `coff` execution. SOCKS5
(`proxy`) and mesh gossip can follow.

---

## 11. Versioning and capabilities

`MsgAuth.ProtocolVersion` (key 20) carries the wire-format version. The server
rejects any value other than `1` (`def.ProtocolVersion`), so a protocol bump is
an all-peers rebuild. This is the handle for future incompatible changes.

`Capabilities` doubles as the route selector and the feature advertisement.
Exactly one configured **route** token selects the handler; any number of
**feature** tokens (`file-mgmt`, `bof`, `memmod`, `socks5`, `mesh`, ...) may
follow. Unknown tokens are ignored by the server but are part of the signed
canonical string, so they must be sent exactly as advertised. An interoperating
agent MUST send exactly one route token.

Still _PROPOSED_, not implemented: the operator UI does not yet consume the
advertised feature tokens, so it may still offer a Go-only builtin to a minimal
C agent. That is a server/operator change, not a wire change.

---

## 12. Conformance vectors

Interoperability is only as good as the tests. Before a second implementation is
trusted, generate and check in golden vectors (a Go generator should emit them;
the C side consumes them):

1. **PSK** — `GenAESKey("...")` for fixed `MagicString` values.
2. **SecureConn** — fixed key + plaintext + nonce ⇒ exact frame bytes; decrypt
   round-trip; reject zero/oversize length and truncated payload.
3. **ECDH/HKDF** — fixed private keys ⇒ shared secret and 32-byte session key.
4. **Public key serialization** — `X||Y` round-trip and point-on-curve rejection.
5. **Canonical auth string** — fixed inputs, including capability sorting.
6. **ECDSA** — fixed key + message ⇒ verify DER signature; reject a mutated
   canonical string.
7. **CBOR** — exact bytes for `MsgAuth`, `MsgTunData`, and `Emp3r0rAgent` minimal
   bodies, and decode round-trips in both directions.
8. **End-to-end** — a recorded check-in transcript and a hello/handshake
   transcript, byte-for-byte.

The framing and KDF vectors are the highest priority: a wrong `md5hex` slice or a
missing `client-session:` prefix fails silently and is painful to debug.

---

## 13. Security considerations

- **Bootstrap secrecy is weak by design.** The PSK is a build-time constant;
  everything before PFS is only as secret as `MagicString`. Do not send sensitive
  data before the session key is established.
- **PFS is negotiated once per tunnel.** A mid-session `EphemPublicKey` is
  rejected. A new tunnel starts a fresh ECDH.
- **Replay** is bounded by a ±60 s window and a per-UUID nonce cache; an agent
  clock must be roughly correct.
- **TOFU** pins the agent's P-256 key on first check-in; rotation is refused.
- **Framing** authenticates the payload length; the outer encrypted-length
  prefix is untrusted and only bounds reads.
- **Padding** obscures normal frame lengths; explicit bulk relays opt out.
- **Identity derivation** — the server derives the operator-facing tag from the
  verified UUID and overwrites any agent-supplied tag. A C agent should still
  send its tag for compatibility but must not depend on it.
- **Input is hostile** — a C agent must validate every length and index from the
  stream and must not panic on malformed CBOR or frames.

---

## Appendix A — Reference constants (Go source)

| Item                       | Location                                                                                 |
| -------------------------- | ---------------------------------------------------------------------------------------- |
| PSK derivation             | `core/internal/def/util.go` (`GenAESKey`), `core/internal/def/config.go`                 |
| Framing/encryption         | `core/internal/transport/crypto.go` (`SecureConn`)                                       |
| MsgAuth + canonical string | `core/internal/def/msg_auth.go`, `core/internal/transport/auth.go`                       |
| Routes                     | `core/internal/def/config.go` (`C2Routing`, defaults)                                    |
| Dispatch                   | `core/internal/cc/server/dispatcher.go`                                                  |
| Check-in                   | `core/internal/cc/server/handler_checkin.go`                                             |
| Msg tunnel + PFS           | `core/internal/cc/server/handler_messagetun.go`, `handler_messagetun_helper.go`          |
| ECDH/HKDF/serialization    | `core/internal/transport/keyexchange.go`                                                 |
| ECDSA/DER/base64           | `core/internal/transport/certs.go`                                                       |
| `http_poll`                | `core/internal/transport/c2channel_http.go`, `core/internal/cc/server/c2_http_server.go` |
| Agent client               | `core/internal/agent/base/c2transport/`                                                  |
| C protocol headers         | `core/c_agent/include/` (this document as C declarations)                                |

## Appendix B — Minimal C agent checklist

- [ ] `md5hex` + first 32 ASCII chars ⇒ PSK
- [ ] AES-256-GCM with 12-byte random nonce, 16-byte tag
- [ ] SecureConn frame codec (both directions, padding strip, 10 MiB cap)
- [ ] CBOR encoder/decoder with integer keys
- [ ] P-256 keygen, ECDH, raw `X||Y` serialization
- [ ] HKDF-SHA256 (`session-key-salt-v1`, `client-session:<uuid>`)
- [ ] ECDSA/DER sign + verify over SHA-256
- [ ] base64url (padded)
- [ ] One channel: `http_poll` and/or a duplex wrapper (TLS)
- [ ] `MsgAuth` (with `ProtocolVersion = 1`) + canonical string
- [ ] check-in, hello handshake, keepalive, job loop
- [ ] `www` download, `ftp` upload (gzip stream), `!ls_dir`/`!stat`
- [ ] optional: `coff` loader, `proxy` relay

The C declarations for every item above are in `core/c_agent/include/`; this
document is the specification they implement.
