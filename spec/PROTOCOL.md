# POOL Protocol Specification v1.0
## Protected Orchestrated Overlay Link

### 1. Overview

POOL is a secure, self-healing transport protocol designed to eliminate the systemic
failures of TCP/IP networking. It operates as IP Protocol Number 253 (experimental)
and provides:

- **Mandatory mutual authentication** on every connection (no trust-by-default)
- **Always-on encryption** with no plaintext mode
- **Stateless handshake** immune to SYN flood / resource exhaustion attacks
- **Cryptographic sequence numbers** preventing hijacking, prediction, and RST injection
- **Self-describing 256-bit addresses** with embedded node identity (no address exhaustion)
- **Automatic MTU discovery** with no silent drops
- **Built-in telemetry** (latency, loss, jitter per-flow)
- **Atomic configuration with automatic rollback** at the protocol level
- **Change journaling** for every state transition
- **Vendor-neutral canonical behavior** — single specification, no vendor-specific defaults

### 2. Packet Format

All POOL packets share a common header. Multi-byte fields are big-endian (network order).

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Version (4)  |  Type (4)     |          Flags (16)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Sequence Number (64)                     |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Acknowledgment (64)                      |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Session ID (128)                         |
|                                                               |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Timestamp (64)                           |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Payload Length (16)    |    Channel (8)  | Reserved (8)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      HMAC (256)                               |
|                         ...                                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Payload (variable)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Total header size: 80 bytes** (without payload)

#### Field Descriptions:

| Field | Bits | Description |
|-------|------|-------------|
| Version | 4 | Protocol version (currently 1) |
| Type | 4 | Packet type (see §2.1) |
| Flags | 16 | Bitfield flags (see §2.2) |
| Sequence | 64 | Cryptographic sequence number (CSPRNG-derived) |
| Ack | 64 | Acknowledges peer's last received sequence |
| Session ID | 128 | Unique session identifier (generated during INIT) |
| Timestamp | 64 | Nanosecond-precision monotonic clock for RTT/jitter |
| Payload Len | 16 | Length of encrypted payload in bytes |
| Channel | 8 | Multiplexed channel within session (0-255) |
| Reserved | 8 | Must be zero, for future use |
| HMAC | 256 | HMAC-SHA256 over entire header + payload (pre-encryption) |

### 2.1 Packet Types

| Value | Name | Description |
|-------|------|-------------|
| 0x0 | INIT | Connection initiation (contains ephemeral public key) |
| 0x1 | CHALLENGE | Server challenge (contains puzzle + server ephemeral key) |
| 0x2 | RESPONSE | Client puzzle solution + key agreement completion |
| 0x3 | DATA | Encrypted application data |
| 0x4 | ACK | Pure acknowledgment |
| 0x5 | HEARTBEAT | Keepalive with embedded telemetry |
| 0x6 | REKEY | Session key rotation |
| 0x7 | CLOSE | Graceful authenticated close |
| 0x8 | CONFIG | Configuration change announcement |
| 0x9 | ROLLBACK | Atomic rollback to previous configuration |
| 0xA | DISCOVER | Network/MTU/peer discovery |
| 0xB | JOURNAL | Change journal synchronization |
| 0xF | RESERVED | Reserved for future use |

### 2.2 Flags

| Bit | Name | Description |
|-----|------|-------------|
| 0 | ENCRYPTED | Payload is encrypted (always set after handshake) |
| 1 | COMPRESSED | Payload is compressed before encryption |
| 2 | PRIORITY | High-priority packet (QoS) |
| 3 | FRAGMENT | This is a fragment of a larger message |
| 4 | LAST_FRAG | This is the last fragment |
| 5 | REQUIRE_ACK | Sender requires explicit acknowledgment |
| 6 | TELEMETRY | Heartbeat contains telemetry data |
| 7 | ROLLBACK_READY | Node supports atomic rollback |
| 8 | CONFIG_LOCKED | Configuration changes are frozen |
| 9 | JOURNAL_SYNC | Journal synchronization in progress |
| 10-15 | RESERVED | Must be zero |

### 3. Connection Establishment (Stateless Handshake)

Unlike TCP's 3-way handshake which allocates server resources on SYN receipt,
POOL uses a **stateless challenge-response** that allocates ZERO server resources
until the client proves it can receive replies and solve a computational puzzle.

```
Client                                Server
  |                                     |
  |--- INIT (client ephemeral pubkey) ->|  Server allocates NOTHING
  |                                     |  Server generates challenge from
  |                                     |  hash(client_ip, timestamp, secret)
  |<-- CHALLENGE (puzzle, server key) --|  Still ZERO state on server
  |                                     |
  |  Client solves puzzle               |
  |  Client derives shared secret       |
  |                                     |
  |--- RESPONSE (solution, proof) ----->|  Server verifies puzzle solution
  |                                     |  Server derives shared secret
  |                                     |  NOW server allocates session state
  |<-- DATA (first payload) ------------|
  |                                     |
```

**Why this prevents SYN floods:** The server never stores state for unanswered
connections. The challenge is derived from a keyed hash of the client address and
a rotating server secret — the server can regenerate it statelessly. The client
must solve a hash-based puzzle (difficulty adjustable under load) to prove it is
willing to spend CPU, deterring volumetric attacks.

**Why this prevents IP spoofing:** The client must receive the CHALLENGE packet
to proceed. A spoofed source IP means the challenge goes to the wrong host.

### 4. Cryptography

#### 4.1 Key Exchange
- X25519 (Curve25519 Diffie-Hellman) for ephemeral key agreement
- Both sides generate ephemeral keypairs per session
- Shared secret derived via ECDH, then HKDF-SHA256 for key derivation

#### 4.2 Symmetric Encryption
- ChaCha20-Poly1305 AEAD for all payload encryption
- 256-bit session key, 96-bit nonce derived from sequence number
- Nonce = HKDF(session_key, sequence_number) — never reused

#### 4.3 Packet Authentication
- HMAC-SHA256 over (header + plaintext_payload) using session HMAC key
- HMAC key derived separately from session key via HKDF
- Prevents header manipulation, RST injection, and sequence corruption

#### 4.4 Key Rotation
- Automatic REKEY every 2^32 packets or 1 hour (whichever first)
- New ephemeral ECDH exchange within encrypted session
- Old keys zeroed from memory immediately after rotation

#### 4.5 Sequence Numbers
- Initial sequence number: output of CSPRNG (cryptographically secure)
- Subsequent: encrypted counter mode — seq = AES-CTR(counter, seq_key)
- Unpredictable to external observers, prevents prediction attacks
- 64-bit space: no wraparound concern in practice

### 5. Addressing

POOL uses 256-bit self-describing addresses:

```
[32-bit: address type + version]
[64-bit: organization/network ID]
[64-bit: subnet/segment ID]
[64-bit: node ID (derived from node's public key hash)]
[32-bit: checksum]
```

**Properties:**
- **No exhaustion**: 2^256 address space
- **No conflicts**: Node ID derived from cryptographic key = globally unique
- **Self-authenticating**: Address is bound to the node's identity key
- **No NAT needed**: Addresses are globally unique, end-to-end reachable
- **Built-in subnetting**: Organization and segment fields provide hierarchical structure
- **Checksum**: CRC32 catches typos and misconfiguration in manual entry

### 6. MTU Discovery & Fragmentation

- DISCOVER packets probe the path MTU using binary search
- No "silent drops" — every fragment requires HMAC verification
- Fragment reassembly with cryptographic ordering (no misordering attacks)
- Minimum MTU: 512 bytes (header + minimum payload)
- MTU re-probed every 60 seconds and on any packet loss detection
- PMTU cached per-session with graceful degradation

### 7. Built-in Telemetry (Self-Monitoring)

Every HEARTBEAT packet (sent every 5 seconds by default) contains:

```
struct pool_telemetry {
    uint64_t rtt_ns;           // Round-trip time in nanoseconds
    uint64_t jitter_ns;        // Jitter (RTT variance)
    uint32_t loss_rate_ppm;    // Packet loss in parts-per-million
    uint32_t throughput_bps;   // Current throughput estimate
    uint16_t mtu_current;      // Current path MTU
    uint16_t queue_depth;      // Local send queue depth
    uint64_t uptime_ns;        // Session uptime
    uint32_t rekey_count;      // Number of key rotations completed
    uint32_t config_version;   // Current configuration version
};
```

**This eliminates:**
- Need for external monitoring tools to detect degradation
- Blind spots during network changes
- Inability to baseline before/after changes

### 8. Atomic Configuration & Rollback

POOL nodes maintain a versioned configuration state:

```
struct pool_config {
    uint32_t version;          // Monotonically increasing version
    uint32_t prev_version;     // Previous version for rollback
    uint8_t  config_hash[32];  // SHA-256 of serialized config
    uint8_t  prev_hash[32];    // Hash of previous config
    uint64_t timestamp;        // When this config was applied
    uint64_t rollback_deadline; // Auto-rollback if not confirmed by this time
    // ... config fields ...
};
```

**Mechanism:**
1. CONFIG packet proposes new configuration with `rollback_deadline`
2. Peer applies new config **tentatively**
3. If confirmation not received before deadline → automatic ROLLBACK
4. Rollback restores exact previous state (config + prev_hash verified)
5. All config changes are recorded in the change journal

**This eliminates:** Unsaved configs, untested rollbacks, configuration drift,
and the "change window ran out" problem.

### 9. Change Journal

Every POOL node maintains an append-only journal of state changes:

```
struct pool_journal_entry {
    uint64_t timestamp;
    uint32_t config_version_before;
    uint32_t config_version_after;
    uint8_t  change_hash[32];
    uint16_t change_type;      // CONNECT, DISCONNECT, CONFIG, REKEY, ERROR, etc.
    uint16_t detail_length;
    uint8_t  detail[];         // Serialized change details
};
```

Journals are synchronized between peers via JOURNAL packets and provide:
- Complete audit trail (compliance: SOX, PCI-DSS, HIPAA)
- Before/after diffs for every change
- Forensic analysis capability
- Automatic documentation of all network state transitions

### 10. Error Handling

POOL never silently drops packets. Every error condition produces:
- A logged journal entry
- A telemetry counter increment
- An optional encrypted error notification to the peer

Error categories:
| Code | Category | Description |
|------|----------|-------------|
| 0x01 | AUTH_FAIL | Authentication/HMAC verification failed |
| 0x02 | DECRYPT_FAIL | Decryption failed |
| 0x03 | SEQ_INVALID | Sequence number outside valid window |
| 0x04 | FRAG_TIMEOUT | Fragment reassembly timed out |
| 0x05 | MTU_EXCEEDED | Packet exceeds negotiated MTU |
| 0x06 | CONFIG_REJECT | Configuration change rejected by policy |
| 0x07 | REKEY_FAIL | Key rotation failed |
| 0x08 | JOURNAL_FULL | Journal storage exhausted |
| 0x09 | OVERLOAD | Node is overloaded (backpressure signal) |
| 0x0A | VERSION_MISMATCH | Protocol version incompatible |

### 11. Security Vulnerability Response

See [`SECURITY.md`](SECURITY.md) for the complete vulnerability response playbook,
including triage procedures, emergency patching, crypto-specific incident playbooks,
and version transition guidance.

### 12. IPv6 Support

POOL provides full native IPv6 support across the entire stack. IP addresses are
not carried in POOL packet headers — the underlying TCP transport layer handles
network addressing. This means the wire protocol is unchanged between IPv4 and IPv6.

#### 12.1 Internal Address Representation

All IP addresses are stored internally as 128-bit (16-byte) values:

- **IPv4 addresses** are stored as IPv4-mapped IPv6: `::ffff:x.x.x.x`
- **IPv6 addresses** are stored natively as 16 bytes
- An `addr_family` field (`AF_INET` or `AF_INET6`) accompanies each address
- Helper functions `pool_ipv4_to_mapped()`, `pool_mapped_to_ipv4()`, and
  `pool_addr_is_v4mapped()` handle conversions

#### 12.2 Dual-Stack Listener

The kernel module's TCP listener uses `AF_INET6` with `IPV6_V6ONLY=0`:

- Accepts both IPv4 and IPv6 connections on a single socket
- IPv4 clients appear as `::ffff:x.x.x.x` in the peer address
- No separate IPv4 listener is needed

#### 12.3 Crypto IP Binding

The proof-of-work puzzle in the handshake binds to the client's IP address.
The puzzle input uses the full 16-byte address (28 bytes total: 16-byte address +
8-byte server secret + 4-byte timestamp). This applies identically to IPv4-mapped
and native IPv6 addresses.

#### 12.4 Ioctl Interface

The `pool_connect_req` structure uses:
- `peer_addr[16]` — 128-bit destination address
- `addr_family` — `AF_INET` or `AF_INET6`
- `peer_port` — destination port

The `pool_session_info` structure reports the same fields for active sessions.

#### 12.5 Raw Socket Path

The raw IP socket transport (protocol 253) remains IPv4-only. IPv4-mapped
addresses are converted at the boundary using the helper functions. Raw socket
transport for IPv6 is not currently implemented.

#### 12.6 Userspace Tools

All CLI tools (`poolctl`, `pool_test`, `pool_vault`, `pool_relay`, `pool_bridge`,
`pool_migrate`) accept IPv6 addresses, bracketed IPv6 literals (`[::1]`), and
hostnames via `getaddrinfo()`. Display output uses `inet_ntop()` with column
widths accommodating the longer IPv6 address format.

### 13. How POOL Addresses Each Documented Failure Category

| Failure Category | TCP/IP Problem | POOL Solution |
|-----------------|---------------|---------------|
| No built-in security | Trust-by-default | Mandatory mutual auth + encryption |
| IP Spoofing | Unverified source | Challenge-response proves reachability |
| SYN Flood | Stateful handshake | Stateless challenge, zero pre-allocation |
| Sequence prediction | Predictable ISN | CSPRNG + encrypted counter sequences |
| RST Injection | Unauth'd control | All packets HMAC-authenticated |
| No encryption | Plaintext default | ChaCha20-Poly1305 always-on |
| MITM attacks | No channel binding | ECDH key agreement + HMAC |
| Header manipulation | No header auth | HMAC-SHA256 covers entire packet |
| Address exhaustion | 32-bit IPv4 | 256-bit self-describing addresses |
| Address conflicts | DHCP/static clash | Crypto-derived globally unique IDs |
| MTU silent drops | PMTUD failures | Active probing + mandatory fragmentation |
| No monitoring | External tools only | Built-in per-flow telemetry |
| Config drift | No versioning | Atomic versioned config with rollback |
| No audit trail | External logging | Built-in change journal |
| Unsaved config | Volatile state | Persistent versioned config state |
| Vendor lock-in | Proprietary CLIs | Single open specification |
| BGP hijacking | No route auth | Crypto-bound addresses verify origin |
| DNS dependency | Separate service | Embedded peer discovery, no DNS needed |
| Cascading failure | No backpressure | OVERLOAD signal + built-in flow control |
| Change window risk | No auto-rollback | Deadline-based automatic rollback |

### 13. Security Amendments (P01–P13)

The following amendments address 13 protocol-level failure modes identified
during comprehensive security analysis. All are normative requirements for
compliant implementations.

#### 13.1 Nonce Construction (P01)

The 96-bit nonce for ChaCha20-Poly1305 MUST be constructed as:

```
nonce[0:3]  = hmac_key[0:4]   (session-unique prefix)
nonce[4:11] = big-endian(seq)  (64-bit sequence number)
```

Implementations MUST trigger rekeying before the sequence counter reaches
2^63 to prevent nonce reuse. After rekeying, the new hmac_key provides a
fresh prefix, guaranteeing nonce uniqueness across key epochs.

**Rationale:** Using zero bytes for nonce[0:3] (as in earlier drafts) reduces
the effective nonce space by 32 bits, increasing collision probability across
concurrent sessions.

#### 13.2 Challenge Secret Rotation (P02)

The server MUST rotate its challenge secret at least every 300 seconds
(5 minutes). During rotation, the server MUST accept challenges generated
with the previous secret for a grace period of 2× the rotation interval
(10 minutes) to avoid rejecting in-flight handshakes.

**Rationale:** Without rotation, captured challenge parameters could be
solved offline and replayed indefinitely.

#### 13.3 HMAC Verification Timing (P03)

All HMAC verification MUST use constant-time comparison
(`crypto_memneq` in kernel, `CRYPTO_memcmp` in userspace). Standard
`memcmp` MUST NOT be used for any authentication tag or HMAC comparison.

**Rationale:** Variable-time comparison leaks tag bytes via timing
side-channels, enabling byte-by-byte forgery.

#### 13.4 Fragment Resource Limits (P04)

Implementations MUST enforce:
- Maximum 16 concurrent fragment reassembly slots per peer
- Maximum 5-second timeout per incomplete fragment sequence
- LRU eviction when all fragment slots are occupied
- Total fragment buffer memory capped at 16 × MTU per peer

**Rationale:** Without limits, an attacker can exhaust reassembly memory
with many small fragment sequences that are never completed.

#### 13.5 MTU Probe Rate Limiting (P05)

DISCOVER packets used for MTU probing MUST be rate-limited to at most
1 probe per second per peer. Probe responses MUST only be accepted from
peers with established sessions (authenticated by session HMAC).

**Rationale:** Unauthenticated probes can be amplified by spoofing,
causing exponential probe storms between peers.

#### 13.6 Rekey Tie-Breaking (P06)

When both peers initiate REKEY simultaneously, the peer with the
lexicographically lower session_id MUST proceed as the rekey initiator.
The other peer MUST abort its rekey attempt and process the received
REKEY as a responder. Each rekey MUST include a monotonically increasing
epoch number to disambiguate key material.

**Rationale:** Without deterministic tie-breaking, both peers may use
inconsistent key material for intermediate packets.

#### 13.7 Config Rollback Semantics (P07)

If no CONFIG_CONFIRM is received within the rollback deadline,
implementations MUST treat silence as confirmation (not as failure).
The CONFIG sender MUST retry the confirmation request at least 3 times
with exponential backoff (1s, 2s, 4s) before the deadline expires.

**Rationale:** An attacker who can suppress a single packet should not
be able to force a rollback to a less secure configuration.

#### 13.8 INIT Replay Protection (P10, P11)

INIT packets MUST include a 64-bit nanosecond timestamp. The server
MUST reject INIT packets with timestamps more than ±30 seconds from
the server's current time. The puzzle difficulty MUST be at least 16
(requiring 2^16 hash operations on average) to prevent free INIT spam.

**Rationale:** Without timestamps, captured INIT packets can be replayed
indefinitely. Without minimum difficulty, INIT→CHALLENGE spam has zero
computational cost.

#### 13.9 Version Downgrade Prevention (P13)

After a successful v2 (hybrid post-quantum) handshake with a peer,
implementations MUST record the peer's maximum supported version.
Subsequent connections from that peer at a lower version MUST be
rejected with a CLOSE packet containing error code VERSION_DOWNGRADE.

**Rationale:** An active attacker could strip the v2 negotiation,
forcing peers into v1 (X25519-only) mode which lacks post-quantum
protection.

#### 13.10 Compression Oracle Mitigation (P08)

When the COMPRESSED flag (bit 1) is set, implementations SHOULD be
aware that compression before encryption leaks plaintext information
via ciphertext length (CRIME/BREACH-style attack). Applications
handling secrets (passwords, tokens, keys) SHOULD either:
1. Disable compression for sensitive channels, OR
2. Pad compressed output to fixed block sizes (e.g., 256-byte blocks)

**Rationale:** Compression ratio varies with plaintext content, leaking
information through observable ciphertext sizes.

#### 13.11 Address Checksum Collision Bound (P09)

The CRC32 checksum used in POOL address derivation (§5) has a birthday
bound of approximately 2^16 (~65,536) addresses before a 50% collision
probability. For deployments exceeding 10,000 nodes, implementations
SHOULD upgrade to a truncated SHA-256 (first 4 bytes) for address
derivation in protocol v2+.

#### 13.12 Anti-Replay Window (N02)

Implementations MUST maintain a sliding window of at least 64 sequence
numbers. Packets with sequence numbers older than (highest_seen - 64)
MUST be silently discarded. Duplicate sequence numbers within the
window MUST also be discarded.
