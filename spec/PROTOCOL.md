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

### 12. How POOL Addresses Each Documented Failure Category

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
