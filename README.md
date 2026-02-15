# POOL — Protected Orchestrated Overlay Link

A secure transport protocol implemented as a Linux kernel module. POOL replaces TCP/IP's trust-by-default model with mandatory mutual authentication, always-on encryption, and cryptographic sequence numbers.

## Status

✅ **Working** — 500 MB encrypted data transfer tested between two QEMU VMs at 24.3 Mbps with full HMAC-SHA256 authentication and ChaCha20-Poly1305 encryption.

## Features

- **Mandatory mutual authentication** — X25519 ECDH key exchange on every connection
- **Always-on encryption** — ChaCha20-Poly1305 AEAD, no plaintext mode
- **Stateless handshake** — INIT → CHALLENGE (with proof-of-work puzzle) → RESPONSE → ACK; immune to SYN flood attacks
- **HMAC-SHA256 on every packet** — prevents hijacking, injection, and replay
- **Cryptographic sequence numbers** — derived from HKDF, not predictable
- **Built-in telemetry** — per-session RTT, jitter, loss, throughput via HEARTBEAT packets
- **Automatic rekeying** — after configurable packet count or time interval
- **Change journaling** — SHA256-chained audit log of all state transitions
- **procfs reporting** — `/proc/pool/{status,sessions,telemetry,journal}`

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    User Space                       │
│   poolctl       pool_test       poold               │
│      │              │             │                  │
│      └──────────────┴─────────────┴── /dev/pool      │
└─────────────────────────────────────────────────────┘
                       │ ioctl
┌──────────────────────┴──────────────────────────────┐
│              pool.ko (Kernel Module)                │
│                                                     │
│  ┌────────────┐  ┌──────────────┐  ┌─────────────┐  │
│  │  Crypto    │  │   Session    │  │  Network    │  │
│  │  X25519    │  │  Handshake   │  │  TCP Framing│  │
│  │  HKDF      │  │  RX Thread   │  │  Send/Recv  │  │
│  │  ChaCha20  │  │  Rekey       │  │  Listener   │  │
│  │  HMAC-256  │  │              │  │             │  │
│  └────────────┘  └──────────────┘  └─────────────┘  │
│  ┌────────────┐  ┌──────────────┐  ┌─────────────┐  │
│  │  Data      │  │  Telemetry   │  │  Journal    │  │
│  │  Fragment  │  │  Heartbeat   │  │  SHA256     │  │
│  │  Reassemble│  │  RTT/Jitter  │  │  Audit Log  │  │
│  └────────────┘  └──────────────┘  └─────────────┘  │
│  ┌────────────┐                                     │
│  │  Sysinfo   │                                     │
│  │  /proc/pool│                                     │
│  └────────────┘                                     │
└─────────────────────────────────────────────────────┘
```

## Protocol Specification

See [`spec/PROTOCOL.md`](spec/PROTOCOL.md) for the complete protocol specification including packet format, handshake flow, crypto suite, addressing, telemetry, configuration, and journaling.

## Packet Format

80-byte header (all multi-byte fields big-endian):

| Field | Size | Description |
|-------|------|-------------|
| Version/Type | 1B | Protocol version (4 bits) + packet type (4 bits) |
| Flags | 2B | ENCRYPTED, FRAGMENT, ACK, TELEMETRY, REKEY, JOURNAL |
| Sequence | 8B | Cryptographic sequence number |
| Acknowledgment | 8B | Highest received peer sequence |
| Session ID | 16B | 128-bit session identifier |
| Timestamp | 8B | Nanosecond timestamp |
| Payload Length | 2B | Payload size in bytes |
| Channel | 1B | Multiplexed channel ID |
| Reserved | 1B | — |
| HMAC | 32B | HMAC-SHA256 over header+payload |

## Building

**Requirements:** Linux kernel 6.1+ headers, standard kernel build tools.

```bash
cd linux/

# Build kernel module
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules

# Build userspace tools
make tools

# Install
insmod pool.ko
cp poolctl pool_test poold /usr/sbin/
```

## Usage

### Start a listener
```bash
poolctl listen 9253
```

### Connect to a peer
```bash
poolctl connect <ip> 9253
```

### Send data
```bash
poolctl send 0 "Hello, POOL"     # session 0
```

### 500 MB benchmark
```bash
# Node 2 (server):
pool_test server 9253

# Node 1 (client):
pool_test bench <node2_ip> 9253
```

### Check status
```bash
cat /proc/pool/status
cat /proc/pool/sessions
cat /proc/pool/telemetry
cat /proc/pool/journal
```

## Handshake Flow

```
Client                              Server
  │                                    │
  │──── INIT (pubkey) ────────────────>│
  │                                    │
  │<─── CHALLENGE (pubkey, puzzle) ────│
  │                                    │
  │  [Both: ECDH → shared_secret]     │
  │  [Both: HKDF → session keys]      │
  │  [Client: solve puzzle]            │
  │                                    │
  │──── RESPONSE (solution, proof) ──>│
  │                                    │
  │<─── ACK ──────────────────────────│
  │                                    │
  │  [Session established]             │
  │  [All further packets encrypted]   │
```

## Adoption Strategy

POOL solves the four problems that killed every previous transport protocol:

### 1. Migration Strategy — `pool_bridge`
TCP↔POOL bidirectional proxy. Deploy at the network edge — legacy TCP apps connect normally, traffic is encrypted over POOL internally. No application changes required.
```bash
pool_bridge tcp2pool 8080 10.4.4.101 9253   # TCP in, POOL out
pool_bridge pool2tcp 9253 127.0.0.1 80      # POOL in, TCP out
```
See [`spec/MIGRATION.md`](spec/MIGRATION.md) for the three-phase migration plan.

### 2. Compatibility Layer — `libpool_shim.so`
LD_PRELOAD shim that intercepts POSIX socket calls. Existing applications (curl, nginx, ssh) work over POOL with zero code changes.
```bash
LD_PRELOAD=/usr/lib/libpool_shim.so curl http://10.4.4.101
LD_PRELOAD=/usr/lib/libpool_shim.so nginx
```

### 3. Killer Application — `pool_vault`
Encrypted distributed file vault that only works over POOL. No accounts, no cloud, no intermediaries. Security guarantees hold because POOL enforces them at transport level.
```bash
pool_vault serve /shared                          # Share a directory
pool_vault push 10.4.4.101 report.pdf /incoming/  # Push a file
pool_vault pull 10.4.4.101 /data/backup.tar.gz ./ # Pull a file
```

### 4. Operator Incentives — `pool_relay`
Relay daemon with bandwidth reciprocity. Operators earn a generosity score (contributed/consumed ratio) → higher score = priority routing. No cryptocurrency, no tokens — just bandwidth for bandwidth, verified by cryptography.
```bash
pool_relay start                    # Start relaying traffic
pool_relay enroll 10.4.4.101        # Peer with another relay
pool_relay status                   # Check reputation score
```
See [`spec/OPERATORS.md`](spec/OPERATORS.md) for the incentive model.

## Security

See [`spec/SECURITY.md`](spec/SECURITY.md) for the vulnerability response playbook covering triage, coordinated disclosure, emergency patching, crypto-specific incident procedures, and version transition guidance.

## Test Results

```
=== POOL Data Transfer Complete ===
Total sent:     524288000 bytes (500.0 MB)
Time:           172.82 seconds
Throughput:     24.3 Mbps
Encrypted:      Yes (ChaCha20-Poly1305)
Authenticated:  Yes (HMAC-SHA256)
```

## Files

```
POOL/
├── README.md
├── spec/
│   ├── PROTOCOL.md           # Complete protocol specification
│   ├── SECURITY.md           # Vulnerability response playbook
│   ├── MIGRATION.md          # Three-phase TCP→POOL migration strategy
│   ├── OPERATORS.md          # Network operator incentive structure
│   └── STALLED_PROTOCOLS.md  # Analysis of 18 failed protocols
├── linux/                    # Kernel module + core tools
│   ├── pool.h                # Public API (packet types, ioctls, structs)
│   ├── pool_internal.h       # Kernel-internal state
│   ├── pool_main.c           # Module init, char device, ioctl dispatch
│   ├── pool_crypto.c         # X25519 KPP, HKDF, ChaCha20-Poly1305, HMAC
│   ├── pool_net.c            # TCP transport, POOL packet framing
│   ├── pool_session.c        # Handshake, session lifecycle, RX thread
│   ├── pool_data.c           # Data send/recv with fragmentation
│   ├── pool_telemetry.c      # Heartbeat, RTT/jitter/throughput tracking
│   ├── pool_sysinfo.c        # /proc/pool/* reporting
│   ├── pool_journal.c        # SHA256-chained audit journal
│   ├── poolctl.c             # CLI control tool
│   ├── pool_test.c           # Benchmark tool (server/client/bench)
│   ├── poold.c               # Daemon (starts listener)
│   ├── Kbuild                # Kernel build config
│   └── Makefile              # Module + tools build
├── shim/                     # Socket compatibility layer
│   ├── pool_shim.c           # LD_PRELOAD socket interceptor
│   └── Makefile
├── bridge/                   # TCP↔POOL migration bridge
│   ├── pool_bridge.c         # Bidirectional TCP↔POOL proxy
│   ├── pool_migrate.c        # Migration status and control tool
│   └── Makefile
├── vault/                    # Killer application
│   ├── pool_vault.c          # Encrypted distributed file vault
│   └── Makefile
├── relay/                    # Operator incentive relay
│   ├── pool_relay.c          # Relay daemon with generosity scoring
│   └── Makefile
├── windows/                  # (Future: Windows driver)
├── common/                   # (Future: cross-platform code)
└── tools/                    # (Future: additional tools)
```

## License

Proprietary. All rights reserved.
