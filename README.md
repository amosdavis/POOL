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
├── README.md              # This file
├── spec/
│   ├── PROTOCOL.md        # Complete protocol specification
│   └── STALLED_PROTOCOLS.md  # Analysis of 18 failed protocols
├── linux/
│   ├── pool.h             # Public API (packet types, ioctls, structs)
│   ├── pool_internal.h    # Kernel-internal state
│   ├── pool_main.c        # Module init, char device, ioctl dispatch
│   ├── pool_crypto.c      # X25519 KPP, HKDF, ChaCha20-Poly1305, HMAC
│   ├── pool_net.c         # TCP transport, POOL packet framing
│   ├── pool_session.c     # Handshake, session lifecycle, RX thread
│   ├── pool_data.c        # Data send/recv with fragmentation
│   ├── pool_telemetry.c   # Heartbeat, RTT/jitter/throughput tracking
│   ├── pool_sysinfo.c     # /proc/pool/* reporting
│   ├── pool_journal.c     # SHA256-chained audit journal
│   ├── poolctl.c          # CLI control tool
│   ├── pool_test.c        # Benchmark tool (server/client/bench)
│   ├── poold.c            # Daemon (starts listener)
│   ├── Kbuild             # Kernel build config
│   └── Makefile           # Module + tools build
├── windows/               # (Future: Windows driver)
├── common/                # (Future: cross-platform code)
└── tools/                 # (Future: additional tools)
```

## License

Proprietary. All rights reserved.
