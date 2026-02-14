# POOL Operator Incentive Structure
## Why Network Operators Deploy POOL Relays

### The Problem

Every new transport protocol asks network operators to deploy infrastructure
for zero reward. RSVP, HIP, SCTP, DCCP — all required router/middlebox changes
with no tangible benefit to the operator. Operators rationally refused.

### POOL's Answer: Bandwidth Reciprocity

POOL relay operators are rewarded through a simple, unforgeable incentive model
that requires no cryptocurrency, no tokens, and no external payment system.

---

## The Generosity Score

Every POOL relay tracks two counters:

- **Bytes contributed**: traffic relayed for other nodes
- **Bytes consumed**: traffic other nodes relayed for this node

The ratio is the **generosity score**:

```
generosity_score = bytes_contributed / bytes_consumed
```

### Score Effects

| Score Range | Classification | Effect |
|-------------|----------------|--------|
| > 2.0 | Major contributor | Priority routing + first in queue at all peers |
| 1.0 – 2.0 | Balanced | Normal routing |
| 0.5 – 1.0 | Light consumer | Normal routing (no penalty until 0.5) |
| < 0.5 | Heavy consumer | Deprioritized queuing (never blocked) |

### Why It's Unforgeable

- Scores are exchanged via POOL HEARTBEAT packets (built-in telemetry channel)
- Each node's counters are signed with its X25519 private key
- POOL's mandatory mutual authentication means peers are verified
- A node can't fake contributions because the peer tracks what it received
- Bilateral verification: your "contributed" must match the peer's "consumed"

### Why Operators Care

1. **Per-flow visibility**: POOL's built-in telemetry gives operators RTT, jitter,
   loss, and throughput per session — metrics TCP doesn't expose at the transport
   level. This is valuable for capacity planning even without relaying.

2. **Priority routing**: Operators who relay traffic get their own traffic
   prioritized through the relay network. This is a direct, measurable benefit.

3. **Zero marginal cost**: Relay bandwidth is spare capacity that would otherwise
   be idle. The operator isn't paying extra — they're monetizing idle resources.

4. **Compliance**: POOL's change journal provides a cryptographic audit trail
   (SHA256-chained) of every session and state change. This satisfies compliance
   requirements that TCP cannot meet.

5. **No additional infrastructure**: The relay daemon runs alongside the POOL
   kernel module on existing servers. No new hardware, no dedicated appliances.

---

## Relay Network Architecture

```
Organization A                    Organization B
┌─────────────────┐              ┌─────────────────┐
│  App Servers     │              │  App Servers     │
│  (pool.ko)       │              │  (pool.ko)       │
│       │          │              │       │          │
│  pool_relay ─────┼──── POOL ───┼── pool_relay     │
│  score: 1.3      │   encrypted │  score: 0.9      │
└─────────────────┘              └─────────────────┘
         │                                │
         └──────── pool_relay ────────────┘
                   (ISP edge)
                   score: 2.1 (major contributor)
                   → gets priority routing everywhere
```

## Deployment Steps

```bash
# 1. Load POOL module
insmod pool.ko

# 2. Start relay daemon
pool_relay start

# 3. Peer with another relay
pool_relay enroll 10.4.4.101

# 4. Check reputation
pool_relay status

# Output:
# Generosity score:     1.30 (priority routing)
# Total relayed:        142 MB
# Total consumed:       109 MB
# Active peers:         3
```

## Comparison with Failed Incentive Models

| Protocol | Incentive | Why It Failed |
|----------|-----------|---------------|
| RSVP | None — operators expected to deploy for free | No deployment |
| HIP | None — academic project | No deployment |
| SCTP | None — designed for telco, assumed operator cooperation | Limited to telco |
| Tor | Volunteer goodwill | Chronic capacity shortage |
| BitTorrent | Tit-for-tat file sharing | Only works for file sharing |
| **POOL** | **Bandwidth reciprocity + priority routing + visibility** | **Direct measurable benefit** |

## Key Difference

POOL's incentive structure is **built into the protocol itself** — not bolted on
as an afterthought. The generosity score travels in HEARTBEAT packets that POOL
already sends. The priority routing is handled by the relay daemon that operators
already run. The telemetry is data that POOL already collects.

No new infrastructure. No new protocol. No new trust model. Just bandwidth
for bandwidth, verified by cryptography.
