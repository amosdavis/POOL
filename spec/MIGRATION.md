# POOL Migration Strategy
## From TCP/IP to POOL — A Practical Transition Path

### The Problem

Every transport protocol that tried to replace TCP/IP failed because it required
a flag-day cutover: both endpoints must support the new protocol simultaneously,
but neither side has incentive to be first. This chicken-and-egg problem killed
CurveCP, MinimaLT, SST, tcpcrypt, HIP, and dozens of others.

### POOL's Answer: Three-Phase Migration

POOL provides three coexisting mechanisms that allow incremental adoption without
requiring any endpoint to change all at once.

---

## Phase 1: Bridge Mode (Zero Changes Required)

**Deploy `pool_bridge` at the network edge.**

```
TCP Client → [pool_bridge tcp2pool] → POOL Network → [pool_bridge pool2tcp] → TCP Server
```

- Legacy TCP applications connect to `pool_bridge` as if it were a normal TCP server
- `pool_bridge` establishes a POOL session to the destination and forwards all traffic
- The internal network path is encrypted (ChaCha20-Poly1305) and authenticated (HMAC-SHA256)
- Neither the client nor the server needs any modification
- Network operators get POOL's built-in telemetry on the bridged traffic

**Who deploys this:** Network operators (datacenter, enterprise) who want encrypted
internal transport without touching applications.

**What they get immediately:**
- Per-flow RTT, jitter, loss metrics (POOL built-in telemetry)
- Encrypted east-west traffic with no application changes
- Change journal for compliance/audit
- Zero-config mutual authentication between bridge endpoints

---

## Phase 2: Shim Mode (No Recompilation)

**Deploy `libpool_shim.so` via LD_PRELOAD.**

```bash
LD_PRELOAD=/usr/lib/libpool_shim.so nginx
LD_PRELOAD=/usr/lib/libpool_shim.so curl https://example.com
```

- The shim intercepts POSIX socket calls (socket, connect, send, recv, etc.)
- TCP connections are transparently routed through the POOL kernel module
- Applications work unmodified — no recompilation, no config changes
- Optional fallback to TCP if POOL is unavailable (POOL_SHIM_FALLBACK=1)
- Port-selective interception (POOL_SHIM_PORTS=80,443)

**Who deploys this:** Application teams who want POOL security without changing code.

**What they get:**
- Transparent encryption for existing applications
- Gradual per-service rollout (just change the systemd unit file)
- Easy rollback (remove LD_PRELOAD)
- Can coexist with non-POOL services on the same host

---

## Phase 3: Native POOL Applications

**Build directly against the POOL ioctl API.**

```c
#include "pool.h"
int fd = open("/dev/pool", O_RDWR);
ioctl(fd, POOL_IOC_CONNECT, &req);
ioctl(fd, POOL_IOC_SEND, &send_req);
ioctl(fd, POOL_IOC_RECV, &recv_req);
```

- Applications use POOL natively for maximum security and performance
- No TCP involvement — pure POOL transport
- Access to all POOL features: channels, telemetry, journaling
- Example: `pool_vault` (encrypted distributed file vault)

**Who builds this:** Application developers who need POOL's unique guarantees.

---

## Migration Timeline

```
Day 1:    Load pool.ko on internal servers
          Deploy pool_bridge at edge → encrypted internal traffic

Week 1:   Add LD_PRELOAD=libpool_shim.so to key services
          Monitor via /proc/pool/telemetry and pool_migrate status

Month 1:  All internal east-west traffic running over POOL
          TCP bridges at edge for external clients

Month 3:  Partner organizations deploy POOL
          pool_relay network forming between organizations

Year 1:   Native POOL applications in production
          TCP bridges still at edge but handling decreasing traffic
```

## Rollback at Every Phase

- **Phase 1:** Stop pool_bridge → traffic reverts to direct TCP
- **Phase 2:** Remove LD_PRELOAD → application uses TCP directly
- **Phase 3:** Application has TCP fallback mode via POOL_SHIM_FALLBACK

No phase requires burning bridges. TCP continues to work at all times.

## Tools

| Tool | Purpose |
|------|---------|
| `pool_bridge` | TCP↔POOL bidirectional proxy |
| `pool_migrate` | Migration status and connectivity testing |
| `libpool_shim.so` | LD_PRELOAD socket interceptor |
| `poolctl` | Manual POOL session management |
| `pool_vault` | Native POOL file sharing application |
| `pool_relay` | Relay daemon with operator incentives |

## Commands

```bash
# Check if POOL is working
pool_migrate status

# Test connectivity to a peer
pool_migrate test 10.4.4.101 9253

# Bridge a TCP service
pool_bridge tcp2pool 8080 10.4.4.101 9253

# Run an app over POOL transparently
LD_PRELOAD=/usr/lib/libpool_shim.so curl http://10.4.4.101:8080

# Native POOL file transfer
pool_vault push 10.4.4.101 myfile.tar.gz /incoming/myfile.tar.gz
```

---

## IPv6 Deployment

POOL supports full native IPv6 across all phases. All tools accept IPv4 addresses,
IPv6 addresses, bracketed IPv6 literals (`[::1]`), and hostnames.

### Dual-Stack Operation

The POOL kernel listener uses `AF_INET6` with `IPV6_V6ONLY=0`, accepting both
IPv4 and IPv6 connections on a single port. No separate IPv4 listener is needed.
IPv4 clients appear internally as `::ffff:x.x.x.x` (IPv4-mapped IPv6).

### Phase-Specific IPv6 Notes

**Phase 1 (Bridge):** The bridge's TCP listener is dual-stack. Both IPv4 and IPv6
TCP clients are accepted and forwarded over POOL. The `pool_bridge` CLI accepts
IPv6 destinations:

```bash
pool_bridge --tcp-to-pool [::1]:8080 9253
pool_bridge --pool-to-tcp [fd00::1]:443
```

**Phase 2 (Shim):** The shim intercepts both `AF_INET` and `AF_INET6` `connect()`
calls. IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) are detected and handled
correctly. Pure IPv6 connections are routed through POOL natively. `getpeername()`
and `accept()` return the correct address family.

**Phase 3 (Native):** All CLI tools use `getaddrinfo()` for address resolution:

```bash
# IPv6 connectivity test
pool_migrate test ::1 9253
pool_migrate test fd00::1 9253

# IPv6 vault transfer
pool_vault push fd00::1 myfile.tar.gz /incoming/myfile.tar.gz

# IPv6 relay peering
pool_relay enroll fd00::2

# IPv6 direct connection
poolctl connect ::1 9253
```

### Raw Socket Transport

The raw IP socket transport (protocol 253) remains IPv4-only. IPv6 traffic uses
the TCP transport path exclusively. This is transparent to applications.
