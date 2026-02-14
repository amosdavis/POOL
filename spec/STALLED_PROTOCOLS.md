# Stalled, Expired, and Abandoned Network Protocol Proposals
## A Comprehensive Feature Inventory from IETF Internet-Drafts and Research

This document catalogs every known stalled, expired, or abandoned networking protocol
proposal and the features each one attempted to provide. The goal is to ensure the
POOL protocol incorporates the best ideas from these failed efforts while avoiding
their pitfalls.

---

## 1. CurveCP (Daniel J. Bernstein, ~2011, Never Standardized)

**What It Tried To Do:** Replace TCP with a cryptographically secure transport.

| Feature | Description |
|---------|-------------|
| Always-on encryption | All data encrypted using Curve25519 key exchange + NaCl |
| No CA dependency | Peer identity via raw public keys, no certificate authorities |
| Replay protection | Built-in nonce management prevents replay attacks |
| MITM resistance | Mutual authentication during connection setup |
| Message-oriented | Preserves message boundaries unlike TCP's byte stream |
| Cookie-based DoS protection | Server issues cookie before allocating state |
| Forward secrecy | Ephemeral keys per session |
| Connection mobility | Session survives IP address changes |

**Why It Failed:**
- UDP-based: blocked by many enterprise firewalls and NATs
- Complex handshake, hard to implement correctly
- No IETF standardization effort
- TLS improvements and QUIC overtook its design space
- No mainstream library adoption

---

## 2. MinimaLT (~2013, Expired IETF Draft)

**Draft:** draft-agl-tcpm-minimalt-00

**What It Tried To Do:** Ultra-low-latency secure transport with mobility support.

| Feature | Description |
|---------|-------------|
| 0-RTT connection establishment | Resume previous sessions with zero round-trip cost |
| Perfect forward secrecy | Ephemeral Diffie-Hellman per connection |
| IP mobility | Sessions persist across IP address changes |
| Stream multiplexing | Multiple streams per connection |
| Encrypted by default | All payload encrypted, no opt-out |
| Minimal handshake overhead | Designed for minimal latency penalty |
| Key caching | Long-term server keys cached for fast reconnection |
| DoS resistance | Puzzle-based client proof-of-work |

**Why It Failed:**
- UDP-based, blocked by middleboxes
- Limited documentation and reference implementation
- QUIC achieved similar goals with massive industry backing (Google, IETF)
- Never matured beyond experimental paper

---

## 3. SST — Structured Stream Transport (MIT, 2007, Never Standardized)

**What It Tried To Do:** Fix TCP's head-of-line blocking with hierarchical streams.

| Feature | Description |
|---------|-------------|
| Hierarchical child streams | Parent connection spawns unlimited child streams |
| Independent stream flow control | Each stream has its own flow/congestion control |
| No head-of-line blocking | Loss on one stream doesn't stall others |
| Reliable + unreliable modes | Per-stream choice of reliability semantics |
| Shared congestion control | All streams share one congestion controller |
| Built-in security | Integrated authentication and encryption |
| Transactional semantics | Request/response pairs as first-class primitives |
| Datagram mode | Supports both stream and datagram delivery |

**Why It Failed:**
- No kernel-level implementation in any major OS
- Required applications to be rewritten for new API
- HTTP/2 and QUIC later solved head-of-line blocking within existing ecosystem
- No vendor or browser adoption

---

## 4. tcpcrypt (IETF TCPINC WG, RFC 8548 — Experimental, Stalled Deployment)

**Draft Series:** draft-ietf-tcpinc-tcpcrypt → RFC 8548

**What It Tried To Do:** Transparently encrypt all TCP traffic without application changes.

| Feature | Description |
|---------|-------------|
| Opportunistic TCP encryption | Encrypts if both sides support it, falls back otherwise |
| No application changes needed | Transparent to applications above TCP |
| Session IDs for auth | Exposes session ID upward for optional app-level authentication |
| Middlebox tolerant | Designed to survive NATs, proxies, resegmentation |
| Kernel-level operation | Runs inside the TCP stack in the OS kernel |
| Minimal handshake overhead | One extra round-trip for key exchange |
| No authentication by default | Encryption only; auth delegated to applications |

**Why It Stalled:**
- Experimental status only — never became Internet Standard
- No authentication = vulnerable to active MITM
- OS kernel adoption was extremely slow (Linux patches existed but weren't mainlined)
- TLS 1.3 and QUIC solved the problem more comprehensively
- Deployment required both endpoints to upgrade simultaneously

---

## 5. DCCP — Datagram Congestion Control Protocol (RFC 4340, Limited Adoption)

**What It Tried To Do:** Add congestion control to unreliable datagrams (like UDP + congestion control).

| Feature | Description |
|---------|-------------|
| Unreliable delivery with congestion control | Like UDP but fair to other traffic |
| Pluggable congestion control (CCIDs) | Negotiate algorithm: TCP-like (CCID2) or TFRC (CCID3) |
| Feature negotiation at setup | Endpoints negotiate capabilities during handshake |
| ECN support | Early congestion signaling before packet loss |
| Connection-oriented | Formal setup and teardown (unlike UDP) |
| Per-flow acknowledgments | Optional, flexible ack mechanisms |
| Message-oriented | Preserves message boundaries |

**Why It Stalled:**
- Firewall/NAT traversal: middleboxes block unknown IP protocols
- No multicast support (unicast only)
- No built-in encryption or authentication
- Limited OS and application support
- UDP + application-level congestion control became the de facto alternative

---

## 6. SCTP — Stream Control Transmission Protocol (RFC 9260, Limited Deployment)

**What It Tried To Do:** Multi-streaming, multi-homing, message-oriented transport.

| Feature | Description |
|---------|-------------|
| Multi-streaming | Multiple independent streams within one association |
| Multi-homing | Multiple IP addresses per endpoint for failover |
| Message-oriented | Preserves application message boundaries |
| Ordered and unordered delivery | Per-stream choice of ordering semantics |
| Four-way handshake with cookie | INIT/INIT-ACK/COOKIE-ECHO/COOKIE-ACK prevents SYN floods |
| Heartbeat mechanism | Probes backup paths for reachability |
| Partial reliability extension (PR-SCTP) | Application can accept data loss for timeliness |
| Graceful shutdown | No half-open states |

**Why Deployment Stalled:**
- Middlebox ossification: NATs/firewalls don't understand SCTP
- Encapsulation over UDP (RFC 6951) adds overhead
- WebRTC data channels use SCTP-over-DTLS-over-UDP (complex stack)
- No broad application adoption outside telephony signaling
- QUIC now provides multi-streaming over UDP with better deployment story

---

## 7. HIP — Host Identity Protocol (Experimental RFCs 7401/9063, Stalled)

**What It Tried To Do:** Separate host identity from network location (IP address).

| Feature | Description |
|---------|-------------|
| Identifier-locator split | Cryptographic Host Identity ≠ IP address |
| Public key-based identity | Each host has a keypair as its global identity |
| Mutual authentication | Strong DoS-resistant base exchange |
| IPsec ESP integration | Encrypts data using IPsec after HIP handshake |
| NAT traversal extensions | Later drafts added middlebox traversal |
| Mobility support | Seamless handoff when IP address changes |
| Multi-homing | Multiple simultaneous network attachments |
| Legacy application compatibility | Works with IPv4 and IPv6 apps unchanged |
| Rendezvous infrastructure | HIP DNS records and rendezvous servers |

**Why It Stalled:**
- Requires changes at end-hosts AND potentially middleboxes
- Never got vendor/browser/OS mainstream support
- Competing solutions (VPNs, QUIC mobility, overlay networks) gained traction
- Complexity of deployment for marginal perceived benefit
- Stayed Experimental, never became Internet Standard

---

## 8. RSVP / IntServ (RFC 2205/2210, Largely Abandoned for Internet-Scale)

**What It Tried To Do:** Per-flow QoS reservation across the Internet.

| Feature | Description |
|---------|-------------|
| Per-flow resource reservation | Reserve bandwidth, delay guarantees per flow |
| Admission control | Network admits or rejects flows based on capacity |
| Guaranteed service class | Hard delay/bandwidth bounds |
| Controlled-load service class | Approximates unloaded network behavior |
| Multicast support | Reserve resources for multicast trees |
| Soft-state model | Reservations time out and must be refreshed |
| Path/Resv message exchange | Bidirectional signaling for reservation |

**Why It Failed:**
- Requires per-flow state on EVERY router in the path — doesn't scale
- Core Internet routers can't maintain millions of flow states
- DiffServ (class-based, stateless) replaced it for core networks
- Operational complexity: requires universal deployment to work
- Modern SDN and MPLS QoS superseded the approach

---

## 9. DiffServ Interworking Drafts (Expired, Multiple Versions)

**Drafts:** draft-ietf-diffserv-rsvp, draft-ietf-issll-diffserv-rsvp

**What They Tried To Do:** Bridge IntServ (RSVP at edges) with DiffServ (core).

| Feature | Description |
|---------|-------------|
| RSVP-to-DSCP mapping | Translate per-flow reservations to aggregate classes |
| Edge-to-core handoff | IntServ at LAN edge, DiffServ in WAN core |
| Admission control at boundaries | Gate flows at the IntServ/DiffServ boundary |
| Policy-based mapping | Map reservation parameters to PHB (Per-Hop Behavior) |

**Why They Expired:**
- Operators preferred pure DiffServ or MPLS TE
- Mapping complexity between models was never cleanly resolved
- No interop testing or deployment at scale
- SDN rendered the approach largely academic

---

## 10. XTP — Xpress Transport Protocol (~1990s, Historic)

**What It Tried To Do:** High-performance transport with flexible reliability.

| Feature | Description |
|---------|-------------|
| Selective reliability | Choose reliable or unreliable per-message |
| Rate-based flow control | Sender rate control instead of window-based |
| Reliable multicast | Group communication with reliability guarantees |
| Priority/scheduling | Built-in packet priority mechanisms |
| Message framing | First-class message boundaries |
| Error control options | Forward error correction or ARQ selectable |
| Fast connection setup | Minimal handshake overhead |

**Why It Failed:**
- Over-engineered for its era — too complex for available hardware
- Military/research niche, no commercial adoption
- TCP extensions incrementally added many of its features
- No OS or vendor support

---

## 11. Minion (IETF Draft, Expired/Stalled)

**Draft:** draft-iyer-minion

**What It Tried To Do:** Structured datagram semantics multiplexed over TCP.

| Feature | Description |
|---------|-------------|
| Message framing over TCP | Preserves message boundaries within TCP byte stream |
| Multiplexing | Multiple logical flows over one TCP connection |
| Safe for middleboxes | Uses TCP as substrate, so NATs/firewalls pass it |
| Datagram semantics | Applications see messages, not byte streams |
| Backward compatible | Works through existing TCP infrastructure |

**Why It Stalled:**
- TCP ossification made changes to TCP semantics difficult
- HTTP/2 framing solved similar problems within HTTP
- QUIC provided a cleaner multiplexing solution
- Limited working group interest

---

## 12. NEAT — NEtwork Application Tuning (EU Research, ~2015-2018)

**What It Tried To Do:** Abstract transport API over multiple protocols.

| Feature | Description |
|---------|-------------|
| Transport-agnostic API | Applications specify requirements, not protocols |
| Policy-based protocol selection | System chooses TCP/SCTP/UDP based on policy |
| Happy Eyeballs for transport | Race multiple protocols, use whichever works |
| Connection caching | Reuse established connections across requests |
| Quality monitoring | Built-in path quality measurement |
| Cross-layer optimization | Application hints inform transport selection |

**Why It Stalled:**
- Academic project; limited industry adoption
- TAPS WG at IETF standardized related ideas (RFC 9621-9622)
- Complexity of supporting many transports simultaneously
- Real-world deployment favored QUIC over multi-protocol abstraction

---

## 13. TAPS — Transport Services WG (Partially Succeeded)

**Drafts:** draft-ietf-taps-interface, draft-ietf-taps-arch, etc.

**What It Tried To Do:** Define an abstract transport API for future protocols.

| Feature | Description |
|---------|-------------|
| Abstract transport interface | Applications request properties, not specific protocols |
| Protocol-independent API | Works with TCP, UDP, SCTP, QUIC |
| Connection racing | Try multiple transports in parallel |
| Capability negotiation | Advertise and select protocol features |
| Security integration | Security as a first-class transport property |
| Multipath support | Abstraction supports multipath underneath |

**Status:** Some RFCs published (informational), but the abstract API has seen
minimal real-world adoption. Most applications continue to use socket APIs directly.

---

## 14. MASQUE — Multiplexed Application Substrate over QUIC Encryption

**Drafts:** draft-schinazi-masque-obfuscated-udp, others

**What It Tried To Do:** Tunnel arbitrary protocols inside QUIC.

| Feature | Description |
|---------|-------------|
| UDP tunneling over QUIC | Carry UDP flows inside encrypted QUIC connections |
| TCP proxying over QUIC | Carry TCP flows inside QUIC |
| IP-level proxying | Full IP packet encapsulation |
| Obfuscation | Hide inner protocol from network observers |
| HTTP/3 integration | Uses CONNECT-UDP and CONNECT-IP HTTP methods |

**Status:** Partially standardized (RFC 9297, 9298). Earlier obfuscation-focused
drafts expired. Active development continues.

---

## 15. Multipath DCCP (Expired Draft)

**Draft:** draft-amend-tsvwg-multipath-dccp-05

**What It Tried To Do:** Add MPTCP-style multipath to DCCP.

| Feature | Description |
|---------|-------------|
| Multiple paths for DCCP | Resilience and bandwidth aggregation for datagram flows |
| Path management | Add/remove paths dynamically |
| Shared congestion control | Coupled congestion control across paths |

**Why It Expired:** DCCP itself has minimal deployment; multipath DCCP had even less demand.

---

## 16. UDP-Lite (RFC 3828, Minimal Adoption)

**What It Tried To Do:** Allow partial checksum coverage for loss-tolerant media.

| Feature | Description |
|---------|-------------|
| Partial checksum coverage | Only checksum header + critical payload bytes |
| Corrupt-but-delivered data | Application receives slightly damaged packets |
| Codec-friendly | Audio/video codecs can handle bit errors |

**Why Adoption Stalled:** Most applications preferred full checksums + FEC,
and modern link layers have very low bit error rates.

---

## 17. IL Protocol (Plan 9, ~1990s, Never IETF)

**What It Tried To Do:** Lightweight reliable datagram transport for Plan 9 OS.

| Feature | Description |
|---------|-------------|
| Reliable datagrams | Message-oriented with reliability |
| Lightweight | Minimal protocol overhead |
| Simple state machine | Far fewer states than TCP |
| Integrated with OS | Native Plan 9 transport |

**Why It Failed:** Plan 9-only; no cross-platform support; academic interest only.

---

## 18. PR-SCTP — Partial Reliability for SCTP (draft-stewart-tsvwg-prsctp, Expired)

**What It Tried To Do:** Allow SCTP to intentionally drop stale data.

| Feature | Description |
|---------|-------------|
| Timed reliability | Drop data older than deadline |
| Retransmission-limited reliability | Stop retransmitting after N attempts |
| FORWARD-TSN chunk | Skip over abandoned data in sequence space |
| Application-selectable modes | Each message chooses its reliability policy |

**Status:** Concepts incorporated into RFC 3758 (standardized), but SCTP itself
has limited deployment, so PR-SCTP remains niche.

---

## MASTER FEATURE MATRIX — All Features Attempted by Stalled/Expired Protocols

| Feature Category | Protocols That Attempted It | Achieved by Any Standard? |
|-----------------|----------------------------|--------------------------|
| Always-on encryption | CurveCP, MinimaLT, tcpcrypt | QUIC (RFC 9000) |
| 0-RTT resumption | MinimaLT | QUIC, TLS 1.3 |
| Stateless DoS-resistant handshake | CurveCP, MinimaLT, SCTP | SCTP (cookie), QUIC (retry) |
| Stream multiplexing | SST, Minion, SCTP, MinimaLT | QUIC, HTTP/2 |
| No head-of-line blocking | SST, SCTP | QUIC |
| IP mobility / connection migration | MinimaLT, HIP, CurveCP | QUIC (connection ID) |
| Identifier-locator split | HIP | None widely deployed |
| Cryptographic host identity | HIP | None widely deployed |
| Multi-homing (multiple IPs) | SCTP, HIP, MPTCP | MPTCP (RFC 8684) |
| Multi-path aggregation | MPTCP, Multipath DCCP | MPTCP (RFC 8684) |
| Per-flow QoS reservation | RSVP/IntServ | DiffServ (class-based only) |
| Pluggable congestion control | DCCP | QUIC |
| Message-oriented transport | SCTP, DCCP, XTP, IL, Minion | QUIC (datagrams ext.) |
| Partial reliability | PR-SCTP, DCCP | PR-SCTP (RFC 3758, niche) |
| Reliable multicast | XTP | None widely deployed |
| Protocol-agnostic API | TAPS, NEAT | TAPS (RFC 9621, minimal use) |
| Transport obfuscation | MASQUE | MASQUE (RFC 9297/9298) |
| Opportunistic encryption (no auth) | tcpcrypt | None widely deployed |
| Rate-based flow control | XTP | None widely deployed |
| Forward error correction option | XTP | None in transport layer |
| Partial checksum | UDP-Lite | UDP-Lite (RFC 3828, niche) |

---

## KEY GAPS — Features NO Protocol Has Successfully Deployed

These features were either never attempted or attempted and completely failed.
**POOL should target these:**

1. **Built-in atomic configuration with auto-rollback** — No protocol has this
2. **Change journaling / audit trail at transport level** — No protocol has this
3. **Built-in per-flow telemetry (RTT, jitter, loss, throughput)** — No protocol has this
4. **Self-describing cryptographically-bound addresses** — HIP tried but stalled
5. **Protocol-level automatic MTU discovery with no silent drops** — Partially attempted, never fully solved
6. **Mandatory authentication + encryption (no fallback)** — QUIC comes closest, but still runs over UDP
7. **Vendor-neutral single canonical specification (no implementation-defined behavior)** — Aspirational for all protocols
8. **Integrated backpressure / overload signaling** — ECN exists but is separate from transport
9. **Persistent configuration versioning** — No protocol has this
10. **Cross-platform kernel-level implementation** — Most alternatives are userspace-only

---

**Sources:**
- IETF Datatracker (datatracker.ietf.org)
- Potaroo.net Expired Internet-Drafts Archive
- RFC Editor (rfc-editor.org)
- MIT PDOS (SST paper, SIGCOMM 2007)
- Daniel J. Bernstein (CurveCP specification)
- IETF TSVWG, TCPINC, HIP, TAPS, QUIC, MPTCP Working Groups
- IEEE/Springer academic publications on transport protocol evolution
