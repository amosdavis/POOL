# POOL Security Vulnerability Response Playbook

## Protected Orchestrated Overlay Link — Vulnerability Management

This document defines the procedures for triaging, disclosing, patching, and
communicating security vulnerabilities in the POOL protocol and its implementations.
It also provides crypto-specific incident playbooks and version transition guidance.

**Scope:** POOL kernel module (`pool.ko`), userspace tools (`poolctl`, `poold`,
`pool_test`), bridge (`pool_bridge`, `pool_migrate`), shim (`libpool_shim.so`),
vault (`pool_vault`), and relay (`pool_relay`).

**Crypto suite (v1):** X25519 key exchange, ChaCha20-Poly1305 AEAD,
HMAC-SHA256 packet authentication, HKDF-SHA256 key derivation.

---

## 1. Vulnerability Triage

### 1.1 Severity Classification

Every reported vulnerability is classified into one of four severity levels.
Classification is based on the impact to confidentiality, integrity, and
availability of POOL-protected communications.

| Severity | Criteria | Examples |
|----------|----------|----------|
| **Critical** | Active exploitation possible. Confidentiality or integrity of encrypted sessions is broken without physical or privileged access. Affects all POOL nodes. | ChaCha20-Poly1305 plaintext recovery; X25519 private key extraction from public key; HMAC-SHA256 forgery enabling packet injection; remote code execution in `pool.ko` |
| **High** | Exploitable with non-trivial prerequisites (e.g., local access, MITM position, specific timing). Compromises session security for targeted connections. | Nonce reuse under specific rekey race conditions; session ID prediction enabling session hijack; puzzle bypass enabling denial-of-service; privilege escalation via ioctl interface |
| **Medium** | Degrades security guarantees without fully breaking them. Requires significant resources or unlikely conditions to exploit. | Timing side-channel leaking partial key material; telemetry data disclosure to unauthenticated peers; journal entry forgery; sequence number bias reducing unpredictability |
| **Low** | Minimal security impact. Information disclosure of non-sensitive data, or theoretical weaknesses with no practical exploit. | Version fingerprinting via timing; denial-of-service against a single session (not amplified); cosmetic issues in `/proc/pool/*` output; documentation errors |

### 1.2 Response Timelines

| Severity | Acknowledge | Triage Complete | Patch Developed | Patch Released | Disclosure |
|----------|-------------|-----------------|-----------------|----------------|------------|
| **Critical** | 4 hours | 24 hours | 72 hours | 7 days | 14 days after patch |
| **High** | 24 hours | 72 hours | 14 days | 21 days | 30 days after patch |
| **Medium** | 72 hours | 7 days | 30 days | 45 days | 60 days after patch |
| **Low** | 7 days | 14 days | Next release cycle | Next release cycle | With release notes |

### 1.3 Triage Criteria Specific to POOL

When classifying a vulnerability, evaluate these POOL-specific factors:

1. **Crypto primitive affected:** Vulnerabilities in X25519, ChaCha20-Poly1305, or
   HMAC-SHA256 are presumed Critical until proven otherwise, because POOL has no
   algorithm fallback and all sessions use the same fixed crypto suite.

2. **Kernel vs. userspace:** Kernel module (`pool.ko`) vulnerabilities are elevated
   one severity level compared to equivalent userspace-only issues, due to the
   privileged execution context.

3. **Network-reachable vs. local:** Vulnerabilities exploitable by a remote
   unauthenticated attacker over the network are elevated one severity level compared
   to those requiring local access.

4. **Session scope:** Vulnerabilities affecting all sessions (e.g., a flaw in the
   shared HMAC transform `pool_hmac_tfm`) are more severe than those affecting a
   single session's `pool_crypto_state`.

5. **Rekey interaction:** Vulnerabilities that survive or are worsened by automatic
   rekeying are more severe than those mitigated by key rotation.

---

## 2. Coordinated Disclosure

### 2.1 Reporting Vulnerabilities

POOL is a proprietary protocol. Vulnerability reports shall be submitted through
the following channels, in order of preference:

1. **Encrypted email** to the security team using the project's PGP key
   (key fingerprint and email address to be published on the project website).
2. **Direct secure communication** to a designated security contact via a
   pre-established POOL session (if available).
3. **Private issue** filed in the project's issue tracker with the `security`
   label and restricted visibility.

Reports shall include:
- Affected component(s) and version(s)
- Description of the vulnerability and its impact
- Steps to reproduce or proof-of-concept (if available)
- Suggested severity classification
- Reporter's contact information for follow-up

### 2.2 Responsible Disclosure Timeline

| Phase | Duration | Action |
|-------|----------|--------|
| **Embargo** | Until patch release + 14 days | Vulnerability details restricted to the security team and essential contributors. No public discussion. |
| **Coordinated release** | Patch release day | Patch distributed to all known operators simultaneously. Security advisory published. |
| **Public disclosure** | 14 days after patch release (Critical/High) or with release notes (Medium/Low) | Full technical details published. |

### 2.3 Handling for a Proprietary Project

Because POOL is proprietary and deployment is coordinated:

- The security team maintains a **registry of known deployments** (relay operators,
  bridge sites, vault instances). This registry is used for direct notification.
- **Embargo scope** includes all registered operators. Operators who receive
  early notification must sign a non-disclosure agreement covering the embargo period.
- **Patch distribution** occurs via the existing software distribution channel
  (source code delivery or pre-built kernel module packages).
- If a vulnerability is discovered to be **actively exploited in the wild**, the
  embargo is immediately lifted and an emergency advisory is issued.

---

## 3. Emergency Patching

### 3.1 Kernel Module Hot-Swap Procedure

The POOL kernel module (`pool.ko`) can be replaced without rebooting, but all
active sessions will be terminated during the swap. The procedure is:

```bash
# 1. Verify the new module before starting
modinfo pool_patched.ko
# Confirm: version, vermagic, description match expectations

# 2. Gracefully close all POOL sessions
poolctl close-all
# Wait for CLOSE packets to be acknowledged (check /proc/pool/sessions)

# 3. Stop userspace daemons
systemctl stop poold pool_relay pool_bridge

# 4. Unload the current module
rmmod pool

# 5. Load the patched module
insmod pool_patched.ko
# Verify: dmesg | tail -20 — confirm "POOL: crypto subsystem initialized"

# 6. Verify crypto subsystem health
cat /proc/pool/status
# Confirm: module loaded, crypto algorithms available

# 7. Restart userspace daemons
systemctl start poold pool_relay pool_bridge

# 8. Re-establish sessions
poolctl listen 9253
# Sessions will be re-established automatically by peers
```

### 3.2 Peer Coordination for Network-Wide Upgrades

Because POOL v1 has no cipher negotiation, all peers in a POOL network must run
compatible versions. A network-wide patch requires coordinated rollout:

**Rolling upgrade strategy:**

1. **Announce maintenance window** to all registered operators via the
   communication channels defined in §4.
2. **Distribute the patched module** to all operators during the embargo period.
3. **Coordinate simultaneous upgrade** using one of two approaches:

   **Approach A — Simultaneous swap (small networks, < 50 nodes):**
   - All operators swap at the agreed time.
   - Sessions are down for the duration of the swap (typically < 60 seconds).
   - Bridge endpoints provide TCP fallback during the outage.

   **Approach B — Bridge-assisted rolling upgrade (large networks):**
   - Deploy `pool_bridge` instances between upgraded and non-upgraded segments.
   - Upgrade nodes in batches. Upgraded nodes reconnect via POOL; non-upgraded
     nodes communicate through the bridge's TCP side.
   - After all nodes are upgraded, remove the temporary bridges.
   - This approach only works for patches that do not change the wire protocol.
     If the patch changes the protocol version (e.g., v1 → v2), see §7.

4. **Verify** by checking `/proc/pool/sessions` on each node and confirming
   active sessions with correct peer counts.

### 3.3 Rollback Procedure

If the patched module causes regressions:

```bash
# 1. Stop daemons
systemctl stop poold pool_relay pool_bridge

# 2. Unload patched module
rmmod pool

# 3. Reload previous module
insmod pool_previous.ko

# 4. Restart daemons and verify
systemctl start poold pool_relay pool_bridge
cat /proc/pool/status
```

Retain the previous module binary (`pool_previous.ko`) alongside every patch
deployment. The POOL change journal (`/proc/pool/journal`) records all module
load/unload events for audit purposes.

### 3.4 Testing Requirements Before Deployment

Every security patch must pass the following before release:

1. **Unit verification:** The specific vulnerability is confirmed fixed
   (regression test for the reported issue).
2. **Crypto self-test:** Encrypt/decrypt round-trip with known test vectors
   for ChaCha20-Poly1305, HMAC-SHA256, and HKDF-SHA256.
3. **Handshake test:** Full INIT → CHALLENGE → RESPONSE → ACK handshake
   between two instances of the patched module.
4. **Data transfer test:** 500 MB encrypted transfer (using `pool_test bench`)
   with integrity verification.
5. **Rekey test:** Trigger manual rekey and verify session continuity.
6. **Interoperability test (same-version):** Patched module communicates with
   another patched module.
7. **Bridge/shim/vault smoke test:** Verify `pool_bridge`, `libpool_shim.so`,
   and `pool_vault` function correctly with the patched module.

---

## 4. Communication

### 4.1 Notification Tiers

Operators and users are notified based on the severity of the vulnerability and
their deployment type:

| Tier | Audience | Notification Method | Timing |
|------|----------|---------------------|--------|
| **Tier 1** | Relay operators (`pool_relay`) | Direct encrypted communication (POOL session or PGP email) | During embargo — receive patch before public release |
| **Tier 2** | Bridge operators (`pool_bridge`) | Encrypted email with patch and advisory | On patch release day |
| **Tier 3** | Shim users (`libpool_shim.so`) | Encrypted email with advisory and upgrade instructions | On patch release day |
| **Tier 4** | Vault users (`pool_vault`) | Advisory via software update channel | On patch release day |
| **Tier 5** | General public | Public security advisory | After disclosure period |

Relay operators receive earliest notification because they carry traffic for
other nodes and a compromised relay has the widest blast radius.

### 4.2 Security Advisory Format

Every security advisory shall include:

```
POOL Security Advisory — POOL-SA-YYYY-NNN

Severity:       Critical | High | Medium | Low
Affected:       pool.ko versions X.Y through X.Z
                [component names if not pool.ko]
CVE:            CVE-YYYY-NNNNN (if assigned)
Fixed in:       pool.ko version X.Z+1

Summary:        [One-paragraph description of the vulnerability]

Impact:         [What an attacker can achieve, prerequisites, blast radius]

Mitigation:     [Interim steps before patching, if any]

Resolution:     [Upgrade instructions]

Timeline:       [Dates of report, triage, patch, disclosure]

Credit:         [Reporter attribution, if agreed]
```

### 4.3 Severity-Appropriate Notification Channels

| Severity | Channels |
|----------|----------|
| **Critical** | All tiers notified simultaneously. Phone/SMS for Tier 1 operators. Emergency advisory published. |
| **High** | All tiers notified per schedule in §4.1. Email advisory. |
| **Medium** | Tiers 1–4 notified on patch release. Public advisory with release notes. |
| **Low** | Included in release notes. No separate notification. |

---

## 5. Crypto-Specific Incident Playbooks

POOL v1 uses a fixed crypto suite with no algorithm negotiation. If any primitive
is broken, the response depends on which primitive is affected and the severity
of the break.

### 5.1 X25519 (Curve25519 Key Exchange) Broken

**Impact:** An attacker who can solve the Elliptic Curve Discrete Logarithm Problem
(ECDLP) on Curve25519 can derive session keys from the public keys exchanged during
the INIT/CHALLENGE handshake. All sessions — past (if recorded), present, and
future — are compromised.

**Immediate actions (within 24 hours):**

1. **Terminate all POOL sessions** network-wide. Issue `poolctl close-all` on
   every node.
2. **Disable POOL listener** (`poolctl stop`) on all nodes. No new sessions.
3. **Activate TCP fallback** via `pool_bridge` for essential traffic. Bridge
   endpoints provide unencrypted (or TLS-wrapped) TCP transport.
4. **Assess scope:** Determine if the break is theoretical, requires quantum
   computing, or is practically exploitable today.

**Interim mitigations (if partial break, not full ECDLP solve):**

- **Reduce session lifetime** by lowering `POOL_REKEY_SEC` (e.g., from 3600 to 60
  seconds) to limit the window of exposure per key.
- **Increase puzzle difficulty** (`POOL_PUZZLE_DIFFICULTY`) to raise the cost of
  initiating new sessions.
- **Layer with TLS:** Run POOL sessions inside a TLS tunnel (`pool_bridge tcp2pool`
  with TLS on the TCP side) to add a second layer of key exchange (ECDHE on a
  different curve or RSA).

**Long-term resolution:**

- Develop POOL v2 with a post-quantum key exchange (e.g., ML-KEM/Kyber as
  standardized in FIPS 203, or X25519+ML-KEM hybrid). See §7 for version
  transition guidance.

### 5.2 ChaCha20-Poly1305 (Symmetric Encryption) Broken

**Impact:** An attacker who can break ChaCha20-Poly1305 can decrypt all POOL
payload data in transit. If Poly1305 authentication is also broken, the attacker
can inject or modify payloads without detection (though HMAC-SHA256 on the packet
header still provides header integrity).

**Immediate actions (within 24 hours):**

1. **Assess whether Poly1305 (authentication) or ChaCha20 (confidentiality)
   is broken**, or both.
   - **Poly1305 only:** Payload integrity is lost, but HMAC-SHA256 still
     authenticates headers. Confidentiality is intact.
   - **ChaCha20 only:** Confidentiality is lost, but integrity is intact
     (Poly1305 + HMAC-SHA256 both still hold).
   - **Both:** Full loss of payload confidentiality and integrity.
2. **For confidentiality loss:** Immediately classify all POOL-transported data
   as potentially exposed. Cease transmitting sensitive data over POOL sessions.
3. **For integrity loss:** Terminate sessions. Activate TCP fallback.

**Interim mitigations:**

- **Application-layer encryption:** If ChaCha20 is broken but Poly1305 and
  HMAC-SHA256 are intact, applications can layer their own encryption (e.g.,
  AES-256-GCM) on top of POOL's transport. POOL still provides authentication
  and anti-replay.
- **Reduce `POOL_REKEY_PACKETS`** from 2^28 to a lower value (e.g., 2^16)
  to limit data encrypted under any single key.

**Long-term resolution:**

- Develop POOL v2 with an alternative AEAD cipher (e.g., AES-256-GCM, which
  uses a different underlying construction and is widely supported by the
  Linux kernel crypto API via `gcm(aes)`).

### 5.3 HMAC-SHA256 (Packet Authentication) Broken

**Impact:** An attacker who can forge HMAC-SHA256 can inject, modify, or replay
POOL packets including headers. This breaks session integrity, enables sequence
number manipulation, and permits RST injection — the exact attacks POOL was
designed to prevent.

**Immediate actions (within 24 hours):**

1. **Assess the nature of the break:** Is it a full forgery (arbitrary HMAC
   computation without the key) or a collision/length-extension attack?
   - **Full forgery:** Critical. All POOL guarantees are void.
   - **Collision attack:** Evaluate whether it enables practical exploitation
     given POOL's use of HMAC (which is resistant to length-extension and
     most collision attacks on the underlying hash).
2. **If full forgery:** Terminate all sessions. Activate TCP fallback.
3. **If collision only:** Evaluate practical impact. HMAC construction may
   remain secure even if SHA-256 collision resistance is weakened (as was the
   case with HMAC-MD5 and HMAC-SHA1 after collision attacks on MD5/SHA-1).

**Interim mitigations:**

- **Double HMAC:** If the break is partial, apply a second HMAC pass using a
  different key derivation label. This requires a coordinated module update.
- **Reduce session lifetime** to limit the window for forgery attempts.

**Long-term resolution:**

- Develop POOL v2 with HMAC-SHA3-256 or KMAC-256 (SHA-3 based), or

---

## 8. Cipher Agility Roadmap (P12)

POOL v1 uses a fixed cipher suite (ChaCha20-Poly1305 + X25519 + HMAC-SHA256)
with **no algorithm negotiation** (see §6.1).  If any primitive is broken, the
entire protocol version must be replaced — not patched with a fallback cipher.

This section records *possible future directions* for v2+.  Nothing here
applies to v1 nodes; v1 MUST NOT implement cipher negotiation, cipher suite
fields, or runtime algorithm selection.

### 8.1 Cipher Suite Identifiers (v2+ only — not implemented in v1)

Each future protocol version would still ship a **single fixed cipher suite**.
The identifiers below are for documentation and bridge interoperability, not
for runtime negotiation between endpoints.

| ID | AEAD | Key Exchange | MAC | Protocol Version |
|----|------|-------------|-----|------------------|
| 0x01 | ChaCha20-Poly1305 | X25519 | HMAC-SHA256 | v1 (current, fixed) |
| 0x02 | ChaCha20-Poly1305 | X25519 + ML-KEM-768 | HMAC-SHA256 | v2 (hybrid PQ) |

Additional identifiers (e.g., AES-256-GCM variants) would only be assigned
when a concrete protocol version requires them.

### 8.2 Version Compatibility (replaces "Negotiation Rules")

POOL nodes do **not** negotiate cipher suites.  Each node advertises its
protocol version in the INIT packet header (4-bit version field, §2 of
`spec/PROTOCOL.md`).  Compatibility rules:

1. A node MUST refuse a handshake from a peer whose protocol version differs
   from its own.
2. Cross-version communication is handled by `pool_bridge` (§6.2), which
   terminates one version on each side and re-encrypts between them.
3. There is no "downgrade" or "upgrade" at the endpoint level.

### 8.3 Emergency Response to a Primitive Break

If a critical break is discovered in a v1 primitive (e.g., ChaCha20-Poly1305):

1. Issue a new protocol version (v2) that uses the replacement primitive.
2. Deploy `pool_bridge` instances to mediate v1 ↔ v2 traffic during the
   transition (§6.2).
3. Migrate all nodes to v2.
4. Deprecate and remove v1 per the timeline in §6.3.

This approach preserves the fixed-cipher-suite design while allowing the
network to survive a primitive break.
  HMAC-BLAKE2b (if performance is a concern). The HKDF derivation function
  would also need to be updated from HKDF-SHA256 to HKDF with the
  replacement hash.

### 5.4 Multiple Primitives Compromised Simultaneously

**Impact:** If advances in cryptanalysis (e.g., practical quantum computing)
break both the key exchange and symmetric primitives, POOL provides no
residual security.

**Immediate actions:**

1. **Full network shutdown** of all POOL sessions.
2. **Revert to TCP** via `pool_bridge` for all traffic. Accept the loss of
   POOL's security guarantees as a temporary measure.
3. **Audit all data** that traversed POOL sessions during the exposure window.
   Assume all recorded ciphertext is decryptable.

**Long-term resolution:**

- POOL v2 must be designed with a fully post-quantum crypto suite:
  - **Key exchange:** ML-KEM (FIPS 203) or hybrid X25519+ML-KEM
  - **AEAD:** AES-256-GCM (quantum-resistant at 256-bit key length under
    Grover's algorithm, providing 128-bit post-quantum security)
  - **HMAC:** HMAC-SHA3-256 or KMAC-256
- The 4-bit version field supports up to 15 protocol versions, providing
  room for this transition.

### 5.5 HKDF-SHA256 (Key Derivation) Broken

**Impact:** If HKDF-SHA256 is broken (via a break in the underlying HMAC-SHA256
or the HKDF construction itself), all derived keys are compromised. This includes
session keys, HMAC keys, and sequence keys — even if the raw shared secret from
X25519 is secure, the derived material is not.

**Immediate actions:**

1. Follow the HMAC-SHA256 playbook (§5.3) since HKDF-SHA256 depends on
   HMAC-SHA256 internally.
2. Assess whether the break is in HMAC-SHA256 or in the HKDF extract/expand
   construction specifically.

**Long-term resolution:**

- Replace HKDF-SHA256 with HKDF-SHA3-256 or an alternative KDF such as
  NIST SP 800-108r1 KBKDF with a secure underlying PRF.

---

## 6. Version Transition Guidance

### 6.1 Design Philosophy

POOL v1 intentionally uses a fixed crypto suite with no algorithm negotiation.
This design decision was made after studying 18 failed transport protocols
(documented in `spec/STALLED_PROTOCOLS.md`), many of which were hindered by
negotiation complexity, incompatible implementations, and deployment friction.

**This playbook does not recommend adding cipher suite negotiation to v1.**

Instead, crypto evolution is handled through protocol versioning: the 4-bit
version field in the packet header (§2 of `spec/PROTOCOL.md`) allows up to
15 distinct protocol versions, each with its own fixed crypto suite.

### 6.2 How a Protocol v2 Would Be Rolled Out

A new protocol version (e.g., v2 with post-quantum crypto) would be deployed
using the same three-phase migration strategy documented in `spec/MIGRATION.md`,
applied to the v1 → v2 transition:

**Phase 1 — Bridge coexistence:**

```
v1 Node ──POOL v1──> [pool_bridge v1↔v2] ──POOL v2──> v2 Node
```

- `pool_bridge` is extended to understand both v1 and v2 wire formats.
- The bridge terminates a v1 session on one side and initiates a v2 session
  on the other, re-encrypting traffic between them.
- No changes to v1 nodes. v2 nodes are deployed alongside v1.
- **Security note:** During bridge coexistence, traffic transits the bridge
  in plaintext momentarily (between decrypt-v1 and encrypt-v2). The bridge
  must be a trusted, hardened node.

**Phase 2 — Dual-stack nodes:**

- Updated `pool.ko` supports both v1 and v2 handshakes.
- The version field in the INIT packet determines which crypto suite is used.
- Nodes prefer v2 but accept v1 connections from legacy peers.
- `pool_bridge` is no longer needed between dual-stack nodes.

**Phase 3 — v1 deprecation:**

- After a defined transition period, nodes reject v1 connections.
- `pool_bridge` instances for v1 are decommissioned.
- The v1 crypto suite is removed from the module to eliminate attack surface.

### 6.3 Deprecation Timeline for v1

| Milestone | Action |
|-----------|--------|
| v2 release | v2 available. v1 still default. Bridge coexistence begins. |
| v2 release + 6 months | v2 becomes default for new sessions. v1 accepted but deprecated. Warning logged for v1 connections. |
| v2 release + 12 months | v1 acceptance disabled by default. Operators can re-enable via module parameter for legacy compatibility. |
| v2 release + 18 months | v1 support removed from codebase. |

### 6.4 What Stays the Same Across Versions

The following POOL features are version-independent and do not change during
a crypto transition:

- Packet header layout (the version field itself determines interpretation)
- ioctl API for userspace tools
- `/proc/pool/*` interface
- Change journal format and SHA256-chained audit trail
- Telemetry structure and heartbeat semantics
- Bridge, shim, vault, and relay tool interfaces

### 6.5 Reserved Resources for Future Versions

| Resource | Capacity | Current Use | Available |
|----------|----------|-------------|-----------|
| Version field (4 bits) | 16 values (0–15) | v1 (value 1) | 14 values (0, 2–15) |
| Packet type 0xF | 1 type | RESERVED | 1 type |
| Flag bits 10–15 | 6 bits | Must be zero | 6 bits |
| `reserved0` header byte | 8 bits | Must be zero | 8 bits |
| `reserved1` header byte | 8 bits | Must be zero | 8 bits |

These reserved fields provide extension points for future versions without
changing the header size (80 bytes).

---

## 7. References

- `spec/PROTOCOL.md` — Complete POOL v1 protocol specification
- `spec/MIGRATION.md` — Three-phase TCP → POOL migration strategy
- `spec/OPERATORS.md` — Relay operator incentive structure
- `spec/STALLED_PROTOCOLS.md` — Analysis of 18 failed transport protocols
- `linux/pool_crypto.c` — Cryptography implementation
- `linux/pool.h` — Protocol constants and data structures
