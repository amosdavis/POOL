# POOL Runtime Integrity Failure Tenets

## Protected Orchestrated Overlay Link — Runtime Binary Modification Threat Model

**Scope:** All POOL components — kernel module (`pool.ko`), userspace tools
(`poolctl`, `poold`, `pool_test`), bridge (`pool_bridge`, `pool_migrate`),
shim (`libpool_shim.so`), vault (`pool_vault`), relay (`pool_relay`),
platform implementations (Windows, macOS/BSD), and the hardware they execute on.

**Classification:** Design-level threat model. This document defines binding
failure tenets that all future POOL development must satisfy.

---

## 1. Threat Model

### 1.1 Scenario

Technology has progressed to enable immediate modification of running binaries
on live systems. Compiled code no longer needs recompilation to change behavior.
Hardware itself can have "overlay" circuitry where bit flow is intercepted and
redirected, making binaries behave as if they were modified — even when the
on-disk binary remains unchanged.

This threat model encompasses:

- **Live binary patching:** Modification of executable code pages in memory
  after a process or kernel module is loaded.
- **Hardware overlay circuitry:** Physical or firmware-level interception of
  instruction fetch, data read/write, or bus signals, substituting different
  bit patterns at the circuit level.
- **Microcode/firmware modification:** Alteration of CPU microcode, NIC firmware,
  or other subsystem firmware to change computation semantics.
- **Memory bus interception:** Man-in-the-middle attacks on the memory bus,
  PCIe bus, or other interconnects to modify data in transit between CPU
  and memory.

### 1.2 Fundamental Assumption Violated

Modern computing assumes a static boundary between "the code" and "the
execution." POOL's entire security model depends on this assumption:

| POOL Guarantee | Assumption Required | Broken By |
|---------------|---------------------|-----------|
| Mandatory mutual authentication | X25519 ECDH executes correctly | Overlay on crypto path |
| Always-on encryption | ChaCha20-Poly1305 encrypts faithfully | Key/nonce exfiltration via overlay |
| HMAC on every packet | HMAC-SHA256 is computed and verified honestly | Verification overlaid to always pass |
| Cryptographic sequence numbers | HKDF derives unpredictable values | HKDF output replaced with known values |
| Crypto self-tests at load | Self-tests validate primitive correctness | Self-test results falsified |
| SHA256-chained audit journal | Journal entries are immutable once written | Journal chain forged |

### 1.3 Attacker Model

The attacker can:

1. Modify any binary in memory after it has been loaded and after any
   integrity checks have passed.
2. Intercept and modify hardware signals at the circuit level, including
   between CPU and memory, between CPU and network interface, and within
   the CPU execution pipeline.
3. Selectively target specific functions or code paths — the modification
   need not affect the entire binary.
4. Operate persistently — modifications survive across function calls and
   can be applied conditionally (e.g., only when a specific function is called).
5. Evade detection by modifying the detection mechanisms themselves (the
   "quis custodiet" problem).

The attacker cannot:

1. Violate the laws of physics (e.g., cannot intercept photons without
   detection in a quantum channel).
2. Compromise a physically air-gapped, tamper-evident verification coprocessor
   without physical access (Tenet T3).
3. Simultaneously compromise all N independent systems performing replicated
   execution, if they use different architectures and are in different
   physical locations (Tenet T4).
4. Forge a valid zero-knowledge proof of correct execution without actually
   performing the correct execution (Tenet T5).

---

## 2. POOL-Specific Failure Modes

### 2.1 Crypto Path Tampering

**RT-C01: Kernel module binary modification after insmod**

- **Component:** `pool_crypto.c`, `pool_main.c`
- **Attack:** Modify `pool.ko` code pages in kernel memory after `insmod`
  completes and crypto self-tests pass.
- **Impact:** All crypto guarantees void. Self-tests passed at load time but
  the code that runs afterward is different.
- **Existing mitigation (partial):** `pool_crypto_selftest_hmac()` and
  `pool_crypto_selftest_aead()` run at `pool_crypto_init()` during module
  load (pool_main.c:283). Module refuses to load if tests fail.
- **Gap:** Self-tests run once. No re-verification during operation.

**RT-C02: HMAC verification overlaid to always return success**

- **Component:** `pool_crypto.c` (`pool_crypto_hmac_verify()`), `pool_net.c`
- **Attack:** Overlay the `crypto_memneq()` call at pool_crypto.c:640 to
  always return 0 (match), or overlay the branch that checks the return value.
- **Impact:** Packet injection, session hijacking, and replay attacks become
  trivial — the exact attacks POOL was designed to prevent.
- **Existing mitigation (partial):** Uses `crypto_memneq()` for constant-time
  comparison (timing attack resistant). Anti-replay window (64 packets) in
  pool_net.c:273-289.
- **Gap:** Constant-time comparison protects against timing attacks but not
  against overlaying the comparison result itself.

**RT-C03: X25519 private key extraction during ECDH**

- **Component:** `pool_crypto.c` (`pool_crypto_gen_keypair()`,
  `pool_crypto_ecdh()`)
- **Attack:** Overlay on the ECDH computation path to copy the private key
  to an attacker-accessible memory location, or exfiltrate via a covert channel.
- **Impact:** All sessions using the compromised keypair are decryptable —
  past (if recorded), present, and future — because X25519 does not provide
  forward secrecy within a single keypair's lifetime.
- **Existing mitigation (partial):** Keypair regenerated per-node at module
  init (pool_main.c:288). Automatic rekeying after configurable packet count.
- **Gap:** No protection against key exfiltration during computation.

**RT-C04: ChaCha20-Poly1305 key/nonce exfiltration**

- **Component:** `pool_crypto.c` (`pool_crypto_encrypt()`,
  `pool_crypto_decrypt()`)
- **Attack:** Overlay on the encrypt/decrypt path to leak the session key or
  nonce to an attacker via a side channel (e.g., encoding in packet timing,
  unused header bits, or a covert memory location).
- **Impact:** Confidentiality loss for all data encrypted under the leaked key.
  If the nonce is also leaked, decryption of captured ciphertext is trivial.
- **Existing mitigation (partial):** Entropy-rich nonce construction (first 4
  bytes from hmac_key, next 8 from sequence number — pool_net.c:509-510).
  Automatic rekeying limits exposure window.
- **Gap:** Rekeying helps bound exposure but does not prevent exfiltration.

**RT-C05: HKDF output replacement with attacker-known values**

- **Component:** `pool_crypto.c` (`pool_crypto_hkdf()`)
- **Attack:** Overlay the HKDF function to return attacker-chosen key material
  instead of properly derived keys.
- **Impact:** All derived keys (session encryption key, HMAC key, sequence key)
  are known to the attacker. Encryption and authentication are both compromised.
- **Existing mitigation:** None. HKDF output is trusted without independent
  verification.
- **Gap:** No cross-verification of derived key material.

**RT-C06: Random number generator compromise**

- **Component:** Kernel CSPRNG (`get_random_bytes()`), used in key generation,
  puzzle nonces, and session IDs.
- **Attack:** Overlay the kernel's CSPRNG to produce predictable output.
- **Impact:** Key generation predictable (keys reconstructable by attacker),
  session IDs guessable (session hijacking), puzzle nonces predictable
  (DoS protection defeated).
- **Existing mitigation:** None beyond kernel's own CSPRNG integrity.
- **Gap:** POOL trusts the kernel CSPRNG unconditionally.

### 2.2 Session & State Tampering

**RT-S01: Session struct modification in kernel memory**

- **Component:** `pool_session.c` (`struct pool_session`)
- **Attack:** Directly modify the `pool_session` struct in kernel memory to
  change session_id, keys, peer address, or state.
- **Impact:** Session hijacking (change peer address), key substitution (replace
  keys with known values), state machine bypass (force state to ESTABLISHED).
- **Existing mitigation (partial):** Session access serialized by `sessions_lock`
  mutex. State machine in `pool_state.h` validates transitions.
- **Gap:** Mutex protects against concurrent kernel access but not against
  direct memory modification.

**RT-S02: Sequence number generation overlay**

- **Component:** `pool_session.c`, `pool_crypto.c`
- **Attack:** Overlay the sequence number increment or HKDF-derived sequence
  generation to produce predictable or repeated values.
- **Impact:** Replay attacks become possible. Anti-replay window ineffective
  if sequences are predictable. Nonce reuse if sequence feeds into nonce
  construction.
- **Existing mitigation (partial):** Cryptographic sequence numbers derived
  from HKDF. Anti-replay window (64 packets) validates sequence ordering.
- **Gap:** Anti-replay window trusts that the local sequence counter is honest.

**RT-S03: Rekey mechanism suppression**

- **Component:** `pool_session.c`, `pool_crypto.c`
- **Attack:** Overlay the rekey threshold check to never trigger, or overlay
  the rekey packet handler to silently discard rekey requests.
- **Impact:** Session keys never rotate. If a key is compromised via any other
  means, the exposure window extends indefinitely instead of being bounded by
  the rekey interval.
- **Existing mitigation (partial):** Rekey triggers logged via rate-limited
  `pr_info` message. Telemetry tracks packets_since_rekey.
- **Gap:** Logging can also be overlaid. No independent verification that
  rekeying actually occurred.

**RT-S04: Puzzle difficulty check bypass**

- **Component:** `pool_session.c` (handshake proof-of-work verification)
- **Attack:** Overlay the puzzle difficulty verification to always accept,
  regardless of the solution provided.
- **Impact:** Proof-of-work DoS protection defeated. Attackers can flood a
  POOL node with connection attempts at zero computational cost (SYN flood
  equivalent).
- **Existing mitigation (partial):** Minimum puzzle difficulty of 16 bits
  (spec §13.8). Puzzle solution verified via HMAC.
- **Gap:** Verification code itself can be bypassed via overlay.

**RT-S05: State machine transition override**

- **Component:** `pool_session.c`, `pool_state.h` (`pool_state_transition()`)
- **Attack:** Overlay `pool_state_transition()` or `pool_state_valid_packet()`
  to permit any transition, allowing the session to jump from IDLE directly
  to ESTABLISHED without completing the handshake.
- **Impact:** Authentication bypass. Sessions established without mutual
  authentication, without key exchange, without puzzle proof-of-work.
- **Existing mitigation (partial):** Valid packet matrix in pool_state.h
  (lines 16-45). Explicit state checks at each handshake stage.
- **Gap:** All checks are in software and can be overlaid.

### 2.3 Observability & Audit Tampering

**RT-A01: /proc/pool/* output falsification**

- **Component:** `pool_sysinfo.c`
- **Attack:** Overlay the procfs read handlers to report fabricated status,
  session counts, telemetry values, and journal entries.
- **Impact:** Operators see a healthy system while the module is compromised.
  Monitoring and alerting (e.g., Prometheus exporter reading /proc/pool/*)
  receive false data.
- **Existing mitigation:** None. Procfs output is trusted without independent
  verification.
- **Gap:** No out-of-band verification channel.

**RT-A02: Journal SHA256 chain forgery**

- **Component:** `pool_journal.c` (`pool_journal_add()`)
- **Attack:** Modify journal entries in the circular buffer, or overlay the
  SHA256 hash computation to produce hashes consistent with falsified data.
- **Impact:** Audit trail rewritten. Malicious state transitions hidden.
  Post-incident forensics based on the journal are unreliable.
- **Existing mitigation (partial):** Each journal entry hashed with SHA256
  (pool_journal.c:58-71). Circular buffer with version tracking.
- **Gap:** Journal entries are hashed individually but NOT chained — each
  hash covers only its own entry, not the prior chain. An attacker can
  replace any single entry and recompute its hash independently.

**RT-A03: Crypto self-test result falsification**

- **Component:** `pool_crypto.c` (`pool_crypto_selftest_hmac()`,
  `pool_crypto_selftest_aead()`)
- **Attack:** Overlay the self-test functions to always return 0 (success),
  or overlay the branch in `pool_crypto_init()` that checks the return value.
- **Impact:** Module loads even when crypto primitives are broken or overlaid.
  The self-test mechanism — POOL's first line of defense — is neutralized.
- **Existing mitigation:** Self-tests return `-EACCES` on failure, preventing
  module load. Module init checks at pool_main.c:283-285.
- **Gap:** Self-tests are a single point of failure. If overlaid, no backup
  verification exists.

**RT-A04: Telemetry data manipulation**

- **Component:** `pool_telemetry.c`
- **Attack:** Overlay telemetry recording functions to report false RTT,
  jitter, throughput, and loss rate values.
- **Impact:** Anomaly detection systems (including the Prometheus exporter)
  are blinded. A degraded or compromised link appears healthy. Loss-based
  triggers (e.g., automatic failover) never fire.
- **Existing mitigation:** Heartbeat packets carry timestamps verified by
  both peers.
- **Gap:** If both peers' telemetry code is overlaid consistently, the
  falsification is undetectable from within the POOL network.

### 2.4 Userspace & Adoption Tool Tampering

**RT-U01: poolctl/poold binary replacement or overlay**

- **Component:** `poolctl.c`, `poold.c`
- **Attack:** Modify poolctl or poold binaries (on disk or in memory) to issue
  malicious ioctls to the kernel module — e.g., close all sessions, change
  configuration, or exfiltrate session keys via the char device interface.
- **Impact:** Full control over the POOL module from userspace. Attacker can
  terminate sessions, modify config, or extract sensitive data.
- **Existing mitigation (partial):** ioctl requires `/dev/pool` access
  (restricted by file permissions). Module reference counting prevents
  ioctl during unload.
- **Gap:** If the binary is modified, file permissions don't help — the
  modified binary already has the necessary access.

**RT-U02: Bridge plaintext interception during re-encryption**

- **Component:** `pool_bridge.c`
- **Attack:** During v1↔v2 protocol bridging, traffic is decrypted from one
  version and re-encrypted for the other. An overlay on the bridge process
  captures the plaintext in the gap between decrypt and re-encrypt.
- **Impact:** Complete confidentiality loss for all traffic traversing the
  bridge, even though both endpoints are using full POOL encryption.
- **Existing mitigation (partial):** SECURITY.md §6.2 notes that "the bridge
  must be a trusted, hardened node."
- **Gap:** "Trusted and hardened" is aspirational, not enforceable, under
  this threat model.

**RT-U03: Shim library interception**

- **Component:** `pool_shim.c` (`libpool_shim.so`)
- **Attack:** Modify the LD_PRELOAD shim to redirect application traffic
  (e.g., route curl or nginx traffic to an attacker-controlled destination
  instead of the intended POOL peer).
- **Impact:** Application traffic silently redirected. Users believe they
  are communicating over POOL when traffic is actually routed elsewhere.
- **Existing mitigation:** None beyond standard file integrity.
- **Gap:** LD_PRELOAD is inherently a modification of running behavior.

**RT-U04: Vault path validation bypass**

- **Component:** `pool_vault.c`
- **Attack:** Overlay the path traversal check in the vault server to always
  pass, allowing `../../etc/passwd` or similar path traversal.
- **Impact:** Arbitrary file access on the vault server filesystem.
- **Existing mitigation (partial):** Path traversal rejection implemented
  (existing BDD scenario U01 verifies this). Path length validation (U02).
- **Gap:** The validation code itself can be bypassed by overlay.

**RT-U05: Relay generosity score manipulation**

- **Component:** `pool_relay.c`
- **Attack:** Overlay the generosity score calculation to inflate the local
  node's score or deflate peer scores, gaining unfair routing priority.
- **Impact:** Free-riding on the relay network. The bandwidth reciprocity
  incentive model collapses.
- **Existing mitigation (partial):** Generosity scores are computed locally
  from observed bandwidth counters.
- **Gap:** Both the counters and the computation can be overlaid.

---

## 3. Design Tenets

These eight tenets are binding constraints on all future POOL design and
implementation. No code change shall be accepted if it violates a tenet or
creates a new path for one of the failure modes documented in §2.

### Tenet T1: Continuous Runtime Attestation

> Code integrity must be verified continuously during execution,
> not only at load time.

**Rationale:** RT-C01 and RT-A03 exploit the gap between load-time self-tests
and runtime execution. A one-time check is necessary but insufficient.

**Implementation requirements:**

1. **Periodic `.text` section checksumming:** At module init, compute a CRC32
   or SHA256 hash of the module's `.text` (code) section and store it.
   Periodically (e.g., every 60 seconds in the heartbeat thread) re-hash the
   `.text` section and compare. If the hash differs, log a critical alert and
   refuse to process new packets.
2. **Self-test re-execution:** Periodically re-run `pool_crypto_selftest_hmac()`
   and `pool_crypto_selftest_aead()` with different test vectors each time
   (selected from a table of known-answer tests). A single test vector is
   easier to spoof via overlay than a rotating set.
3. **External attestation hook:** Expose a `/proc/pool/attestation` interface
   that an external attestation agent (e.g., TPM-based) can query to verify
   module integrity.

**Addresses:** RT-C01, RT-A03

### Tenet T2: Behavioral Verification Over Binary Verification

> Verify what code *does*, not what code *is*. Monitor outputs and
> side effects against known-good behavioral models.

**Rationale:** If the binary can change at any time, verifying the binary's
identity is unreliable. Verifying its *behavior* — that the right outputs are
produced for given inputs — is more robust.

**Implementation requirements:**

1. **Crypto output spot-checks:** Periodically encrypt a known plaintext with
   a known key and verify the ciphertext matches expected output. This tests
   the *runtime behavior* of the crypto path, not just the binary's identity.
2. **HMAC cross-verification:** After computing an HMAC, recompute it via an
   independent code path (e.g., a second HMAC implementation or a software
   fallback) and compare results. If they differ, the primary path is
   compromised.
3. **Sequence number monotonicity assertion:** Independently track sequence
   numbers in a secondary counter and assert that the primary and secondary
   counters agree. Divergence indicates overlay on the primary counter.
4. **Peer-side behavioral verification:** The remote peer can periodically
   send a "challenge" packet containing a known plaintext. The local node
   must return the correct encrypted form. The peer verifies the result.
   This detects crypto path compromise that is invisible locally.

**Addresses:** RT-C02, RT-C04, RT-C05, RT-S02

### Tenet T3: Hardware Root of Trust

> Verification mechanisms must exist in a physically separate domain
> that is immune to software or circuit overlay.

**Rationale:** Any verification mechanism co-located with the system under
test can be overlaid by the same attacker. The verifier must be in a separate
physical domain.

**Implementation requirements:**

1. **TPM-based module attestation:** On platforms with a TPM, extend a PCR
   with the hash of `pool.ko` at load time. External verifiers can request
   a TPM quote to confirm module integrity.
2. **Secure enclave integration (future):** On platforms with SGX, TrustZone,
   or equivalent, execute critical crypto operations inside the enclave where
   overlay is infeasible.
3. **Out-of-band attestation channel:** Provide a mechanism for a physically
   separate device (e.g., a hardware security module or a dedicated
   verification appliance) to independently query and verify POOL's state
   via a channel that does not traverse the overlaid system.

**Addresses:** RT-C01, RT-C03, RT-C06, RT-A01, RT-A03

**Note:** T3 describes architectural requirements that cannot be fully
implemented in software alone. POOL's software implementation should provide
the *hooks* (attestation interfaces, enclave-compatible code paths) even if
the hardware is not yet available.

### Tenet T4: Replicated Execution with Consensus

> Critical computations must be performed on N independent systems
> and require consensus on the output.

**Rationale:** An attacker who can overlay one system cannot simultaneously
overlay N independent systems (especially if they use different architectures,
different hardware vendors, and are in different physical locations).

**Implementation requirements:**

1. **Cross-peer HMAC verification:** Both endpoints of a POOL session
   independently compute the HMAC for every packet. Both endpoints verify
   the peer's HMAC. This is already implemented — it is the core of POOL's
   packet authentication. This tenet recognizes it as a form of replicated
   execution.
2. **Session state consistency checks:** Periodically, both peers exchange
   session state digests (sequence numbers, rekey epoch, bytes transferred).
   Divergence indicates that one peer's state has been tampered with.
3. **Multi-path verification for bridges:** Critical bridge operations
   (v1↔v2 re-encryption) should be performed by two independent bridge
   instances on different hardware. Traffic is only forwarded if both produce
   the same output.

**Addresses:** RT-C02, RT-S01, RT-S03, RT-U02

### Tenet T5: Cryptographic Execution Proofs

> Computations must be able to prove their correctness independently
> of the binary that produced them.

**Rationale:** If a computation produces a *proof* that can be verified
independently, it doesn't matter whether the binary was modified — the
proof speaks for itself.

**Implementation requirements:**

1. **Journal chain integrity:** Modify `pool_journal_add()` to chain entries:
   each entry's hash includes the prior entry's hash, forming a Merkle chain.
   Any modification to a past entry invalidates all subsequent hashes.
   (Currently, journal entries are hashed individually without chaining —
   see §2.3, RT-A02.)
2. **Key derivation verification:** After HKDF derives session keys, both
   peers independently derive the same keys from the same shared secret and
   exchange a proof (e.g., HMAC of a fixed label under the derived key).
   This already happens implicitly during the handshake (the ACK packet
   proves both peers derived compatible keys), but should be re-verified
   periodically after rekeying.
3. **Proof-of-work verification immutability:** Puzzle solutions are
   self-verifying — the solution either hashes to a value with the required
   leading zeros or it doesn't. This property is inherently overlay-resistant
   if the verifier is on a different system (Tenet T4).

**Addresses:** RT-A02, RT-C05, RT-S04

### Tenet T6: Self-Verifying Code (Canaries)

> Code must embed mechanisms to continuously verify its own integrity
> via checksums, canaries, and control flow integrity.

**Rationale:** While self-verification can be defeated by an attacker who also
overlays the verification code (the "quis custodiet" problem), it raises the
bar significantly. Combined with Tenets T3 and T4, canaries detect overlay
attempts that are targeted rather than comprehensive.

**Implementation requirements:**

1. **Function-level checksums:** Critical functions (`pool_crypto_hmac_verify`,
   `pool_crypto_encrypt`, `pool_crypto_decrypt`, `pool_crypto_ecdh`) should
   compute a checksum of their own instruction bytes at entry and compare
   against a compile-time constant. Mismatch triggers a hard failure.
2. **Stack canaries:** Ensure kernel stack protector (`-fstack-protector-strong`)
   is enabled for `pool.ko`. Verify in the Kbuild configuration.
3. **Control Flow Integrity (CFI):** On kernels that support it (5.13+ with
   Clang CFI), enable CFI for the POOL module to prevent control flow
   hijacking via overlaid function pointers.
4. **Return address verification:** For critical crypto functions, push a
   canary value before the call and verify it on return. A modified return
   address indicates control flow tampering.

**Addresses:** RT-C01, RT-C02, RT-S05

### Tenet T7: Append-Only External Audit Logs

> Execution evidence must be written to an immutable, external log
> outside the modifiable domain.

**Rationale:** RT-A01, RT-A02, and RT-A04 all involve falsifying local
observability data. If audit evidence is also written to an external system
that the attacker cannot overlay, tampering is detectable.

**Implementation requirements:**

1. **Remote journal replication:** Journal entries should be signed with the
   session HMAC key and transmitted to remote peers. Each peer maintains an
   independent copy of the journal chain. Divergence between local and remote
   journals indicates tampering.
2. **Tamper-evident Merkle chain:** When journal entries are chained (Tenet
   T5, item 1), the chain head hash can be periodically published to an
   external service (e.g., a transparency log or a peer's journal) as a
   commitment. Retroactive modification of the chain is detectable.
3. **Out-of-band telemetry export:** Telemetry data should be exported to
   an external monitoring system (Prometheus exporter already exists) AND
   cross-checked against the peer's independently observed values. If
   Node A reports 0% loss but Node B reports 15% loss to Node A, the
   discrepancy indicates falsification.

**Addresses:** RT-A01, RT-A02, RT-A04

### Tenet T8: Assume Compromise, Design for Detection

> Every component is assumed modifiable at any time. Architecture must
> detect compromise and enable recovery, not merely prevent it.

**Rationale:** Prevention-only security fails when the prevention mechanism
itself can be subverted. Detection-and-recovery is more resilient because
it requires the attacker to also subvert the detection mechanism, which
(per Tenets T3 and T4) may reside in a separate physical domain.

**Implementation requirements:**

1. **Redundant verification paths:** No security-critical check should have
   a single code path. HMAC verification, state machine transitions, and
   key derivation should each have at least two independent verification
   mechanisms that an attacker must simultaneously overlay.
2. **Fail-open alerting:** If any self-check fails, POOL must generate an
   alert that is visible *outside* the POOL process — via syslog, via a
   hardware LED/GPIO (if available), via a pre-established secondary
   communication channel. The alert path must not traverse the potentially
   compromised code.
3. **Graceful degradation:** When compromise is detected, POOL should:
   (a) refuse to establish new sessions, (b) mark existing sessions as
   untrusted, (c) log the detection event to the external journal, and
   (d) alert operators via the out-of-band channel.
4. **Recovery without trust in the compromised system:** Recovery procedures
   must not rely on the compromised system to verify its own recovery.
   Module reload, re-attestation, and session re-establishment must be
   verified by an external system (peer node, TPM, or operator).

**Addresses:** All failure modes (defense in depth)

---

## 4. Mitigation Matrix

This matrix maps each failure mode to the tenets that mitigate it.

| Failure Mode | T1 | T2 | T3 | T4 | T5 | T6 | T7 | T8 |
|-------------|----|----|----|----|----|----|----|----|
| RT-C01 Module binary mod after insmod | ✓ | | ✓ | | | ✓ | | ✓ |
| RT-C02 HMAC verify always-pass | | ✓ | | ✓ | | ✓ | | ✓ |
| RT-C03 X25519 private key extraction | | | ✓ | | | | | ✓ |
| RT-C04 ChaCha20 key/nonce exfiltration | | ✓ | | | | | | ✓ |
| RT-C05 HKDF output replacement | | ✓ | | | ✓ | | | ✓ |
| RT-C06 RNG compromise | | | ✓ | | | | | ✓ |
| RT-S01 Session struct modification | | | | ✓ | | | | ✓ |
| RT-S02 Sequence number overlay | | ✓ | | | | | | ✓ |
| RT-S03 Rekey suppression | | | | ✓ | | | | ✓ |
| RT-S04 Puzzle bypass | | | | | ✓ | | | ✓ |
| RT-S05 State machine override | | | | | | ✓ | | ✓ |
| RT-A01 procfs falsification | | | ✓ | | | | ✓ | ✓ |
| RT-A02 Journal chain forgery | | | | | ✓ | | ✓ | ✓ |
| RT-A03 Self-test falsification | ✓ | | ✓ | | | | | ✓ |
| RT-A04 Telemetry manipulation | | | | | | | ✓ | ✓ |
| RT-U01 poolctl/poold replacement | | | | | | | | ✓ |
| RT-U02 Bridge plaintext interception | | | | ✓ | | | | ✓ |
| RT-U03 Shim interception | | | | | | | | ✓ |
| RT-U04 Vault path bypass | | ✓ | | | | ✓ | | ✓ |
| RT-U05 Relay score manipulation | | | | ✓ | | | ✓ | ✓ |

Every failure mode is covered by T8 (Assume Compromise). No failure mode
should have fewer than two tenet mitigations.

---

## 5. Relationship to Existing POOL Security Mechanisms

This document does not replace existing security mechanisms. It identifies
where they are insufficient against this threat class and prescribes
additional layers.

| Existing Mechanism | Location | Status Under This Threat Model |
|-------------------|----------|-------------------------------|
| Crypto self-tests at module load | `pool_crypto.c:33-156` | **Necessary but insufficient.** Defeated by RT-C01, RT-A03. Extended by T1 (continuous re-verification). |
| Constant-time HMAC comparison | `pool_crypto.c:640` | **Necessary but insufficient.** Protects against timing attacks but not overlay (RT-C02). Extended by T2 (behavioral cross-checks). |
| Anti-replay window (64 packets) | `pool_net.c:273-289` | **Effective against network replay.** Does not address RT-S02 (local sequence overlay). Extended by T2 (secondary counter). |
| State machine validation | `pool_state.h:16-80` | **Effective against protocol violations.** Does not address RT-S05 (overlay on validation code). Extended by T6 (CFI). |
| SHA256 journal hashes | `pool_journal.c:58-71` | **Insufficient.** Entries hashed individually, not chained. Addressed by T5 (Merkle chain) and T7 (remote replication). |
| Module reference counting | `pool_main.c:44-46` | **Effective for lifecycle management.** Not relevant to this threat model. |
| Heartbeat telemetry | `pool_telemetry.c` | **Partially effective.** Peer can detect anomalies in RTT/loss but not if both sides are overlaid (RT-A04). Extended by T7. |

---

## 6. Implementation Priority

Mitigations are prioritized by implementability and impact:

| Priority | Tenet | Effort | Impact | Notes |
|----------|-------|--------|--------|-------|
| **P0** | T5 (journal chaining) | Low | High | Simple code change to `pool_journal_add()` to include prior hash |
| **P0** | T1 (periodic self-test re-execution) | Low | High | Add self-test calls to heartbeat thread |
| **P0** | T6 (stack protector verification) | Low | Medium | Verify Kbuild flags |
| **P1** | T1 (.text section checksumming) | Medium | High | Kernel APIs for reading own .text section |
| **P1** | T2 (crypto spot-checks) | Medium | High | Known-answer test in heartbeat loop |
| **P1** | T7 (cross-peer journal replication) | Medium | High | Requires new packet type or heartbeat extension |
| **P2** | T2 (peer behavioral challenge) | Medium | Medium | Requires protocol extension |
| **P2** | T4 (session state consistency) | Medium | Medium | Requires protocol extension |
| **P3** | T3 (TPM attestation hooks) | High | High | Platform-dependent, complex |
| **P3** | T3 (enclave integration) | High | High | Hardware-dependent |

---

## 7. The Core Insight

The fundamental failure this document addresses is:

> **Modern computing assumes a static boundary between "the code" and "the
> execution." This threat model dissolves that boundary entirely.**

Every security, reliability, and governance mechanism POOL implements is built
on the assumption that *what was loaded is what runs*. Remove that assumption,
and trust must shift from **identity** (what is this binary?) to **behavior**
(what did this computation produce, and can I independently verify it?).

This is the same trust model shift that distributed consensus systems
(blockchains, multi-party computation, zero-knowledge proofs) already
implement — they assume adversarial execution environments and verify
*outputs*, not *processes*.

POOL's existing cross-peer verification (mutual HMAC authentication) is
already a primitive form of replicated execution (Tenet T4). The tenets in
this document extend that principle to all aspects of POOL's operation.

---

## 8. References

- `spec/SECURITY.md` — Vulnerability response playbook
- `spec/PROTOCOL.md` — Complete POOL v1 protocol specification
- `spec/MIGRATION.md` — Three-phase TCP → POOL migration strategy
- `linux/pool_crypto.c` — Cryptography implementation (self-tests, HMAC, AEAD)
- `linux/pool_journal.c` — SHA256 audit journal
- `linux/pool_session.c` — Session lifecycle and state machine
- `linux/pool_net.c` — Network transport, anti-replay, HMAC verification
- `linux/pool_main.c` — Module init/exit, self-test invocation
- `common/pool_state.h` — State machine definition and transition logic
- `tests/features/failure_modes.feature` — Existing 52 failure mode BDD tests

---

## 9. Implementation Status

The following mitigations have been implemented in the POOL kernel module
codebase. Each maps to one or more tenets (T1–T8) and failure modes (RT-*).

### 9.1 P0 — Low Effort, High Impact (Complete)

| Mitigation | Tenet | Failure Mode | File(s) |
|-----------|-------|-------------|---------|
| Journal hash chaining (Merkle chain) | T5 | RT-A02 | `pool_journal.c` |
| Periodic crypto self-test re-execution (every ~60s) | T1 | RT-C01, RT-A03 | `pool_crypto.c`, `pool_telemetry.c` |
| Compiler security flags (`-fstack-protector-strong`, `-Wformat-security`) | T6 | RT-S05, RT-C01 | `Makefile`, `Kbuild` |
| Crypto behavioral spot-check (known-answer test) | T2 | RT-C02, RT-C04, RT-C05 | `pool_crypto.c` |

### 9.2 P1 — Medium Effort, High Impact (Complete)

| Mitigation | Tenet | Failure Mode | File(s) |
|-----------|-------|-------------|---------|
| Module `.text` section CRC32 checksumming | T1, T6 | RT-C01 | `pool_main.c`, `pool_telemetry.c` |
| Shadow sequence counter with divergence detection | T2 | RT-S02 | `pool_internal.h`, `pool_net.c` |
| Integrity alert mechanism (`/proc/pool/integrity`, session refusal) | T8 | All | `pool_sysinfo.c`, `pool_session.c` |
| Heartbeat state digest exchange (CRC32 of session state) | T4 | RT-S01, RT-S03 | `pool_telemetry.c`, `pool_proto.h` |

### 9.3 P2 — Medium Effort, Medium Impact (Complete)

| Mitigation | Tenet | Failure Mode | File(s) |
|-----------|-------|-------------|---------|
| Peer crypto challenge-response (`POOL_PKT_INTEGRITY 0xC`) | T2, T4 | RT-C02, RT-C04 | `pool.h`, `pool_state.h`, `pool_session.c`, `pool_telemetry.c` |
| Attestation procfs interface (`/proc/pool/attestation`) | T3 | RT-C01, RT-A03 | `pool_sysinfo.c`, `pool_internal.h` |

### 9.4 Out of Scope

- **TPM/SGX hardware attestation (T3):** Requires platform-specific TPM or SGX
  support. Attestation hooks are provided via `/proc/pool/attestation`.
- **External audit log replication (T7):** Requires external infrastructure
  (syslog server, append-only storage). Journal hash chaining ensures local
  integrity; external replication is a deployment concern.
- **Hardware overlay detection:** Cannot be fully solved in software. Module
  `.text` CRC32 and crypto spot-checks provide partial detection.
