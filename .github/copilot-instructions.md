# POOL Project Rules — Copilot Instructions

## Project Overview

POOL (Protected Orchestrated Overlay Link) is a secure transport protocol
implemented as a Linux kernel module. It replaces TCP/IP's trust-by-default
model with mandatory mutual authentication, always-on encryption, and
cryptographic sequence numbers.

## Critical Design Tenets

All code changes MUST comply with these tenets. No change shall be accepted
if it violates a tenet or creates a new path for a documented failure mode.

### Crypto Suite Policy (Fixed, No Negotiation)

POOL v1 uses a fixed cipher suite with NO algorithm negotiation:
- **Key Exchange:** X25519 ECDH only
- **AEAD:** ChaCha20-Poly1305 only
- **Packet Auth:** HMAC-SHA256 only
- **Key Derivation:** HKDF-SHA256 only

**Rules:**
- Never add cipher fallbacks or negotiation to v1
- If a primitive is unavailable, FAIL HARD — do not substitute
- Cross-version interop is handled by `pool_bridge`, not by endpoint negotiation

### Runtime Integrity Tenets (spec/RUNTIME_INTEGRITY.md)

These 8 tenets address the threat of runtime binary modification and hardware
overlay attacks. All future design must satisfy them:

1. **T1: Continuous Runtime Attestation** — Code integrity must be verified
   continuously during execution, not only at load time. Self-tests must be
   re-executable, not one-shot.

2. **T2: Behavioral Verification Over Binary Verification** — Verify what
   code *does*, not what it *is*. Monitor outputs against known-good models.
   Prefer cross-peer verification of crypto operations.

3. **T3: Hardware Root of Trust** — Verification must exist in a physically
   separate domain immune to overlay. Provide TPM/attestation hooks even if
   hardware is not yet available.

4. **T4: Replicated Execution with Consensus** — Critical computations must
   be verified by N independent systems. POOL's mutual HMAC authentication
   is already a primitive form of this.

5. **T5: Cryptographic Execution Proofs** — Computations must prove
   correctness independently of the binary. Journal entries must be
   Merkle-chained. Key derivation must be cross-verifiable.

6. **T6: Self-Verifying Code (Canaries)** — Code must embed integrity
   checksums, use stack protectors, and support control flow integrity.

7. **T7: Append-Only External Audit Logs** — Audit evidence must be
   written to an immutable external log. Journal entries must be replicated
   to remote peers. Telemetry must be cross-checked.

8. **T8: Assume Compromise, Design for Detection** — Every component is
   assumed modifiable. Architecture must detect and recover from compromise
   via redundant verification paths and out-of-band alerting.

### Documented Failure Modes

20 failure modes are documented in `spec/RUNTIME_INTEGRITY.md` §2:

- **RT-C01–C06:** Crypto path tampering (binary mod after insmod, HMAC
  bypass, key extraction, nonce leak, HKDF replacement, RNG compromise)
- **RT-S01–S05:** Session/state tampering (struct modification, sequence
  overlay, rekey suppression, puzzle bypass, state machine override)
- **RT-A01–A04:** Audit tampering (procfs falsification, journal forgery,
  self-test falsification, telemetry manipulation)
- **RT-U01–U05:** Userspace tampering (binary replacement, bridge plaintext
  intercept, shim redirect, vault path bypass, relay score manipulation)

**Before approving any code change, verify it does not create or worsen
any of these failure modes.**

## Code Quality Standards

- Follow Clean Code Principles (Robert C. Martin)
- All tests are BDD (Cucumber/godog) — see `tests/features/*.feature`
- Use constant-time comparison (`crypto_memneq`) for all auth tag checks
- Never use standard `memcmp` for security-sensitive comparisons
- Kernel code must handle all error paths with proper cleanup (goto chains)
- All state changes must go through the state machine in `pool_state.h`

## Key Files

| Purpose | File |
|---------|------|
| Protocol spec | `spec/PROTOCOL.md` |
| Security playbook | `spec/SECURITY.md` |
| Runtime integrity tenets | `spec/RUNTIME_INTEGRITY.md` |
| Failure modes (existing 52) | `tests/features/failure_modes.feature` |
| Runtime integrity tests | `tests/features/runtime_integrity.feature` |
| State machine | `common/pool_state.h` |
| Crypto implementation | `linux/pool_crypto.c` |
