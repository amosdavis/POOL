Feature: POOL Runtime Integrity Failure Tenets
  As a POOL implementer
  I need all 20 runtime integrity failure modes to be properly mitigated
  So that POOL is resilient against runtime binary modification attacks

  # ---- Category 1: Crypto Path Tampering (RT-C01 through RT-C06) ----

  @runtime-integrity @crypto
  Scenario: RT-C01 - Module must support periodic self-test re-execution
    Given the POOL crypto source code
    When the self-test functions are analyzed
    Then pool_crypto_selftest_hmac should use known RFC 4231 test vectors
    And pool_crypto_selftest_aead should verify encrypt-decrypt round-trip
    And pool_crypto_init should refuse to load on self-test failure

  @runtime-integrity @crypto
  Scenario: RT-C02 - HMAC verification must use constant-time comparison
    Given the POOL crypto source code
    When the HMAC verification path is analyzed
    Then crypto_memneq should be used for HMAC tag comparison
    And standard memcmp should not be used for HMAC verification
    And HMAC verification failure should return EBADMSG

  @runtime-integrity @crypto
  Scenario: RT-C03 - ECDH keypair must be generated per node
    Given the POOL main source code
    When the module initialization is analyzed
    Then a keypair should be generated at module load
    And pool_crypto_gen_keypair should fail hard without curve25519 KPP

  @runtime-integrity @crypto
  Scenario: RT-C04 - Nonce construction must include entropy prefix
    Given the POOL network source code
    When the nonce construction is analyzed
    Then the nonce should include hmac_key bytes not zeros
    And the nonce should include the big-endian sequence number
    And rekeying should be triggered before nonce reuse

  @runtime-integrity @crypto
  Scenario: RT-C05 - HKDF must validate output lengths
    Given the POOL crypto source code
    When the HKDF implementation is analyzed
    Then HKDF should reject zero-length output requests
    And HKDF should reject output lengths exceeding 255 times hash length

  @runtime-integrity @crypto
  Scenario: RT-C06 - Self-test results must prevent module load on failure
    Given the POOL main source code
    When the self-test error handling is analyzed
    Then crypto init failure should trigger goto err_crypto
    And the module should not complete initialization on crypto failure

  # ---- Category 2: Session & State Tampering (RT-S01 through RT-S05) ----

  @runtime-integrity @session
  Scenario: RT-S01 - Session access must be serialized by mutex
    Given the POOL session source code
    When the session access patterns are analyzed
    Then sessions_lock should protect session table iteration
    And session state transitions should be validated before execution

  @runtime-integrity @session
  Scenario: RT-S02 - Anti-replay window must enforce sequence ordering
    Given the POOL network source code
    When the anti-replay implementation is analyzed
    Then packets outside the 64-entry replay window should be rejected
    And the expected_remote_seq should be updated on valid packets
    And sequence gaps should be counted as packet loss

  @runtime-integrity @session
  Scenario: RT-S03 - Rekey must trigger after packet threshold
    Given the POOL crypto source code
    When the rekey mechanism is analyzed
    Then packets_since_rekey should be tracked
    And a rekey trigger should occur at POOL_REKEY_PACKETS threshold

  @runtime-integrity @session
  Scenario: RT-S04 - Handshake proof must use constant-time verification
    Given the POOL session source code
    When the handshake proof verification is analyzed
    Then crypto_memneq should be used for proof comparison
    And proof verification failure should reject the handshake

  @runtime-integrity @session
  Scenario: RT-S05 - State machine must reject invalid transitions
    Given the POOL state machine definition
    When the state transition logic is analyzed
    Then each state should have a defined set of valid packet types
    And invalid packet types should not change the session state
    And the IDLE state should only accept INIT packets

  # ---- Category 3: Observability & Audit Tampering (RT-A01 through RT-A04) ----

  @runtime-integrity @audit
  Scenario: RT-A01 - Journal entries must be individually hashed
    Given the POOL journal source code
    When the journal add function is analyzed
    Then each entry should be hashed with SHA256
    And the hash should cover timestamp and change_type and detail
    And the journal should use a circular buffer with version tracking

  @runtime-integrity @audit
  Scenario: RT-A02 - Journal should support chained hashing for tamper evidence
    Given the POOL runtime integrity specification
    When the journal chaining requirement is analyzed
    Then Tenet T5 should require Merkle chain linking of journal entries
    And modification of past entries should invalidate subsequent hashes

  @runtime-integrity @audit
  Scenario: RT-A03 - Self-test failure must prevent all crypto operations
    Given the POOL crypto source code
    When the self-test failure path is analyzed
    Then self-test failure should return EACCES
    And pool_crypto_init should propagate the failure to module init
    And no crypto operations should proceed after self-test failure

  @runtime-integrity @audit
  Scenario: RT-A04 - Telemetry must be verifiable by peer
    Given the POOL telemetry source code
    When the heartbeat mechanism is analyzed
    Then heartbeat packets should carry timestamps
    And both peers should independently compute RTT from heartbeat round-trip

  # ---- Category 4: Userspace & Adoption Tool Tampering (RT-U01 through RT-U05) ----

  @runtime-integrity @userspace
  Scenario: RT-U01 - ioctl must require module reference before execution
    Given the POOL main source code
    When the ioctl protection is analyzed
    Then try_module_get should be called before ioctl processing
    And module_put should be called on all ioctl exit paths
    And ioctl during module unload should fail with ENODEV

  @runtime-integrity @userspace
  Scenario: RT-U02 - Bridge re-encryption gap must be documented
    Given the POOL security specification
    When the bridge security documentation is analyzed
    Then the bridge plaintext transit risk should be documented
    And the bridge must be designated as a trusted hardened node

  @runtime-integrity @userspace
  Scenario: RT-U03 - Vault must reject path traversal attempts
    Given the POOL vault source code
    When the path validation logic is analyzed
    Then dot-dot-slash sequences should be detected and rejected
    And path length should be validated against VAULT_MAX_PATH

  @runtime-integrity @userspace
  Scenario: RT-U04 - Relay state access must be mutex-protected
    Given the POOL relay source code
    When the thread safety implementation is analyzed
    Then pthread_mutex_lock should protect relay state access
    And generosity score computation should be serialized

  @runtime-integrity @userspace
  Scenario: RT-U05 - Module shutdown must close sessions before workqueue flush
    Given the POOL main source code
    When the module exit sequence is analyzed
    Then all sessions should be closed before workqueue flush
    And no flushed work should reference freed session data

  # ---- Category 5: Design Tenet Verification ----

  @runtime-integrity @tenet
  Scenario: T1 - Continuous Runtime Attestation is specified
    Given the POOL runtime integrity specification
    When Tenet T1 is analyzed
    Then periodic text section checksumming should be required
    And self-test re-execution should be required
    And external attestation hook should be required

  @runtime-integrity @tenet
  Scenario: T2 - Behavioral Verification is specified
    Given the POOL runtime integrity specification
    When Tenet T2 is analyzed
    Then crypto output spot-checks should be required
    And peer-side behavioral verification should be required

  @runtime-integrity @tenet
  Scenario: T3 - Hardware Root of Trust is specified
    Given the POOL runtime integrity specification
    When Tenet T3 is analyzed
    Then TPM-based module attestation should be required
    And out-of-band attestation channel should be required

  @runtime-integrity @tenet
  Scenario: T4 - Replicated Execution is specified
    Given the POOL runtime integrity specification
    When Tenet T4 is analyzed
    Then cross-peer HMAC verification should be required
    And session state consistency checks should be required

  @runtime-integrity @tenet
  Scenario: T5 - Cryptographic Execution Proofs is specified
    Given the POOL runtime integrity specification
    When Tenet T5 is analyzed
    Then journal chain integrity via Merkle chain should be required
    And key derivation verification should be required

  @runtime-integrity @tenet
  Scenario: T6 - Self-Verifying Code is specified
    Given the POOL runtime integrity specification
    When Tenet T6 is analyzed
    Then function-level checksums should be required
    And stack canary enablement should be required
    And control flow integrity should be required

  @runtime-integrity @tenet
  Scenario: T7 - Append-Only External Audit Logs is specified
    Given the POOL runtime integrity specification
    When Tenet T7 is analyzed
    Then remote journal replication should be required
    And tamper-evident Merkle chain should be required
    And out-of-band telemetry export should be required

  @runtime-integrity @tenet
  Scenario: T8 - Assume Compromise is specified
    Given the POOL runtime integrity specification
    When Tenet T8 is analyzed
    Then redundant verification paths should be required
    And fail-open alerting should be required
    And graceful degradation should be required
    And recovery without trust in compromised system should be required

  # ---- Implementation Verification Scenarios ----

  @runtime-integrity @implementation
  Scenario: P0-1 - Journal entries use hash chaining
    Given the POOL journal source code
    When the hash computation is analyzed
    Then the previous entry hash should be included in SHA256 input
    And the first entry should use a zero-initialized previous hash

  @runtime-integrity @implementation
  Scenario: P0-2 - Runtime self-tests execute periodically
    Given the POOL telemetry source code
    When the heartbeat thread is analyzed
    Then pool_crypto_runtime_selftest should be called periodically
    And pool_crypto_spot_check should be called periodically
    And integrity_compromised should be set on failure

  @runtime-integrity @implementation
  Scenario: P0-3 - Compiler security flags are enabled
    Given the POOL build configuration
    When the compiler flags are analyzed
    Then fstack-protector-strong should be enabled
    And Wformat-security should be enabled

  @runtime-integrity @implementation
  Scenario: P1-1 - Module text section is checksummed
    Given the POOL main source code
    When the module initialization is analyzed
    Then text_crc32 should be computed at init via CRC32
    And the text section CRC should be re-verified in heartbeat

  @runtime-integrity @implementation
  Scenario: P1-2 - Shadow sequence counter detects divergence
    Given the POOL network source code
    When the send path is analyzed
    Then shadow_local_seq should be incremented independently
    And shadow and primary sequence counters should be compared
    And divergence should set integrity_compromised

  @runtime-integrity @implementation
  Scenario: P1-3 - Integrity alert mechanism is operational
    Given the POOL sysinfo source code
    When the procfs entries are analyzed
    Then proc_pool_integrity should report integrity status
    And proc_pool_attestation should report text CRC32
    And session allocation should refuse when integrity is compromised

  @runtime-integrity @implementation
  Scenario: P1-4 - Heartbeat includes state digest
    Given the POOL protocol definitions
    When the telemetry structure is analyzed
    Then state_digest field should exist in pool_telemetry
    And state_digest should be CRC32 of session state

  @runtime-integrity @implementation
  Scenario: P2-1 - Peer crypto challenge is implemented
    Given the POOL session source code
    When the packet dispatch is analyzed
    Then POOL_PKT_INTEGRITY should be defined as 0xC
    And POOL_PKT_INTEGRITY should be valid in ESTABLISHED state
    And integrity challenge should encrypt and return nonce
    And integrity response should verify decrypted challenge
