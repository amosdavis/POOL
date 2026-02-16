Feature: POOL Failure Mode Mitigations
  As a POOL implementer
  I need all 52 identified failure modes to be properly mitigated
  So that POOL is secure and robust for ubiquitous deployment

  # ---- Category 1: Cryptography (C01-C07) ----

  @crypto
  Scenario: C01 - Nonce uses session-unique prefix instead of zeros
    Given a POOL session with established crypto state
    When the nonce is constructed for encryption
    Then bytes 0-3 of the nonce should contain hmac_key bytes not zeros
    And bytes 4-11 should contain the big-endian sequence number

  @crypto
  Scenario: C02 - ECDH without curve25519 KPP fails hard
    Given a POOL crypto context with no hardware ECDH
    When the ECDH function is called
    Then it should return an error refusing to proceed
    And no fallback cipher should be used

  @crypto
  Scenario: C03 - HKDF rejects invalid output lengths
    Given a POOL HKDF context
    When HKDF is called with okm_len 0
    Then it should return EINVAL
    When HKDF is called with okm_len exceeding 255 times 32
    Then it should return EINVAL

  @crypto
  Scenario: C04 - Rekey triggers after packet threshold
    Given a POOL session with established crypto state
    When packets_since_rekey reaches POOL_REKEY_PACKETS
    Then a rate-limited rekey info message should be logged

  @crypto
  Scenario: C05 - PQC CBD uses aligned memory access
    Given a POOL PQC context
    When mlkem_cbd_eta2 processes an input buffer
    Then it should use memcpy for 32-bit reads instead of pointer casts
    And it should not cause unaligned access faults on ARM

  @crypto
  Scenario: C06 - PQC encaps and decaps propagate HKDF errors
    Given a POOL PQC context
    When HKDF fails during ML-KEM encapsulation
    Then the error code should be propagated to the caller
    When HKDF fails during ML-KEM decapsulation
    Then the error code should be propagated to the caller

  @crypto
  Scenario: C07 - PQC keygen fails if SHA256 allocation fails
    Given a POOL PQC context
    When crypto_alloc_shash for SHA256 fails during keygen
    Then keygen should return the allocation error code
    And no partial secret key should be generated

  # ---- Category 2: Network Transport (N01-N07) ----

  @network
  Scenario: N01 - TCP connect has 10-second timeout
    Given a POOL node attempting TCP connection
    When connecting to an unreachable peer
    Then the connection attempt should timeout within 10 seconds
    And not block indefinitely

  @network
  Scenario: N02 - Sequence replay outside window is discarded
    Given a POOL session with established crypto state
    And the highest received sequence is 100
    When a packet with sequence number 30 arrives
    Then the packet should be silently discarded as outside replay window
    When a packet with sequence number 80 arrives
    Then the packet should be accepted as within replay window

  @network
  Scenario: N03 - Source IP validation on raw socket
    Given a POOL raw transport session with peer IP 192.168.1.1
    When a packet arrives from IP 192.168.1.2 matching the session ID
    Then the packet should be rejected with a rate-limited warning
    And not delivered to the session RX queue

  @network
  Scenario: N04 - RX queue depth limited to 4096
    Given a POOL raw transport session
    When the RX queue contains 4096 entries
    And another packet arrives for the session
    Then the packet should be dropped with a rate-limited warning
    And the queue depth should not exceed 4096

  @network
  Scenario: N05 - Session lookup under mutex protection
    Given a POOL raw transport listener
    When looking up sessions by session ID
    Then the sessions_lock mutex should be held during iteration
    And no use-after-free is possible from concurrent session deletion

  @network
  Scenario: N06 - Peer table uses LRU eviction when full
    Given a POOL peer discovery table with 256 active peers
    When a new peer announces itself
    Then the oldest non-static peer should be evicted
    And the new peer should be added to the table

  @network
  Scenario: N07 - Announce processing is rate-limited
    Given a POOL peer discovery listener
    When announces arrive faster than every 100 milliseconds
    Then excess announces should be silently dropped
    And the peer table should not churn excessively

  # ---- Category 3: Session / Data Path (S01-S06) ----

  @session
  Scenario: S01 - kthread failure does not leak session resources
    Given a POOL session being established
    When kthread_run fails for the rx_thread
    Then pool_session_free should be called
    And all session resources should be released

  @session
  Scenario: S02 - Fragment cleanup holds rx_lock
    Given a POOL session with active fragment reassembly
    When pool_session_free is called
    Then the rx_lock should be held while freeing fragment buffers
    And no race with concurrent rx_thread fragment writes

  @session
  Scenario: S03 - Fragment reassembly validates bounds
    Given a POOL session receiving fragmented data
    When a fragment with offset plus length exceeding total_len arrives
    Then the fragment should be rejected
    And no heap overflow should occur

  @session
  Scenario: S04 - Fragment slots use LRU eviction when full
    Given a POOL session with all 16 fragment slots occupied
    When a new fragment sequence begins
    Then the oldest incomplete fragment should be evicted
    And the new fragment should use the freed slot

  @session
  Scenario: S05 - Config operations use mutex protection
    Given a POOL config subsystem
    When concurrent CONFIG packets arrive from different sessions
    Then config_lock mutex should serialize all config operations
    And no race condition on current_config

  @session
  Scenario: S06 - MTU binary search handles lo equals hi
    Given a POOL session performing MTU discovery
    When the probe range collapses to lo equals hi
    Then MTU discovery should declare complete
    And no further probes should be sent

  # ---- Category 4: Module Lifecycle (M01-M05) ----

  @lifecycle
  Scenario: M01 - Sessions closed before workqueue flush
    Given a POOL kernel module shutting down
    When pool_exit is called
    Then all sessions should be closed first
    And then the workqueue should be flushed
    And no flushed work should reference freed sessions

  @lifecycle
  Scenario: M02 - Channel ioctl validates bounds
    Given a POOL session with channel subscriptions
    When a CHANNEL ioctl requests channel 256
    Then it should return EINVAL
    And no out-of-bounds write should occur

  @lifecycle
  Scenario: M03 - Ioctl acquires module reference
    Given a POOL kernel module
    When an ioctl is called
    Then try_module_get should be called first
    And module_put should be called on all exit paths
    And ioctl during module unload should return ENODEV

  @lifecycle
  Scenario: M04 - procfs reader holds sessions_lock
    Given a POOL kernel module with active sessions
    When /proc/pool/sessions is read
    Then sessions_lock should be held during iteration
    And no use-after-free from concurrent session deletion

  @lifecycle
  Scenario: M05 - Heartbeat waits for sessions_ready
    Given a POOL kernel module initializing
    When the heartbeat thread starts before session_init completes
    Then the heartbeat should wait for sessions_ready flag
    And not access uninitialized session data

  # ---- Category 5: Platform (W01-W04, D01-D03) ----

  @platform @windows
  Scenario: W01 - Windows fails hard when ChaCha20-Poly1305 unavailable
    Given a POOL Windows node on pre-1903 Windows
    When BCrypt ChaCha20-Poly1305 is unavailable
    Then the implementation should fail with an error
    And no fallback cipher should be used

  @platform @windows
  Scenario: W02 - Windows uses real X25519 ECDH
    Given a POOL Windows node
    When X25519 shared secret is computed
    Then BCrypt ECDH with Curve25519 should be used
    And not SHA-256 hash of sorted keys

  @platform @windows
  Scenario: W03 - Windows named pipe has DACL restricting access
    Given a POOL Windows service with control pipe
    When the named pipe is created
    Then a DACL should restrict access to SYSTEM and Administrators
    And local unprivileged users should not be able to connect

  @platform @windows
  Scenario: W04 - Windows pipe validates command length
    Given a POOL Windows service receiving pipe commands
    When a command with len exceeding bytes_read arrives
    Then the command should be rejected
    And no buffer overflow should occur

  @platform @macos
  Scenario: D01 - macOS uses OpenSSL ChaCha20-Poly1305
    Given a POOL macOS node
    When AEAD encryption is performed
    Then OpenSSL EVP ChaCha20-Poly1305 should be used
    And not the XOR-based placeholder

  @platform @macos
  Scenario: D02 - macOS uses OpenSSL X25519
    Given a POOL macOS node
    When X25519 keypair is generated
    Then OpenSSL EVP_PKEY X25519 should be used
    And not CC_SHA256 derivation

  @platform @macos
  Scenario: D03 - macOS daemon validates command length
    Given a POOL macOS daemon receiving socket commands
    When a command with len exceeding bytes_read arrives
    Then the command should be rejected
    And no buffer overflow should occur

  # ---- Category 6: Userspace Tools (U01-U07) ----

  @userspace
  Scenario: U01 - Vault rejects path traversal attempts
    Given a POOL vault server serving a directory
    When a client requests path "../../etc/passwd"
    Then the request should be rejected
    And the response should indicate path traversal denied

  @userspace
  Scenario: U02 - Vault validates path length against buffer
    Given a POOL vault server serving a directory
    When a client sends a path exceeding VAULT_MAX_PATH
    Then the request should be rejected before buffer copy
    And no stack buffer overflow should occur

  @userspace
  Scenario: U03 - Bridge shutdown collects threads before join
    Given a POOL bridge with active bidirectional threads
    When the bridge shuts down
    Then thread handles should be collected under lock
    And lock should be released before joining threads
    And no use-after-free should occur

  @userspace
  Scenario: U04 - Bridge allocation uses safe slot selection
    Given a POOL bridge with concurrent connection attempts
    When two connections try to allocate the same slot
    Then only one should succeed
    And no double allocation should occur

  @userspace
  Scenario: U05 - Relay uses properly sized buffer
    Given a POOL relay forwarding packets
    When a packet of 109 bytes is received
    Then the receive buffer should be at least 4096 bytes
    And no stack overflow should occur

  @userspace
  Scenario: U06 - Relay state access is mutex-protected
    Given a POOL relay with concurrent connections
    When state is accessed from multiple threads
    Then pthread_mutex_lock should protect all state access
    And no data race should occur

  @userspace
  Scenario: U07 - Shim logs warning for out-of-bounds FD
    Given a POOL shim intercepting socket calls
    When a file descriptor exceeding POOL_SHIM_MAX_FDS is returned
    Then a warning should be logged
    And the FD should not be stored in the tracking array

  # ---- Category 7: Protocol / Spec (P01-P13) ----

  @protocol
  Scenario: P01 - Nonce construction prevents collision
    Given the POOL protocol specification
    Then section 13.1 should mandate hmac_key prefix in nonce bytes 0-3
    And rekeying before sequence counter reaches 2^63

  @protocol
  Scenario: P02 - Challenge secret rotates every 5 minutes
    Given a POOL server
    When the challenge secret is 300 seconds old
    Then it should be rotated
    And the previous secret should remain valid for 600 seconds

  @protocol
  Scenario: P03 - HMAC uses constant-time comparison
    Given the POOL protocol specification
    Then section 13.3 should mandate crypto_memneq for HMAC verification
    And prohibit standard memcmp for authentication tags

  @protocol
  Scenario: P04 - Fragment limits are specified
    Given the POOL protocol specification
    Then section 13.4 should specify max 16 concurrent fragment slots
    And 5-second timeout per incomplete fragment
    And LRU eviction when slots are full

  @protocol
  Scenario: P05 - MTU probes are rate-limited
    Given the POOL protocol specification
    Then section 13.5 should limit probes to 1 per second per peer
    And require authentication on probe responses

  @protocol
  Scenario: P06 - Rekey tie-breaking is deterministic
    Given the POOL protocol specification
    Then section 13.6 should define lower session_id wins rekey tie
    And include monotonic epoch numbers

  @protocol
  Scenario: P07 - Config silence means confirmation
    Given the POOL protocol specification
    Then section 13.7 should treat silence as config confirmation
    And require 3 retry attempts with exponential backoff

  @protocol
  Scenario: P08 - Compression oracle risk is documented
    Given the POOL protocol specification
    Then section 13.10 should document CRIME-style attack risk
    And recommend disabling compression for sensitive data

  @protocol
  Scenario: P09 - CRC32 birthday bound is documented
    Given the POOL protocol specification
    Then section 13.11 should document the 2^16 collision bound
    And recommend SHA-256 truncated for large deployments

  @protocol
  Scenario: P10 - INIT packets require timestamps
    Given the POOL protocol specification
    Then section 13.8 should require 64-bit timestamps in INIT
    And reject timestamps outside 30-second window

  @protocol
  Scenario: P11 - Minimum puzzle difficulty is enforced
    Given the POOL protocol specification
    Then section 13.8 should require minimum puzzle difficulty of 16

  @protocol
  Scenario: P12 - Cipher agility roadmap exists
    Given the POOL security specification
    Then section 8 should define cipher suite identifiers
    And negotiation rules for future cipher suites
    And emergency cipher rotation procedure

  @protocol
  Scenario: P13 - Version downgrade prevention
    Given the POOL protocol specification
    Then section 13.9 should require recording peer max version
    And rejecting connections at lower version from known peers
