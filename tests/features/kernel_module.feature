@kernel
Feature: POOL Kernel Module Robustness
  The POOL kernel module must handle edge cases gracefully without
  crashing, deadlocking, leaking resources, or silently losing data.

  Background:
    Given the POOL kernel module is loaded
    And a POOL listener is started on port 9253

  # 1.1 CRITICAL — Module unload crash
  @critical
  Scenario: Module unloads cleanly with active sessions
    Given a POOL session is established to "127.0.0.1" port 9253
    When the POOL kernel module is unloaded
    Then the module unload completes within 5 seconds
    And no kernel panic or deadlock occurs
    And all session resources are freed

  # 1.2 CRITICAL — Fragment offset truncation
  @critical
  Scenario: Sending data larger than 65535 bytes returns an error
    Given a POOL session is established to "127.0.0.1" port 9253
    When I attempt to send 70000 bytes on the session
    Then the send returns error code EMSGSIZE
    And no data is silently truncated

  Scenario: Sending data at exactly 65535 bytes succeeds
    Given a POOL session is established to "127.0.0.1" port 9253
    When I attempt to send 65535 bytes on the session
    Then the send succeeds
    And all 65535 bytes are received intact

  # 1.3 CRITICAL — No handshake timeout
  @critical
  Scenario: Handshake times out when peer does not respond
    Given a TCP listener that accepts but never sends POOL packets on port 9254
    When I attempt a POOL connection to "127.0.0.1" port 9254
    Then the connection attempt fails within 15 seconds
    And the session slot is freed
    And an appropriate error is returned

  # 1.4 HIGH — No fragment reassembly timeout
  @high
  Scenario: Incomplete fragments are cleaned up after timeout
    Given a POOL session is established to "127.0.0.1" port 9253
    When the peer sends the first fragment of a message but no subsequent fragments
    Then the fragment buffer is freed after 5 seconds
    And the fragment slot is available for new messages

  # 1.4b HIGH — Fragment reassembly produces correct data
  @high
  Scenario: Fragmented message is reassembled correctly
    Given a POOL session is established to "127.0.0.1" port 9253
    When the peer sends a 50000-byte message that requires fragmentation
    Then the receiver reassembles all fragments
    And all 50000 bytes are received intact

  # 1.5 HIGH — Silent data truncation on recv
  @high
  Scenario: Receiving into a buffer smaller than the message returns EMSGSIZE
    Given a POOL session is established to "127.0.0.1" port 9253
    And the peer sends a 1000-byte message
    When I attempt to receive into a 500-byte buffer
    Then the receive returns error code EMSGSIZE
    And the required buffer size is reported as 1000
    And the message remains in the receive queue

  Scenario: Retrying receive with correct buffer size succeeds
    Given a POOL session is established to "127.0.0.1" port 9253
    And the peer sends a 1000-byte message
    And I attempted to receive into a 500-byte buffer and got EMSGSIZE
    When I retry the receive with a 1000-byte buffer
    Then the receive succeeds
    And all 1000 bytes match the original message

  # 1.6 HIGH — Listen backlog too small
  @high
  Scenario: 20 simultaneous connections all succeed
    Given a POOL listener is started on port 9255
    When 20 clients connect simultaneously to port 9255
    Then all 20 connections are established successfully

  # 1.7 HIGH — No TCP keepalive
  @high
  Scenario: Dead peer is detected and session cleaned up
    Given a POOL session is established to "127.0.0.1" port 9253
    When the peer process is killed without sending CLOSE
    Then the session is detected as dead within 120 seconds
    And the session slot is freed

  # 1.8 MEDIUM — Session limit with no feedback
  @medium
  Scenario: Exceeding session limit returns ENOSPC
    Given 64 POOL sessions are established
    When I attempt to establish a 65th session
    Then the connection returns error code ENOSPC
    And a warning is logged indicating the session limit

  # 1.9 MEDIUM — Loss rate telemetry
  @medium
  Scenario: Loss rate telemetry tracks sequence gaps
    Given a POOL session is established to "127.0.0.1" port 9253
    When 100 packets are sent on the session
    Then the telemetry loss_rate_ppm is updated
    And the loss rate is a valid parts-per-million value

  # 1.10 MEDIUM — Raw IP proto 253 transport
  @medium
  Scenario: Raw IP protocol 253 transport with TCP fallback
    Given the POOL kernel module is loaded
    And the transport mode is set to "auto"
    When a POOL listener is started on port 9253
    Then the listener accepts connections via TCP
    And the raw IP proto 253 listener is started or skipped gracefully

  # 1.11 MEDIUM — Peer discovery via multicast
  @medium
  Scenario: Peer discovery announces on multicast group
    Given the POOL kernel module is loaded
    When a POOL listener is started on port 9253
    Then the peer discovery service is running
    And the multicast group 239.253.0.1 is joined

  @medium
  Scenario: Discovered peers are added to peer table
    Given the POOL kernel module is loaded
    And a POOL listener is started on port 9253
    When a peer announce is received from "192.168.1.10"
    Then the peer table contains at least 1 peer
    And the peer "192.168.1.10" has a valid public key

  @medium
  Scenario: Stale peers are expired after timeout
    Given the POOL kernel module is loaded
    And a POOL listener is started on port 9253
    When a peer announce is received from "192.168.1.20"
    And no announce is received for 120 seconds
    Then the peer "192.168.1.20" is removed from the table

  # 1.12 MEDIUM — Post-quantum hybrid key exchange
  @medium
  Scenario: Hybrid X25519 + ML-KEM-768 key exchange
    Given the POOL kernel module is loaded
    And post-quantum crypto is enabled
    When a v2 handshake is initiated with a peer
    Then the shared secret combines X25519 and ML-KEM components
    And the session uses the hybrid shared secret

  @medium
  Scenario: Version negotiation falls back to v1
    Given the POOL kernel module is loaded
    And post-quantum crypto is enabled
    When a peer responds with v1 CHALLENGE
    Then the session falls back to X25519-only key exchange
    And the connection is established successfully

  @medium
  Scenario: ML-KEM-768 encaps/decaps round-trip
    Given the POOL kernel module is loaded
    When an ML-KEM-768 keypair is generated
    And encapsulation is performed with the public key
    And decapsulation is performed with the secret key
    Then both sides derive the same shared secret
