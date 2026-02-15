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
