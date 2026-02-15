@bridge
Feature: POOL Bridge Robustness
  The pool_bridge TCP↔POOL proxy must handle resource limits,
  concurrency, and shutdown gracefully.

  Background:
    Given the POOL kernel module is loaded
    And a POOL listener is started on port 9253

  # 2.1 HIGH — Bridge connection limit with no feedback
  @high
  Scenario: Exceeding bridge connection limit notifies the client
    Given a pool_bridge is running in tcp2pool mode on TCP port 8080 to POOL "127.0.0.1" port 9253
    And 256 TCP clients are connected through the bridge
    When a 257th TCP client attempts to connect on port 8080
    Then the 257th client receives a connection refused or reset
    And a warning is logged with the current and maximum bridge count

  # 2.2 HIGH — TOCTOU race in session lookup
  @high
  Scenario: Simultaneous POOL sessions do not create duplicate bridges
    Given a pool_bridge is running in pool2tcp mode on POOL port 9253 to TCP "127.0.0.1" port 8081
    When 10 POOL sessions are established simultaneously
    Then exactly 10 bridge threads are created
    And no duplicate bridges exist for the same session index

  # 2.3 MEDIUM — Detached threads on shutdown
  @medium
  Scenario: Bridge shutdown joins all worker threads
    Given a pool_bridge is running in tcp2pool mode on TCP port 8080 to POOL "127.0.0.1" port 9253
    And 5 TCP clients are actively transferring data through the bridge
    When a SIGTERM signal is sent to the bridge process
    Then all 5 worker threads are joined within 10 seconds
    And no file descriptors are leaked
    And the bridge process exits cleanly

  # 2.4 MEDIUM — Double-close risk
  @medium
  Scenario: TCP peer disconnect during transfer does not cause double-close
    Given a pool_bridge is running in tcp2pool mode on TCP port 8080 to POOL "127.0.0.1" port 9253
    And a TCP client is connected and transferring data through the bridge
    When the TCP client disconnects abruptly mid-transfer
    Then the bridge thread cleans up without errors
    And no double-close warnings occur
    And the bridge connection slot is freed for reuse
