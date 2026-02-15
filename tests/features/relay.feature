@relay
Feature: POOL Relay Operator Incentives
  The pool_relay daemon must correctly track bandwidth reciprocity,
  maintain generosity scores, handle peer enrollment, persist state,
  and enforce priority routing based on contribution.

  Background:
    Given the POOL kernel module is loaded
    And a POOL listener is started on port 9253

  # 5.1 CRITICAL — Relay starts and listens
  @critical
  Scenario: Relay daemon starts and accepts connections
    When I start pool_relay
    Then the relay daemon is listening on port 9254
    And pool_relay status reports a generosity score

  # 5.2 CRITICAL — Peer enrollment
  @critical
  Scenario: Enrolling with a peer relay establishes bidirectional peering
    Given a relay daemon is running on port 9254
    When I enroll with a peer relay at "127.0.0.1"
    Then the enrollment completes successfully
    And pool_relay status shows the peer in the peer list

  # 5.3 HIGH — Generosity score calculation
  @high
  Scenario: Generosity score reflects relayed vs consumed traffic
    Given a relay daemon is running on port 9254
    And the relay has relayed 200 MB for peers
    And the relay has consumed 100 MB from peers
    Then pool_relay status reports a generosity score of approximately 2.0

  # 5.4 HIGH — Score exchange between peers
  @high
  Scenario: Relay exchanges scores with peers periodically
    Given a relay daemon is running on port 9254
    And a peer relay is running
    When 35 seconds elapse
    Then the peer has received an updated score from this relay

  # 5.5 HIGH — State persistence across restart
  @high
  Scenario: Relay state is preserved across daemon restart
    Given a relay daemon is running on port 9254
    And the relay has relayed 50 MB for peers
    When the relay daemon is stopped
    And the relay daemon is restarted
    Then pool_relay status shows the previously relayed 50 MB

  # 5.6 MEDIUM — Graceful shutdown
  @medium
  Scenario: Relay saves state and exits on SIGTERM
    Given a relay daemon is running on port 9254
    When SIGTERM is sent to the relay daemon
    Then the relay daemon exits within 5 seconds
    And the state file exists at "/var/lib/pool/relay_state.dat"

  # 5.7 MEDIUM — Status command output format
  @medium
  Scenario: Relay status provides complete operational information
    Given a relay daemon is running on port 9254
    When I run pool_relay status
    Then the output includes "Generosity score"
    And the output includes "Total relayed"
    And the output includes "Active peers"
