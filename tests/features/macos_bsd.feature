Feature: macOS/BSD POOL Daemon
  As a macOS or BSD user
  I want to run POOL as a daemon
  So that I can establish secure POOL connections on my platform

  Background:
    Given the POOL daemon binary is built for the current platform

  @macos @bsd
  Scenario: Daemon starts in foreground mode
    When the daemon is started with "--foreground"
    Then the control socket "/var/run/pool.sock" is created
    And the daemon is accepting connections

  @macos
  Scenario: Daemon runs under launchd
    Given the launchd plist is installed at "/Library/LaunchDaemons/"
    When the service is loaded via launchctl
    Then the daemon process is running
    And the control socket "/var/run/pool.sock" is accessible

  @macos @bsd
  Scenario: Connect to a POOL peer via Unix socket
    Given the daemon is running
    When a CONNECT command is sent for "127.0.0.1" port 9253 via the control socket
    Then the response contains a 16-byte session ID
    And the SESSIONS command returns at least 1 active session

  @macos @bsd
  Scenario: CommonCrypto/OpenSSL backend works correctly
    Given the platform crypto library is available
    When an X25519 keypair is generated
    Then the keypair has valid 32-byte components
    When HMAC-SHA256 is computed
    Then the output is a valid 32-byte hash

  @macos @bsd
  Scenario: Daemon stops cleanly on SIGTERM
    Given the daemon is running
    When SIGTERM is sent to the daemon
    Then the daemon exits with code 0
    And the control socket is removed
    And all sessions are closed

  @bsd
  Scenario: Daemon daemonizes correctly
    When the daemon is started with "--daemon"
    Then the PID file "/var/run/poold.pid" is created
    And the daemon is running in the background
    And the control socket is accessible
