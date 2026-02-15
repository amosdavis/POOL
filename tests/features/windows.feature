Feature: Windows POOL Service
  As a Windows user
  I want to run POOL as a Windows service
  So that I can establish secure POOL connections on Windows

  Background:
    Given the Windows POOL service binary is built

  @windows
  Scenario: Service installs and starts
    When the service is installed with "--install"
    Then the service "POOLProtocol" exists in the service manager
    When the service is started
    Then the service status is "running"
    And the named pipe "\\.\pipe\pool_control" is accessible

  @windows
  Scenario: Console mode runs without service installation
    When the service is started in console mode
    Then the named pipe "\\.\pipe\pool_control" is accessible
    And the console outputs "POOL console mode started"

  @windows
  Scenario: Connect to a POOL peer via named pipe
    Given the service is running in console mode
    When a CONNECT command is sent for "127.0.0.1" port 9253
    Then the response contains a 16-byte session ID
    And the SESSIONS command returns at least 1 session

  @windows
  Scenario: BCrypt crypto backend works correctly
    Given the Windows POOL platform library is loaded
    When an X25519 keypair is generated via BCrypt
    Then the public key is 32 bytes
    And the private key is 32 bytes
    When HMAC-SHA256 is computed for "test data" with key "test key"
    Then the HMAC output is 32 bytes

  @windows
  Scenario: Service uninstalls cleanly
    Given the service "POOLProtocol" is installed
    When the service is stopped
    And the service is uninstalled with "--uninstall"
    Then the service "POOLProtocol" no longer exists
