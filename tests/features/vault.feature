@vault
Feature: POOL Vault Encrypted File Transfer
  The pool_vault application provides encrypted distributed file
  sharing over POOL. It must handle file push/pull, error conditions,
  and concurrent transfers correctly.

  Background:
    Given the POOL kernel module is loaded
    And a POOL listener is started on port 9253

  # 4.1 CRITICAL — Basic push and pull
  @critical
  Scenario: Push a file to a vault server and pull it back
    Given a vault server is serving directory "/tmp/pool_vault_test"
    When I push a 1024-byte test file to the vault server
    Then the push completes successfully
    And the file exists on the vault server at the expected path
    When I pull the file back from the vault server
    Then the pull completes successfully
    And the pulled file matches the original byte-for-byte

  # 4.2 CRITICAL — Large file transfer
  @critical
  Scenario: Push a large file requiring multiple chunks
    Given a vault server is serving directory "/tmp/pool_vault_test"
    When I push a 1048576-byte test file to the vault server
    Then the push completes successfully
    And the file exists on the vault server at the expected path

  # 4.3 HIGH — File not found on pull
  @high
  Scenario: Pull a nonexistent file returns an error
    Given a vault server is serving directory "/tmp/pool_vault_test"
    When I attempt to pull a nonexistent file "/no_such_file.dat"
    Then the pull fails with an error message
    And no partial file is created locally

  # 4.4 HIGH — Permission denied on push
  @high
  Scenario: Push to a read-only directory returns an error
    Given a vault server is serving directory "/tmp/pool_vault_readonly"
    And the vault serve directory is read-only
    When I attempt to push a file to the vault server
    Then the push fails with a permission error

  # 4.5 HIGH — Zero-byte file
  @high
  Scenario: Push and pull a zero-byte file
    Given a vault server is serving directory "/tmp/pool_vault_test"
    When I push a 0-byte test file to the vault server
    Then the push completes successfully
    When I pull the file back from the vault server
    Then the pull completes successfully
    And the pulled file is empty

  # 4.6 MEDIUM — Status command
  @medium
  Scenario: Vault status reports security guarantees
    When I run pool_vault status
    Then the output includes "ChaCha20-Poly1305"
    And the output includes "HMAC-SHA256"
    And the output includes "X25519"
