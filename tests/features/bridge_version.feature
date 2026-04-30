@bridge_version @cross_version @D
Feature: pool_bridge Cross-Version Protocol Adapter
  As a POOL operator bridging different protocol versions
  I want pool_bridge to support a --pool-version flag
  So that TCP clients can be forwarded to POOL endpoints using v1 or PQC v2

  Background:
    Given the pool_bridge binary is built

  @smoke
  Scenario: Default pool_bridge version is v1
    When I run pool_bridge with no --pool-version flag
    Then the POOL connect request uses protocol version 1

  @smoke
  Scenario: --pool-version 1 explicitly requests POOL v1
    When I run pool_bridge with "--pool-version 1"
    Then the POOL connect request uses protocol version 1
    And no warning is emitted about unsupported versions

  Scenario: --pool-version 2 requests PQC hybrid v2
    When I run pool_bridge with "--pool-version 2"
    Then the POOL connect request uses protocol version 2
    And a log message is emitted indicating PQC hybrid mode

  Scenario: --pool-version 0 is rejected
    When I run pool_bridge with "--pool-version 0"
    Then pool_bridge exits with a non-zero status
    And the error output contains "--pool-version must be 1 or 2"

  Scenario: --pool-version 3 is rejected
    When I run pool_bridge with "--pool-version 3"
    Then pool_bridge exits with a non-zero status
    And the error output contains "--pool-version must be 1 or 2"

  Scenario: --pool-version 99 is rejected
    When I run pool_bridge with "--pool-version 99"
    Then pool_bridge exits with a non-zero status
    And the error output contains "--pool-version must be 1 or 2"

  @kernel_validation
  Scenario: Kernel rejects connect request with version > 2
    Given the POOL kernel module is loaded
    When a POOL_IOC_CONNECT ioctl is issued with pool_version = 3
    Then the ioctl returns -EINVAL

  @kernel_validation
  Scenario: Kernel accepts connect request with version = 0 (treated as v1)
    Given the POOL kernel module is loaded
    When a POOL_IOC_CONNECT ioctl is issued with pool_version = 0
    Then the ioctl does not return -EINVAL due to version

  @kernel_validation
  Scenario: Kernel accepts connect request with version = 1
    Given the POOL kernel module is loaded
    When a POOL_IOC_CONNECT ioctl is issued with pool_version = 1
    Then the ioctl does not return -EINVAL due to version

  @kernel_validation
  Scenario: Kernel logs PQC version request
    Given the POOL kernel module is loaded
    When a POOL_IOC_CONNECT ioctl is issued with pool_version = 2
    Then the kernel log contains "PQC v2 requested"

  Scenario: usage output documents --pool-version flag
    When I run pool_bridge with no arguments
    Then the usage text contains "--pool-version"
    And the usage text describes version 1 and version 2

  @backward_compatibility
  Scenario: Existing pool_bridge invocations without --pool-version continue to work
    Given I have a pool_bridge invocation without --pool-version
    When I run it
    Then pool_bridge starts normally with version 1
    And the behavior is identical to the previous release
