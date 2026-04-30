@tpm_pcr @T3 @runtime_integrity
Feature: T3 Software PCR Measurement Chain
  As a POOL node operator
  I want a tamper-evident software measurement chain (PCR)
  So that I can detect post-load modifications to the POOL module state
  and provide a T3 hook for future hardware TPM integration

  Background:
    Given the POOL kernel module is loaded
    And the procfs entry "/proc/pool/tpm_pcr" exists

  @smoke
  Scenario: PCR entry is present and contains hex-encoded data
    When I read "/proc/pool/tpm_pcr"
    Then the output contains "PCR[0]:"
    And the PCR value is a 64-character lowercase hexadecimal string

  @smoke
  Scenario: PCR value changes after a crypto spot-check
    Given I record the current PCR value
    When the crypto spot-check runs
    Then the PCR value is different from the recorded value

  Scenario: PCR extends on each journal entry
    Given I record the current PCR value
    And I record the current extend count
    When a journal event is appended
    Then the PCR value changes
    And the extend count increments by 1

  Scenario: PCR extend count increases monotonically
    Given I record the current extend count as N
    When 3 journal events are appended
    Then the extend count is at least N + 3

  Scenario: PCR is non-zero after module init
    When I read the PCR value at module startup
    Then the PCR value is not all zeros

  Scenario: PCR value format is stable across multiple reads
    When I read "/proc/pool/tpm_pcr" five times consecutively without new events
    Then all five reads return the same PCR value

  @T3 @attestation
  Scenario: PCR procfs entry carries software TPM label
    When I read "/proc/pool/tpm_pcr"
    Then the output contains "Software measurement chain"
    And the output contains "extends:"
    And the output contains "T3 hook"

  @T3 @attestation
  Scenario: Session establishment extends PCR
    Given I record the current extend count
    When a POOL session is established
    Then the extend count increments by at least 1
    And the PCR value changes

  Scenario: Cleanup removes procfs entry
    When the POOL kernel module is unloaded
    Then the procfs entry "/proc/pool/tpm_pcr" no longer exists
