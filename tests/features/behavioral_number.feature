Feature: POOL Behavioral Numbers
  As a POOL operator
  I need to compute Behavioral Numbers (BNs) for POOL cryptographic primitives
  So that I can verify function behavior, not just binary structure, per Tenets T2 and T5

  # A Behavioral Number is:
  #   BN(f, V) = balternary( SHA-256( f(v₁) ‖ f(v₂) ‖ … ‖ f(vₙ) ) )
  # where balternary uses digits T (−1), 0, 1 and is MST-first with no padding.
  # A 256-bit SHA-256 digest fits in at most 163 trits.

  Background:
    Given the pool_behavioral_number tool is built

  # ---- Output validity ----

  @behavioral-number @charset
  Scenario: HMAC BN contains only valid balanced ternary digits
    When I compute the behavioral number for "hmac"
    Then the bn field should contain only the characters "T", "0", and "1"
    And the bn field length should be at most 163

  @behavioral-number @charset
  Scenario: AEAD BN contains only valid balanced ternary digits
    When I compute the behavioral number for "aead"
    Then the bn field should contain only the characters "T", "0", and "1"
    And the bn field length should be at most 163

  @behavioral-number @charset
  Scenario: HKDF BN contains only valid balanced ternary digits
    When I compute the behavioral number for "hkdf"
    Then the bn field should contain only the characters "T", "0", and "1"
    And the bn field length should be at most 163

  @behavioral-number @charset
  Scenario: ECDH BN contains only valid balanced ternary digits
    When I compute the behavioral number for "ecdh"
    Then the bn field should contain only the characters "T", "0", and "1"
    And the bn field length should be at most 163

  # ---- Reference values (RFC test vectors) ----

  @behavioral-number @reference
  Scenario: HMAC BN matches RFC 4231 Test Case 2 reference value
    When I compute the behavioral number for "hmac"
    Then the output hex should be "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    And the sha256 hex should be "86ea816be859ea16764f6371c1b0e0b5577efb5e6e72b20ed5f683c503f8e80f"
    And the bn field should be "10T1011T1T1TTT001TT0T0101T10T1011111T0100T01T000T00011TT1T1TT0T01TT1TTT1T111T00T01011010T0000T0T01T1T0T1010001T00110T11100TT1TT1010TTTTT1TT11T11111T10T1T1T1T00TT0"

  @behavioral-number @reference
  Scenario: AEAD BN matches RFC 7539 Section 2.8.2 reference value
    When I compute the behavioral number for "aead"
    Then the sha256 hex should be "4e54427e462f3beb69677d39865c5da8d57f603a85f7bf71368dce8ec9b9933c"
    And the bn field should be "1TT0TT101TT1T1001T1T01T01T110110T1T0TT0T100T0101111000TT0T01T101T1T00T0T0TT0T111110101111T0T0T11T0T10TT0TT1010T1011T10T10001T01100T0T1TT0100T1T0T00T1T1TTT0T0011TT"

  @behavioral-number @reference
  Scenario: HKDF BN matches RFC 5869 Test Case 1 reference value
    When I compute the behavioral number for "hkdf"
    Then the sha256 hex should be "b421bf493199866037dfe54b7dc67467326bad6055cdb78e48525eb1db5841a8"
    And the bn field should be "11T1TT01T000010TTT1T1T1TT00TT0000TT101TTT101T000T0100101111T1T0T110000010T1TT000000001000000111T001T11011TT0111000TTTT1001T1111000T0T0100T01T1T011011T10T0T01T1001"

  @behavioral-number @reference
  Scenario: ECDH BN matches RFC 7748 Section 6.1 reference value
    When I compute the behavioral number for "ecdh"
    Then the output hex should be "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    And the sha256 hex should be "dead45a1d43d6902aa9240b43c0d75a0b5fc750660590d6d45461cbfc4010684"
    And the bn field should be "1TTTT1111T101TT11T0T0101001T1T000TTT1T110011T001111011TT0110000000TTT1T011T101T1TT01011TTT0001T1T1T0TT11T0110T010T1T10TT0TT111T10T10T010T0TTT0TT10T011000110T1100T0"

  # ---- Determinism ----

  @behavioral-number @determinism
  Scenario: HMAC BN is identical on repeated runs
    When I compute the behavioral number for "hmac"
    And I compute the behavioral number for "hmac" again
    Then both bn fields should be identical

  @behavioral-number @determinism
  Scenario: All primitive BNs are identical on repeated runs
    When I compute the behavioral number for "all"
    And I compute the behavioral number for "all" again
    Then all bn fields from both runs should be identical

  # ---- Hex / balanced-ternary round-trip consistency ----

  @behavioral-number @roundtrip
  Scenario: HMAC BN and sha256 hex represent the same integer
    When I compute the behavioral number for "hmac"
    Then the bn field decoded as balanced ternary should equal the sha256 hex decoded as a big integer

  @behavioral-number @roundtrip
  Scenario: ECDH BN and sha256 hex represent the same integer
    When I compute the behavioral number for "ecdh"
    Then the bn field decoded as balanced ternary should equal the sha256 hex decoded as a big integer

  # ---- all subcommand ----

  @behavioral-number @all
  Scenario: all subcommand produces exactly four primitives
    When I compute the behavioral number for "all"
    Then the output should contain entries for "hmac", "aead", "hkdf", and "ecdh"

  @behavioral-number @all
  Scenario: all subcommand primitive BNs match individual runs
    When I compute the behavioral number for "all"
    And I separately compute the behavioral number for "hmac"
    Then the hmac bn from the "all" run should match the individual "hmac" bn

  # ---- --verify flag ----

  @behavioral-number @verify
  Scenario: verify exits zero when the expected BN matches
    When I verify the behavioral number for "hmac" with the correct expected BN
    Then the exit code should be 0

  @behavioral-number @verify
  Scenario: verify exits non-zero when the expected BN does not match
    When I verify the behavioral number for "hmac" with an incorrect expected BN "wrong0T1"
    Then the exit code should be non-zero
    And stderr should contain "VERIFY FAILED"
