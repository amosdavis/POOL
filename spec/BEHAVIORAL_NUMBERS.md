# POOL Behavioral Numbers Specification

## Protected Orchestrated Overlay Link — Behavioral Number System

**Scope:** Provides a deterministic, human-readable encoding of cryptographic
function behavior for attestation, audit, and cross-peer verification.

**Classification:** Design specification. This document defines the Behavioral
Number primitive that all POOL implementations MAY use to satisfy Tenets T2
and T5 of `RUNTIME_INTEGRITY.md`.

---

## 1. Motivation

A SHA-256 checksum of a binary gives a *structural fingerprint* — it tells you
whether the bytes of a program changed. It says nothing about whether the
program still computes correctly.

A **Behavioral Number (BN)** is different. It is derived from what a function
*does* — the actual outputs it produces for a fixed set of known-good test
vectors. If the function's behavior changes (even if its bytes remain the same,
as in a hardware-overlay attack), the BN changes.

> "Verify what code **does**, not what it **is**." — Tenet T2

---

## 2. Formal Definition

For a deterministic function `f` and a fixed ordered set of test vector inputs
`V = {v₁, v₂, …, vₙ}`:

```
BN(f, V) = balternary( SHA-256( f(v₁) ‖ f(v₂) ‖ … ‖ f(vₙ) ) )
```

Where:
- `f(vᵢ)` is the byte output of applying `f` to test vector input `vᵢ`
- `‖` is byte concatenation
- `SHA-256(…)` produces a 32-byte digest
- `balternary(…)` converts the digest (interpreted as a big-endian unsigned
  256-bit integer) to balanced ternary

---

## 3. Balanced Ternary Encoding

### 3.1 Digit Set

Balanced ternary uses three digit values:

| Digit | Numeric value | Notes |
|-------|--------------|-------|
| `1`   | +1           |       |
| `0`   |  0           |       |
| `T`   | −1           | Knuth / Setun convention |

### 3.2 Conversion Algorithm (Integer → Balanced Ternary)

```
Input:  n  (non-negative big integer)
Output: string over {T, 0, 1}, MST-first, no leading zeros
        (exception: the value zero is encoded as "0")

digits ← empty list
while n ≠ 0:
    r ← n mod 3             // r ∈ {0, 1, 2}
    if r = 0:
        digits ← digits + ['0']
        n ← n / 3
    if r = 1:
        digits ← digits + ['1']
        n ← (n − 1) / 3
    if r = 2:               // 2 ≡ −1 (mod 3)
        digits ← digits + ['T']
        n ← (n + 1) / 3
reverse(digits)
return join(digits)
```

### 3.3 Conversion Algorithm (Balanced Ternary → Integer)

```
Input:  s  (string over {T, 0, 1})
Output: integer value

n ← 0
for each character c in s:
    n ← n × 3
    if c = '1': n ← n + 1
    if c = 'T': n ← n − 1
return n
```

### 3.4 Properties

| Property | Description |
|----------|-------------|
| **Deterministic** | Same input → identical BN on all platforms |
| **Avalanche** | A 1-bit change in any `f(vᵢ)` output changes ~half the trits |
| **Compact** | A 256-bit SHA-256 digest requires at most 163 trits |
| **Signed-ready** | Negation is trivially `T↔1`, `0↔0` (not used here, but available) |
| **No padding** | BN is a number, not a fixed-width field; leading zeros are omitted |

**Size bound:** A 256-bit unsigned integer requires at most 163 trits because:

```
(3^163 − 1) / 2  ≈  2.95 × 10^77  >  2^256  ≈  1.16 × 10^77
(3^162 − 1) / 2  ≈  9.83 × 10^76  <  2^256
```

Therefore the BN of any SHA-256 digest is always **≤ 163 trits**.

### 3.5 Why Balanced Ternary (Not Decimal, Not Hex)

| Encoding | Radix economy | Sign support | Char set | Ambiguity |
|----------|--------------|-------------|----------|-----------|
| Hex      | 4.34 | No  | 0–9, a–f | case (a vs A) |
| Decimal  | 3.32 | No  | 0–9 | none |
| Balanced ternary | **1.00** | Yes | T, 0, 1 | none |

Balanced ternary achieves the theoretical minimum radix economy (the radix
closest to *e* = 2.718… is 3). BNs encoded in balanced ternary are shorter
than decimal for large values:

- 256-bit value in decimal: up to 77 digits
- 256-bit value in balanced ternary: up to 163 trits

While balanced ternary strings are longer in character count, each trit carries
log₂(3) ≈ 1.585 bits of information, outperforming binary-grouped bases (hex
carries exactly 4 bits; decimal carries ~3.32 bits per digit). The
sign-preserving property enables efficient tree arithmetic in audit logs.

---

## 4. Reference Behavioral Numbers

All reference BNs are computed using POOL's canonical reference tool
(`tools/pool_behavioral_number`). Test vectors are taken exclusively from IETF
RFCs so any independent implementation can reproduce them.

The BN for a single-vector primitive is:
```
BN = balternary( SHA-256( <primitive output> ) )
```

### 4.1 HMAC-SHA256 — RFC 4231 Test Case 2

```
Key:    "Jefe"  (4 bytes, ASCII)
Data:   "what do ya want for nothing?"  (28 bytes, ASCII)

HMAC output (hex):
  5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843

SHA-256(HMAC output):
  86ea816be859ea16764f6371c1b0e0b5577efb5e6e72b20ed5f683c503f8e80f

Behavioral Number (162 trits):
  10T1011T1T1TTT001TT0T0101T10T1011111T0100T01T000T00011TT1T1TT0T01
  TT1TTT1T111T00T01011010T0000T0T01T1T0T1010001T00110T11100TT1TT1010
  TTTTT1TT11T11111T10T1T1T1T00TT0
```

### 4.2 ChaCha20-Poly1305 — RFC 7539 §2.8.2

```
Key (hex):    808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
Nonce (hex):  070000004041424344454647
AAD (hex):    50515253c0c1c2c3c4c5c6c7
Plaintext:    "Ladies and Gentlemen of the class of '99: If I could offer
               you only one tip for the future, sunscreen would be it."

Ciphertext+Tag (hex):
  d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6
  3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36
  92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3
  ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691

SHA-256(Ciphertext+Tag):
  4e54427e462f3beb69677d39865c5da8d57f603a85f7bf71368dce8ec9b9933c

Behavioral Number (162 trits):
  1TT0TT101TT1T1001T1T01T01T110110T1T0TT0T100T0101111000TT0T01T101T
  1T00T0T0TT0T111110101111T0T0T11T0T10TT0TT1010T1011T10T10001T01100
  T0T1TT0100T1T0T00T1T1TTT0T0011TT
```

### 4.3 HKDF-SHA256 — RFC 5869 Test Case 1

```
IKM  (hex): 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b  (22 bytes)
Salt (hex): 000102030405060708090a0b0c  (13 bytes)
Info (hex): f0f1f2f3f4f5f6f7f8f9  (10 bytes)
L = 42 bytes

OKM (hex):
  3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf
  34007208d5b887185865

SHA-256(OKM):
  b421bf493199866037dfe54b7dc67467326bad6055cdb78e48525eb1db5841a8

Behavioral Number (162 trits):
  11T1TT01T000010TTT1T1T1TT00TT0000TT101TTT101T000T0100101111T1T0T1
  10000010T1TT000000001000000111T001T11011TT0111000TTTT1001T1111000T
  0T0100T01T1T011011T10T0T01T1001
```

### 4.4 X25519 — RFC 7748 §6.1

```
Alice's private key (hex):
  77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a

Bob's public key (hex):
  de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f

Shared secret = X25519(alice_priv, bob_pub) (hex):
  4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742

SHA-256(Shared secret):
  dead45a1d43d6902aa9240b43c0d75a0b5fc750660590d6d45461cbfc4010684

Behavioral Number (163 trits):
  1TTTT1111T101TT11T0T0101001T1T000TTT1T110011T001111011TT011000000
  0TTT1T011T101T1TT01011TTT0001T1T1T0TT11T0110T010T1T10TT0TT111T10T
  10T010T0TTT0TT10T011000110T1100T0
```

---

## 5. Reference Tool

`tools/pool_behavioral_number` is a standalone Go CLI that computes BNs for
all four POOL crypto primitives.

### 5.1 Usage

```
pool_behavioral_number <primitive>
pool_behavioral_number --verify <expected_bn> <primitive>
```

**Primitives:** `hmac` | `aead` | `hkdf` | `ecdh` | `all`

### 5.2 Output Format

For each primitive, three fields are printed:

```
<primitive>
  output: <hex encoding of the raw crypto output>
  sha256: <hex encoding of SHA-256(output)>
  bn:     <balanced ternary BN string>
```

### 5.3 Attestation Mode (`--verify`)

When `--verify <expected_bn>` is supplied:
- The tool exits **0** if the computed BN equals the expected BN.
- The tool exits **1** if they differ, printing the discrepancy to stderr.

This enables integration into deployment scripts:
```sh
pool_behavioral_number --verify "10T1011T..." hmac || { echo "HMAC tampered"; exit 1; }
```

---

## 6. Integration with Runtime Integrity Tenets

### 6.1 T2: Behavioral Verification

The BN is a concrete implementation of T2. Rather than checking the bytes of
`pool_crypto.c`, an operator:
1. Compiles and runs `pool_behavioral_number all` on a trusted reference build.
2. Stores the four BN strings as known-good values.
3. Runs `pool_behavioral_number --verify <bn> <primitive>` on the deployed system.
4. A mismatch proves the deployed crypto function behaves differently from the
   reference — regardless of whether the binary bytes appear unchanged.

### 6.2 T5: Cryptographic Execution Proofs

The BN of a crypto primitive is itself a cryptographic proof:
- It is derived from the actual outputs of the function, not from its code.
- Two independent parties who compute the same BN using the same RFC test
  vectors have proven they are running the same behavior, without sharing keys
  or session state.
- BN strings can be embedded as leaf values in Merkle audit chains.

### 6.3 Relationship to `pool_crypto_spot_check`

`pool_crypto_spot_check` (in `linux/pool_crypto.c`) is a **kernel-space
runtime check** — it verifies behavior inline during operation.

The BN tool is an **out-of-band attestation artifact** — it verifies behavior
from the outside, before or alongside deployment. They are complementary.

| Mechanism | Where | When | Output |
|-----------|-------|------|--------|
| `pool_crypto_spot_check` | Kernel (in-process) | Periodic, during heartbeat | pass/fail |
| `pool_behavioral_number` | Userspace (external) | At deploy time or on demand | BN string (attestable) |

---

## 7. Failure Mode Coverage

This mechanism directly mitigates:

| Failure mode | How BN helps |
|---|---|
| RT-C01 (binary mod after insmod) | BN run post-load detects behavioral change |
| RT-C02 (HMAC bypass) | HMAC BN would change if HMAC produces wrong output |
| RT-C05 (HKDF replacement) | HKDF BN detects non-RFC-compliant derivation |
| RT-A04 (telemetry manipulation) | BN provides an independent behavioral baseline |
