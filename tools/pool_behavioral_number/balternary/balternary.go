// Package balternary converts non-negative big integers to and from balanced
// ternary. Balanced ternary uses three digit values:
//
//	'1'  →  +1
//	'0'  →   0
//	'T'  →  -1  (Knuth / Setun convention)
//
// Strings are big-endian (most-significant trit first) with no leading zeros
// except for the value zero itself, which is represented as "0".
//
// A 256-bit SHA-256 digest fits in at most 163 trits:
//
//	(3^163 − 1)/2 ≈ 2.95 × 10^77  >  2^256 ≈ 1.16 × 10^77
package balternary

import (
	"fmt"
	"math/big"
	"strings"
)

var (
	bigZero  = big.NewInt(0)
	bigOne   = big.NewInt(1)
	bigTwo   = big.NewInt(2)
	bigThree = big.NewInt(3)
)

// Encode converts n (non-negative) to a balanced ternary string.
// Panics if n is negative.
func Encode(n *big.Int) string {
	if n.Sign() < 0 {
		panic("balternary.Encode: negative input not supported")
	}
	if n.Sign() == 0 {
		return "0"
	}

	work := new(big.Int).Set(n)
	rem := new(big.Int)
	digits := make([]byte, 0, 165)

	for work.Sign() != 0 {
		work.DivMod(work, bigThree, rem)
		r := rem.Int64() // r ∈ {0, 1, 2}
		switch r {
		case 0:
			digits = append(digits, '0')
		case 1:
			digits = append(digits, '1')
		case 2:
			// 2 ≡ −1 (mod 3): emit T, carry +1
			digits = append(digits, 'T')
			work.Add(work, bigOne)
		}
	}

	// Digits were collected LST-first; reverse for big-endian output.
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	return string(digits)
}

// Decode converts a balanced ternary string back to a non-negative big integer.
// Returns an error if the string is empty, contains invalid characters, or
// represents a negative number (leading T trit).
func Decode(s string) (*big.Int, error) {
	if s == "" {
		return nil, fmt.Errorf("balternary.Decode: empty string")
	}
	result := new(big.Int)
	for _, c := range s {
		result.Mul(result, bigThree)
		switch c {
		case '1':
			result.Add(result, bigOne)
		case '0':
			// nothing
		case 'T':
			result.Sub(result, bigOne)
		default:
			return nil, fmt.Errorf("balternary.Decode: invalid character %q", c)
		}
	}
	if result.Sign() < 0 {
		return nil, fmt.Errorf("balternary.Decode: decoded value is negative")
	}
	return result, nil
}

// Validate returns nil if s is a valid balanced ternary string over {T, 0, 1}
// with at most maxTrits characters.
func Validate(s string, maxTrits int) error {
	if s == "" {
		return fmt.Errorf("balternary: empty string")
	}
	if len(s) > maxTrits {
		return fmt.Errorf("balternary: string length %d exceeds limit %d", len(s), maxTrits)
	}
	for i, c := range s {
		if c != 'T' && c != '0' && c != '1' {
			return fmt.Errorf("balternary: invalid character %q at position %d", c, i)
		}
	}
	if strings.ContainsAny(s, "ABCDEFGHIJKLMNOPQRSUVWXYZ") {
		return fmt.Errorf("balternary: unexpected uppercase letter")
	}
	return nil
}

// MaxTritsForBits returns the maximum number of trits needed to represent any
// unsigned integer with the given bit width.
//
// Formula: ceil(bits × log₃(2)) + 1 safety margin.
// For 256 bits this returns 163.
func MaxTritsForBits(bits int) int {
	// log₃(2) = log(2)/log(3) ≈ 0.63093
	// We use integer arithmetic: multiply bits by 100000 and divide by 158496
	// (100000 × log₂(3) ≈ 158496) to avoid floating point.
	trits := (bits*100000 + 158495) / 158496
	return trits + 1 // +1 safety margin
}
