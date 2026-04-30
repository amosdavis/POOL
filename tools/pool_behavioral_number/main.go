// pool_behavioral_number computes the Behavioral Number (BN) of each POOL
// cryptographic primitive.
//
// A Behavioral Number is:
//
//	BN(f, V) = balternary( SHA-256( f(v₁) ‖ f(v₂) ‖ … ‖ f(vₙ) ) )
//
// where f is a crypto primitive, V is a fixed set of RFC test vectors, ‖ is
// byte concatenation, and balternary() converts the digest to balanced ternary
// (digits T=−1, 0, 1; MST-first; no padding).
//
// Usage:
//
//	pool_behavioral_number <primitive>
//	pool_behavioral_number --verify <expected_bn> <primitive>
//
// Primitives: hmac | aead | hkdf | ecdh | all
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/pool-protocol/pool/tools/behavioral-number/balternary"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// result holds the output of one BN computation.
type result struct {
	Primitive  string
	OutputHex  string
	DigestHex  string
	BN         string
}

// ---- RFC test vectors --------------------------------------------------------

// hmacVector computes HMAC-SHA256 using RFC 4231 Test Case 2:
//
//	key  = "Jefe"
//	data = "what do ya want for nothing?"
func hmacVector() ([]byte, error) {
	key  := []byte("Jefe")
	data := []byte("what do ya want for nothing?")
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// aeadVector computes ChaCha20-Poly1305 encryption using RFC 7539 §2.8.2.
func aeadVector() ([]byte, error) {
	key := mustDecodeHex(
		"808182838485868788898a8b8c8d8e8f" +
			"909192939495969798999a9b9c9d9e9f",
	)
	nonce := mustDecodeHex("070000004041424344454647")
	aad   := mustDecodeHex("50515253c0c1c2c3c4c5c6c7")
	plain := []byte(
		"Ladies and Gentlemen of the class of '99: " +
			"If I could offer you only one tip for the future, " +
			"sunscreen would be it.",
	)

	ciph, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	ct := ciph.Seal(nil, nonce, plain, aad)
	return ct, nil
}

// hkdfVector derives 42 bytes using HKDF-SHA256 with RFC 5869 Test Case 1.
func hkdfVector() ([]byte, error) {
	ikm  := mustDecodeHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt := mustDecodeHex("000102030405060708090a0b0c")
	info := mustDecodeHex("f0f1f2f3f4f5f6f7f8f9")

	r := hkdf.New(sha256.New, ikm, salt, info)
	okm := make([]byte, 42)
	if _, err := io.ReadFull(r, okm); err != nil {
		return nil, err
	}
	return okm, nil
}

// ecdhVector computes X25519(alice_priv, bob_pub) using RFC 7748 §6.1.
func ecdhVector() ([]byte, error) {
	alicePriv := mustDecodeHex(
		"77076d0a7318a57d3c16c17251b26645" +
			"df4c2f87ebc0992ab177fba51db92c2a",
	)
	bobPub := mustDecodeHex(
		"de9edb7d7b7dc1b4d35b61c2ece43537" +
			"3f8343c85b78674dadfc7e146f882b4f",
	)
	shared, err := curve25519.X25519(alicePriv, bobPub)
	if err != nil {
		return nil, err
	}
	return shared, nil
}

// ---- BN computation ---------------------------------------------------------

// computeBN runs vector(), SHA-256s the output, and returns a result.
func computeBN(name string, vector func() ([]byte, error)) (*result, error) {
	output, err := vector()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}

	digest := sha256.Sum256(output)
	n := new(big.Int).SetBytes(digest[:])
	bn := balternary.Encode(n)

	return &result{
		Primitive: name,
		OutputHex: hex.EncodeToString(output),
		DigestHex: hex.EncodeToString(digest[:]),
		BN:        bn,
	}, nil
}

// ---- Output -----------------------------------------------------------------

func printResult(r *result) {
	fmt.Printf("%s\n", r.Primitive)
	fmt.Printf("  output: %s\n", r.OutputHex)
	fmt.Printf("  sha256: %s\n", r.DigestHex)
	fmt.Printf("  bn:     %s\n", r.BN)
}

// ---- CLI --------------------------------------------------------------------

var primitives = []struct {
	name   string
	vector func() ([]byte, error)
}{
	{"hmac", hmacVector},
	{"aead", aeadVector},
	{"hkdf", hkdfVector},
	{"ecdh", ecdhVector},
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: pool_behavioral_number [--verify <expected_bn>] <primitive>")
	fmt.Fprintln(os.Stderr, "       primitive: hmac | aead | hkdf | ecdh | all")
	os.Exit(1)
}

func main() {
	args := os.Args[1:]

	var expectedBN string
	if len(args) >= 2 && args[0] == "--verify" {
		expectedBN = args[1]
		args = args[2:]
	}

	if len(args) != 1 {
		usage()
	}
	primitiveName := args[0]

	var targets []struct {
		name   string
		vector func() ([]byte, error)
	}

	if primitiveName == "all" {
		targets = primitives
	} else {
		found := false
		for _, p := range primitives {
			if p.name == primitiveName {
				targets = append(targets, p)
				found = true
				break
			}
		}
		if !found {
			fmt.Fprintf(os.Stderr, "unknown primitive %q\n", primitiveName)
			usage()
		}
	}

	exitCode := 0
	for _, t := range targets {
		r, err := computeBN(t.name, t.vector)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		printResult(r)

		if expectedBN != "" && r.BN != expectedBN {
			fmt.Fprintf(os.Stderr,
				"VERIFY FAILED for %s:\n  expected: %s\n  got:      %s\n",
				t.name, expectedBN, r.BN)
			exitCode = 1
		}
	}

	os.Exit(exitCode)
}

// ---- helpers ----------------------------------------------------------------

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("mustDecodeHex: " + err.Error())
	}
	return b
}
