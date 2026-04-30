package steps

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cucumber/godog"
)

// bnResult holds the parsed output from one pool_behavioral_number invocation.
type bnResult struct {
	primitive string
	outputHex string
	sha256Hex string
	bn        string
}

type behavioralNumberCtx struct {
	*PoolTestContext
	toolPath   string
	lastResult []bnResult
	lastStdout string
	lastStderr string
	lastExit   int
	altResult  []bnResult
}

func newBehavioralNumberCtx() *behavioralNumberCtx {
	return &behavioralNumberCtx{
		PoolTestContext: NewPoolTestContext(),
	}
}

// ---- tool location ----

func (b *behavioralNumberCtx) toolIsBuilt() error {
	// Look for the pre-built binary in the tool directory.
	// Resolve relative to this file's package root (two levels up from tests/steps).
	candidates := []string{
		filepath.Join("..", "..", "tools", "pool_behavioral_number", "pool_behavioral_number"),
		filepath.Join("..", "..", "tools", "pool_behavioral_number", "pool_behavioral_number.exe"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			b.toolPath = c
			return nil
		}
	}

	// Fall back: try to build it now.
	buildDir := filepath.Join("..", "..", "tools", "pool_behavioral_number")
	gobin, err := findGo()
	if err != nil {
		return fmt.Errorf("pool_behavioral_number not found and go not available: %w", err)
	}
	cmd := exec.Command(gobin, "build", "-o", "pool_behavioral_number", ".")
	cmd.Dir = buildDir
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to build pool_behavioral_number: %w\n%s", err, out)
	}
	b.toolPath = filepath.Join(buildDir, "pool_behavioral_number")
	return nil
}

func findGo() (string, error) {
	for _, candidate := range []string{"go", "/usr/local/go/bin/go", "/home/linux/go/bin/go"} {
		if p, err := exec.LookPath(candidate); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("go binary not found in PATH or common locations")
}

// ---- run helpers ----

func (b *behavioralNumberCtx) runTool(args ...string) ([]bnResult, string, string, int, error) {
	cmd := exec.Command(b.toolPath, args...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			return nil, "", "", 0, err
		}
	}
	results := parseToolOutput(stdout.String())
	return results, stdout.String(), stderr.String(), exitCode, nil
}

// parseToolOutput parses the multi-primitive output format:
//
//	hmac
//	  output: <hex>
//	  sha256: <hex>
//	  bn:     <bt>
func parseToolOutput(s string) []bnResult {
	var results []bnResult
	var current *bnResult
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			// New primitive header
			if current != nil {
				results = append(results, *current)
			}
			current = &bnResult{primitive: trimmed}
			continue
		}
		if current == nil {
			continue
		}
		if after, ok := strings.CutPrefix(trimmed, "output: "); ok {
			current.outputHex = after
		} else if after, ok := strings.CutPrefix(trimmed, "sha256: "); ok {
			current.sha256Hex = after
		} else if after, ok := strings.CutPrefix(trimmed, "bn:     "); ok {
			current.bn = after
		}
	}
	if current != nil {
		results = append(results, *current)
	}
	return results
}

func (b *behavioralNumberCtx) findResult(primitive string) (*bnResult, error) {
	for i := range b.lastResult {
		if b.lastResult[i].primitive == primitive {
			return &b.lastResult[i], nil
		}
	}
	return nil, fmt.Errorf("primitive %q not found in last result (have: %v)", primitive, primitiveNames(b.lastResult))
}

func primitiveNames(results []bnResult) []string {
	names := make([]string, len(results))
	for i, r := range results {
		names[i] = r.primitive
	}
	return names
}

// ---- step definitions ----

func (b *behavioralNumberCtx) computeBN(primitive string) error {
	results, stdout, stderr, exit, err := b.runTool(primitive)
	if err != nil {
		return fmt.Errorf("running tool: %w", err)
	}
	b.lastResult = results
	b.lastStdout = stdout
	b.lastStderr = stderr
	b.lastExit = exit
	return nil
}

func (b *behavioralNumberCtx) computeBNSeparately(primitive string) error {
	results, _, _, _, err := b.runTool(primitive)
	if err != nil {
		return err
	}
	b.altResult = results
	return nil
}

// computeBNAgain is an alias for computeBNSeparately used in determinism scenarios.
func (b *behavioralNumberCtx) computeBNAgain(primitive string) error {
	return b.computeBNSeparately(primitive)
}

func (b *behavioralNumberCtx) bnCharsetValid(primitive string) error {
	r, err := b.findResult(primitive)
	if err != nil {
		// For a single-primitive run, use the first result.
		if len(b.lastResult) == 1 {
			r = &b.lastResult[0]
		} else {
			return err
		}
	}
	for i, c := range r.bn {
		if c != 'T' && c != '0' && c != '1' {
			return fmt.Errorf("invalid character %q at position %d in bn for %s", c, i, r.primitive)
		}
	}
	return nil
}

func (b *behavioralNumberCtx) bnLengthAtMost(maxLen int) error {
	for _, r := range b.lastResult {
		if len(r.bn) > maxLen {
			return fmt.Errorf("bn for %s has length %d, exceeds limit %d", r.primitive, len(r.bn), maxLen)
		}
	}
	return nil
}

func (b *behavioralNumberCtx) outputHexMatches(expected string) error {
	if len(b.lastResult) == 0 {
		return fmt.Errorf("no results")
	}
	got := b.lastResult[0].outputHex
	if got != expected {
		return fmt.Errorf("output hex mismatch:\n  expected: %s\n  got:      %s", expected, got)
	}
	return nil
}

func (b *behavioralNumberCtx) sha256HexMatches(expected string) error {
	if len(b.lastResult) == 0 {
		return fmt.Errorf("no results")
	}
	got := b.lastResult[0].sha256Hex
	if got != expected {
		return fmt.Errorf("sha256 hex mismatch:\n  expected: %s\n  got:      %s", expected, got)
	}
	return nil
}

func (b *behavioralNumberCtx) bnMatches(expected string) error {
	if len(b.lastResult) == 0 {
		return fmt.Errorf("no results")
	}
	got := b.lastResult[0].bn
	if got != expected {
		return fmt.Errorf("bn mismatch:\n  expected: %s\n  got:      %s", expected, got)
	}
	return nil
}

func (b *behavioralNumberCtx) bothBNsIdentical() error {
	if len(b.lastResult) == 0 || len(b.altResult) == 0 {
		return fmt.Errorf("one or both result sets are empty")
	}
	first := b.lastResult[0].bn
	second := b.altResult[0].bn
	if first != second {
		return fmt.Errorf("non-deterministic BN:\n  first run:  %s\n  second run: %s", first, second)
	}
	return nil
}

func (b *behavioralNumberCtx) allBNsIdentical() error {
	if len(b.lastResult) == 0 || len(b.altResult) == 0 {
		return fmt.Errorf("one or both result sets are empty")
	}
	for i, r1 := range b.lastResult {
		if i >= len(b.altResult) {
			return fmt.Errorf("result count mismatch: first=%d second=%d", len(b.lastResult), len(b.altResult))
		}
		r2 := b.altResult[i]
		if r1.primitive != r2.primitive {
			return fmt.Errorf("primitive order mismatch at index %d: %q vs %q", i, r1.primitive, r2.primitive)
		}
		if r1.bn != r2.bn {
			return fmt.Errorf("non-deterministic BN for %s:\n  first:  %s\n  second: %s", r1.primitive, r1.bn, r2.bn)
		}
	}
	return nil
}

func (b *behavioralNumberCtx) bnRoundTripMatchesSHA256() error {
	if len(b.lastResult) == 0 {
		return fmt.Errorf("no results")
	}
	r := &b.lastResult[0]

	// Decode balanced ternary → big.Int
	n := new(big.Int)
	for _, c := range r.bn {
		n.Mul(n, big.NewInt(3))
		switch c {
		case '1':
			n.Add(n, big.NewInt(1))
		case 'T':
			n.Sub(n, big.NewInt(1))
		case '0':
			// nothing
		default:
			return fmt.Errorf("invalid bt digit %q", c)
		}
	}

	// Decode sha256 hex → big.Int
	digestBytes, err := hex.DecodeString(r.sha256Hex)
	if err != nil {
		return fmt.Errorf("decoding sha256 hex: %w", err)
	}
	expected := new(big.Int).SetBytes(digestBytes)

	if n.Cmp(expected) != 0 {
		return fmt.Errorf("round-trip mismatch:\n  from bn:     %s\n  from sha256: %s", n.Text(16), expected.Text(16))
	}
	return nil
}

func (b *behavioralNumberCtx) allOutputContainsFour() error {
	want := []string{"hmac", "aead", "hkdf", "ecdh"}
	have := make(map[string]bool)
	for _, r := range b.lastResult {
		have[r.primitive] = true
	}
	for _, w := range want {
		if !have[w] {
			return fmt.Errorf("missing primitive %q in 'all' output (have: %v)", w, primitiveNames(b.lastResult))
		}
	}
	return nil
}

func (b *behavioralNumberCtx) allHmacMatchesIndividual() error {
	// lastResult is 'all', altResult is individual 'hmac'
	var allHMAC *bnResult
	for i := range b.lastResult {
		if b.lastResult[i].primitive == "hmac" {
			allHMAC = &b.lastResult[i]
			break
		}
	}
	if allHMAC == nil {
		return fmt.Errorf("hmac not found in 'all' output")
	}
	if len(b.altResult) == 0 {
		return fmt.Errorf("no individual hmac result")
	}
	if allHMAC.bn != b.altResult[0].bn {
		return fmt.Errorf("hmac bn from 'all' differs from individual run:\n  all: %s\n  ind: %s", allHMAC.bn, b.altResult[0].bn)
	}
	return nil
}

func (b *behavioralNumberCtx) verifyWithCorrectBN(primitive string) error {
	// First compute to get the correct BN, then verify with it.
	results, _, _, _, err := b.runTool(primitive)
	if err != nil || len(results) == 0 {
		return fmt.Errorf("computing bn: %v", err)
	}
	correctBN := results[0].bn
	_, _, _, exit, err := b.runTool("--verify", correctBN, primitive)
	if err != nil {
		return err
	}
	b.lastExit = exit
	return nil
}

func (b *behavioralNumberCtx) verifyWithIncorrectBN(primitive, wrongBN string) error {
	_, _, stderr, exit, err := b.runTool("--verify", wrongBN, primitive)
	if err != nil {
		// exit code 1 is expected; don't error on that.
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			b.lastExit = 1
			b.lastStderr = stderr
			return nil
		}
		return err
	}
	b.lastExit = exit
	b.lastStderr = stderr
	return nil
}

func (b *behavioralNumberCtx) exitCodeIs(expected int) error {
	if b.lastExit != expected {
		return fmt.Errorf("exit code: expected %d, got %d", expected, b.lastExit)
	}
	return nil
}

func (b *behavioralNumberCtx) exitCodeIsNonZero() error {
	if b.lastExit == 0 {
		return fmt.Errorf("exit code: expected non-zero, got 0")
	}
	return nil
}

func (b *behavioralNumberCtx) stderrContains(sub string) error {
	if !strings.Contains(b.lastStderr, sub) {
		return fmt.Errorf("stderr does not contain %q:\n%s", sub, b.lastStderr)
	}
	return nil
}

// ---- registration ----

func InitializeBehavioralNumberScenario(ctx *godog.ScenarioContext) {
	b := newBehavioralNumberCtx()

	ctx.Step(`^the pool_behavioral_number tool is built$`, b.toolIsBuilt)
	ctx.Step(`^I compute the behavioral number for "([^"]+)"$`, b.computeBN)
	ctx.Step(`^I compute the behavioral number for "([^"]+)" again$`, b.computeBNAgain)
	ctx.Step(`^I separately compute the behavioral number for "([^"]+)"$`, b.computeBNSeparately)
	ctx.Step(`^the bn field should contain only the characters "T", "0", and "1"$`, func() error {
		return b.bnCharsetValid("")
	})
	ctx.Step(`^the bn field length should be at most (\d+)$`, b.bnLengthAtMost)
	ctx.Step(`^the output hex should be "([^"]+)"$`, b.outputHexMatches)
	ctx.Step(`^the sha256 hex should be "([^"]+)"$`, b.sha256HexMatches)
	ctx.Step(`^the bn field should be "([^"]+)"$`, b.bnMatches)
	ctx.Step(`^both bn fields should be identical$`, b.bothBNsIdentical)
	ctx.Step(`^all bn fields from both runs should be identical$`, b.allBNsIdentical)
	ctx.Step(`^the bn field decoded as balanced ternary should equal the sha256 hex decoded as a big integer$`, b.bnRoundTripMatchesSHA256)
	ctx.Step(`^the output should contain entries for "hmac", "aead", "hkdf", and "ecdh"$`, b.allOutputContainsFour)
	ctx.Step(`^the hmac bn from the "all" run should match the individual "hmac" bn$`, b.allHmacMatchesIndividual)
	ctx.Step(`^I verify the behavioral number for "([^"]+)" with the correct expected BN$`, b.verifyWithCorrectBN)
	ctx.Step(`^I verify the behavioral number for "([^"]+)" with an incorrect expected BN "([^"]+)"$`, b.verifyWithIncorrectBN)
	ctx.Step(`^the exit code should be (\d+)$`, b.exitCodeIs)
	ctx.Step(`^the exit code should be non-zero$`, b.exitCodeIsNonZero)
	ctx.Step(`^stderr should contain "([^"]+)"$`, b.stderrContains)
}
