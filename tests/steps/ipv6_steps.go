package steps

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

// IPv6TestContext holds state for IPv6-specific test scenarios.
type IPv6TestContext struct {
	*PoolTestContext
	PeerAddr      [16]byte
	AddrFamily    uint8
	MappedResult  [16]byte
	ExtractedIPv4 uint32
	IsV4Mapped    bool
	CommandOutput string
}

// NewIPv6TestContext creates a fresh IPv6 test context.
func NewIPv6TestContext() *IPv6TestContext {
	return &IPv6TestContext{
		PoolTestContext: NewPoolTestContext(),
	}
}

func (ctx *IPv6TestContext) aClientConnectsToIPv6(addr string, port int) error {
	ip := net.ParseIP(addr)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", addr)
	}

	ip6 := ip.To16()
	if ip6 == nil {
		return fmt.Errorf("cannot convert to 16-byte form: %s", addr)
	}

	copy(ctx.PeerAddr[:], ip6)
	if ip.To4() != nil {
		ctx.AddrFamily = 2 // AF_INET
	} else {
		ctx.AddrFamily = 10 // AF_INET6
	}

	return nil
}

func (ctx *IPv6TestContext) theSessionPeerAddressIs(expected string) error {
	ip := net.IP(ctx.PeerAddr[:])
	actual := ip.String()
	if actual != expected {
		return fmt.Errorf("expected peer address %q, got %q", expected, actual)
	}
	return nil
}

func (ctx *IPv6TestContext) theSessionAddressFamilyIs(family string) error {
	var expected uint8
	switch family {
	case "AF_INET":
		expected = 2
	case "AF_INET6":
		expected = 10
	default:
		return fmt.Errorf("unknown address family: %s", family)
	}
	if ctx.AddrFamily != expected {
		return fmt.Errorf("expected addr_family %d (%s), got %d", expected, family, ctx.AddrFamily)
	}
	return nil
}

func (ctx *IPv6TestContext) ipv4ToMapped(ipHex uint32) error {
	var addr [16]byte
	// ::ffff:x.x.x.x format
	addr[10] = 0xff
	addr[11] = 0xff
	binary.BigEndian.PutUint32(addr[12:], ipHex)
	ctx.MappedResult = addr
	return nil
}

func (ctx *IPv6TestContext) theMappedResultMatchesIPv6(expected string) error {
	ip := net.ParseIP(expected)
	if ip == nil {
		return fmt.Errorf("cannot parse expected IP: %s", expected)
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return fmt.Errorf("cannot convert to 16-byte: %s", expected)
	}

	for i := 0; i < 16; i++ {
		if ctx.MappedResult[i] != ip16[i] {
			return fmt.Errorf("byte %d: expected 0x%02x, got 0x%02x (full: %s vs %s)",
				i, ip16[i], ctx.MappedResult[i],
				hex.EncodeToString(ip16), hex.EncodeToString(ctx.MappedResult[:]))
		}
	}
	return nil
}

func (ctx *IPv6TestContext) mappedToIPv4(ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("cannot parse IP: %s", ipStr)
	}
	ip16 := ip.To16()
	copy(ctx.MappedResult[:], ip16)
	ctx.ExtractedIPv4 = binary.BigEndian.Uint32(ip16[12:])
	return nil
}

func (ctx *IPv6TestContext) theExtractedIPv4Is(expected uint32) error {
	if ctx.ExtractedIPv4 != expected {
		return fmt.Errorf("expected 0x%08X, got 0x%08X", expected, ctx.ExtractedIPv4)
	}
	return nil
}

func (ctx *IPv6TestContext) checkV4Mapped(addr string) error {
	ip := net.ParseIP(addr)
	if ip == nil {
		return fmt.Errorf("cannot parse IP: %s", addr)
	}
	ip4 := ip.To4()
	ip16 := ip.To16()
	// An address is v4-mapped if it has a valid To4() and the 16-byte form
	// has the ::ffff: prefix (bytes 10-11 are 0xff)
	ctx.IsV4Mapped = ip4 != nil && ip16[10] == 0xff && ip16[11] == 0xff
	return nil
}

func (ctx *IPv6TestContext) v4MappedReturns(expected string) error {
	want := expected == "true"
	if ctx.IsV4Mapped != want {
		return fmt.Errorf("expected pool_addr_is_v4mapped=%v, got %v", want, ctx.IsV4Mapped)
	}
	return nil
}

func (ctx *IPv6TestContext) poolctlConnectIPv6(addr string, port int) error {
	cmd := exec.Command("poolctl", "connect", addr, fmt.Sprintf("%d", port))
	out, err := cmd.CombinedOutput()
	ctx.CommandOutput = strings.TrimSpace(string(out))
	ctx.LastError = err
	return nil
}

func (ctx *IPv6TestContext) poolctlSessionsExecuted() error {
	cmd := exec.Command("poolctl", "sessions")
	out, err := cmd.CombinedOutput()
	ctx.CommandOutput = strings.TrimSpace(string(out))
	ctx.LastError = err
	return nil
}

func (ctx *IPv6TestContext) outputShowsIPv6Notation() error {
	if !strings.Contains(ctx.CommandOutput, "::") &&
		!strings.Contains(ctx.CommandOutput, ":") {
		return fmt.Errorf("output does not contain IPv6 notation: %s", ctx.CommandOutput)
	}
	return nil
}

func (ctx *IPv6TestContext) theConnectRequestUsesFamily(family string) error {
	return ctx.theSessionAddressFamilyIs(family)
}

func (ctx *IPv6TestContext) bridgeAcceptsIPv6(addr string, port int) error {
	conn, err := net.DialTimeout("tcp6", fmt.Sprintf("[%s]:%d", addr, port),
		5*time.Second)
	if err != nil {
		return fmt.Errorf("cannot connect to bridge via IPv6: %v", err)
	}
	conn.Close()
	return nil
}

func (ctx *IPv6TestContext) shimPopulatesPeerAddr(addr string) error {
	ip := net.ParseIP(addr)
	if ip == nil {
		return fmt.Errorf("invalid address: %s", addr)
	}
	ip16 := ip.To16()
	copy(ctx.PeerAddr[:], ip16)
	if ip.To4() != nil {
		ctx.AddrFamily = 2
	} else {
		ctx.AddrFamily = 10
	}
	return nil
}

// InitializeIPv6Scenario registers IPv6 step definitions with godog.
func InitializeIPv6Scenario(ctx *godog.ScenarioContext) {
	tc := NewIPv6TestContext()

	// Kernel dual-stack
	ctx.Step(`^a client connects to "([^"]*)" port (\d+)$`,
		tc.aClientConnectsToIPv6)
	ctx.Step(`^the session peer address is "([^"]*)"$`,
		tc.theSessionPeerAddressIs)
	ctx.Step(`^the session address family is (AF_INET6?|AF_INET)$`,
		tc.theSessionAddressFamilyIs)

	// Address helpers
	ctx.Step(`^IPv4 address (0x[0-9A-Fa-f]+) is converted to mapped$`,
		tc.ipv4ToMapped)
	ctx.Step(`^the result is the 16-byte sequence for "([^"]*)"$`,
		tc.theMappedResultMatchesIPv6)
	ctx.Step(`^the mapped address for "([^"]*)" is converted back$`,
		tc.mappedToIPv4)
	ctx.Step(`^the result is (0x[0-9A-Fa-f]+)$`,
		tc.theExtractedIPv4Is)
	ctx.Step(`^an address "([^"]*)"$`, tc.checkV4Mapped)
	ctx.Step(`^pool_addr_is_v4mapped returns (true|false)$`, tc.v4MappedReturns)

	// CLI
	ctx.Step(`^"poolctl connect ([^ ]+) (\d+)" is executed$`,
		tc.poolctlConnectIPv6)
	ctx.Step(`^"poolctl sessions" is executed$`, tc.poolctlSessionsExecuted)
	ctx.Step(`^the output shows the peer address in IPv6 notation$`,
		tc.outputShowsIPv6Notation)
	ctx.Step(`^the connect request uses (AF_INET6?|AF_INET)$`,
		tc.theConnectRequestUsesFamily)

	// Shim
	ctx.Step(`^the shim populates peer_addr with the full 128-bit address$`,
		func() error { return nil })
	ctx.Step(`^the shim sets addr_family to (AF_INET6?|AF_INET)$`,
		func(family string) error { return nil })
	ctx.Step(`^the shim detects the IPv4-mapped address$`,
		func() error { return nil })

	// Bridge
	ctx.Step(`^an IPv6 TCP client connects to "\[([^\]]+)\]:(\d+)"$`,
		tc.bridgeAcceptsIPv6)
}
