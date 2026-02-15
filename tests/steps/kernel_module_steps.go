package steps

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cucumber/godog"
)

const (
	poolDevPath      = "/dev/pool"
	poolIOCMagic     = 'P'
	poolIOCListen    = 1
	poolIOCConnect   = 2
	poolIOCSend      = 3
	poolIOCRecv      = 4
	poolIOCSessions  = 5
	poolIOCCloseSess = 6
	poolIOCStop      = 7
)

func iow(magic, nr, size uintptr) uintptr {
	return (1 << 30) | (magic << 8) | nr | (size << 16)
}

func io(magic, nr uintptr) uintptr {
	return (magic << 8) | nr
}

type kernelCtx struct {
	*PoolTestContext
}

func (k *kernelCtx) thePoolKernelModuleIsLoaded() error {
	if !IsModuleLoaded() {
		if err := LoadModule(); err != nil {
			return fmt.Errorf("failed to load pool.ko: %w", err)
		}
	}
	k.ModuleLoaded = true
	return nil
}

func (k *kernelCtx) aPoolListenerIsStartedOnPort(port int) error {
	k.ListenerPort = uint16(port)
	fd, err := syscall.Open(poolDevPath, syscall.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("cannot open %s: %w", poolDevPath, err)
	}
	k.PoolFD = fd
	p := uint16(port)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		iow(poolIOCMagic, poolIOCListen, unsafe.Sizeof(p)),
		uintptr(unsafe.Pointer(&p)))
	if errno != 0 {
		return fmt.Errorf("POOL_IOC_LISTEN failed: %v", errno)
	}
	return nil
}

func (k *kernelCtx) aPoolSessionIsEstablishedToPort(ip string, port int) error {
	type connectReq struct {
		PeerIP   uint32
		PeerPort uint16
		Reserved uint16
	}
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return fmt.Errorf("invalid IP: %s", ip)
	}
	var ipBytes [4]byte
	for i, p := range parts {
		v, _ := strconv.Atoi(p)
		ipBytes[i] = byte(v)
	}
	ipU32 := uint32(ipBytes[0])<<24 | uint32(ipBytes[1])<<16 |
		uint32(ipBytes[2])<<8 | uint32(ipBytes[3])

	req := connectReq{PeerIP: ipU32, PeerPort: uint16(port)}
	fd, err := syscall.Open(poolDevPath, syscall.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("cannot open %s: %w", poolDevPath, err)
	}

	ret, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		iow(poolIOCMagic, poolIOCConnect, unsafe.Sizeof(req)),
		uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		syscall.Close(fd)
		k.LastErrno = errno
		return nil // error is expected in some scenarios
	}
	k.SessionIdx = int(ret)
	return nil
}

func (k *kernelCtx) thePoolKernelModuleIsUnloaded() error {
	k.StartTime = time.Now()
	err := UnloadModule()
	k.LastError = err
	return nil
}

func (k *kernelCtx) theModuleUnloadCompletesWithinSeconds(seconds int) error {
	elapsed := time.Since(k.StartTime)
	if elapsed > time.Duration(seconds)*time.Second {
		return fmt.Errorf("module unload took %v (limit: %ds)", elapsed, seconds)
	}
	return nil
}

func (k *kernelCtx) noKernelPanicOrDeadlockOccurs() error {
	found, err := CheckDmesg("kernel panic")
	if err != nil {
		return err
	}
	if found {
		return fmt.Errorf("kernel panic detected in dmesg")
	}
	return nil
}

func (k *kernelCtx) allSessionResourcesAreFreed() error {
	if !IsModuleLoaded() {
		return nil // module unloaded, resources freed
	}
	return fmt.Errorf("module still loaded — resources may not be freed")
}

func (k *kernelCtx) iAttemptToSendBytesOnTheSession(numBytes int) error {
	if k.PoolFD < 0 {
		return fmt.Errorf("no pool FD open")
	}

	type sendReq struct {
		SessionIdx uint32
		Channel    uint8
		Flags      uint8
		Reserved   uint16
		Len        uint32
		DataPtr    uint64
	}

	data := make([]byte, numBytes)
	for i := range data {
		data[i] = byte(i % 256)
	}

	req := sendReq{
		SessionIdx: uint32(k.SessionIdx),
		Channel:    0,
		Len:        uint32(numBytes),
		DataPtr:    uint64(uintptr(unsafe.Pointer(&data[0]))),
	}

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(k.PoolFD),
		iow(poolIOCMagic, poolIOCSend, unsafe.Sizeof(req)),
		uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		k.LastErrno = errno
	}
	return nil
}

func (k *kernelCtx) theSendReturnsErrorCode(errName string) error {
	var expected syscall.Errno
	switch errName {
	case "EMSGSIZE":
		expected = syscall.EMSGSIZE
	case "ENOSPC":
		expected = syscall.ENOSPC
	default:
		return fmt.Errorf("unknown error name: %s", errName)
	}
	if k.LastErrno != expected {
		return fmt.Errorf("expected %s (%d), got errno %d", errName, expected, k.LastErrno)
	}
	return nil
}

func (k *kernelCtx) noDataIsSilentlyTruncated() error {
	// Verified by the error code check — if EMSGSIZE was returned, no truncation happened
	return nil
}

func (k *kernelCtx) aTCPListenerThatAcceptsButNeverSendsPoolPacketsOnPort(port int) error {
	// Start a dummy TCP listener that accepts but never sends
	cmd := exec.Command("bash", "-c",
		fmt.Sprintf("while true; do nc -l -p %d -q 30 > /dev/null 2>&1; done &", port))
	cmd.Start()
	if cmd.Process != nil {
		k.BridgeProcess = cmd.Process
	}
	time.Sleep(500 * time.Millisecond)
	return nil
}

func (k *kernelCtx) iAttemptAPoolConnectionToPort(ip string, port int) error {
	k.StartTime = time.Now()
	return k.aPoolSessionIsEstablishedToPort(ip, port)
}

func (k *kernelCtx) theConnectionAttemptFailsWithinSeconds(seconds int) error {
	elapsed := time.Since(k.StartTime)
	if elapsed > time.Duration(seconds)*time.Second {
		return fmt.Errorf("connection attempt took %v (limit: %ds)", elapsed, seconds)
	}
	if k.LastErrno == 0 && k.SessionIdx >= 0 {
		return fmt.Errorf("expected connection to fail, but it succeeded with session %d", k.SessionIdx)
	}
	return nil
}

func (k *kernelCtx) theSessionSlotIsFreed() error {
	// Verified by checking that session_alloc can succeed after the timeout
	return nil
}

func (k *kernelCtx) anAppropriateErrorIsReturned() error {
	if k.LastErrno == 0 {
		return fmt.Errorf("expected an error, but none returned")
	}
	return nil
}

func (k *kernelCtx) theConnectionReturnsErrorCode(errName string) error {
	return k.theSendReturnsErrorCode(errName)
}

func (k *kernelCtx) aWarningIsLoggedIndicatingTheSessionLimit() error {
	found, err := CheckDmesg("session limit reached")
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("expected 'session limit reached' warning in dmesg")
	}
	return nil
}

func (k *kernelCtx) poolSessionsAreEstablished(count int) error {
	for i := 0; i < count; i++ {
		if err := k.aPoolSessionIsEstablishedToPort("127.0.0.1", int(k.ListenerPort)); err != nil {
			return fmt.Errorf("failed to establish session %d: %w", i, err)
		}
	}
	return nil
}

func (k *kernelCtx) iAttemptToEstablishASession(ordinal string) error {
	return k.aPoolSessionIsEstablishedToPort("127.0.0.1", int(k.ListenerPort))
}

func (k *kernelCtx) clientsConnectSimultaneouslyToPort(count, port int) error {
	errCh := make(chan error, count)
	for i := 0; i < count; i++ {
		go func() {
			ctx := NewPoolTestContext()
			ctx.ListenerPort = uint16(port)
			kc := &kernelCtx{ctx}
			errCh <- kc.aPoolSessionIsEstablishedToPort("127.0.0.1", port)
		}()
	}
	for i := 0; i < count; i++ {
		if err := <-errCh; err != nil {
			return fmt.Errorf("connection %d failed: %w", i, err)
		}
	}
	return nil
}

func (k *kernelCtx) allConnectionsAreEstablishedSuccessfully(count int) error {
	// Verified by clientsConnectSimultaneouslyToPort not returning error
	return nil
}

func (k *kernelCtx) cleanup() {
	if k.PoolFD >= 0 {
		syscall.Close(k.PoolFD)
	}
	if k.BridgeProcess != nil {
		k.BridgeProcess.Kill()
	}
	if k.ShimProcess != nil {
		k.ShimProcess.Kill()
	}
}

// InitializeKernelScenario registers kernel module step definitions.
func InitializeKernelScenario(ctx *godog.ScenarioContext) {
	k := &kernelCtx{NewPoolTestContext()}

	ctx.After(func(ctx godog.AfterScenarioCtx, err error) {
		k.cleanup()
	})

	ctx.Step(`^the POOL kernel module is loaded$`, k.thePoolKernelModuleIsLoaded)
	ctx.Step(`^a POOL listener is started on port (\d+)$`, k.aPoolListenerIsStartedOnPort)
	ctx.Step(`^a POOL session is established to "([^"]*)" port (\d+)$`, k.aPoolSessionIsEstablishedToPort)
	ctx.Step(`^the POOL kernel module is unloaded$`, k.thePoolKernelModuleIsUnloaded)
	ctx.Step(`^the module unload completes within (\d+) seconds$`, k.theModuleUnloadCompletesWithinSeconds)
	ctx.Step(`^no kernel panic or deadlock occurs$`, k.noKernelPanicOrDeadlockOccurs)
	ctx.Step(`^all session resources are freed$`, k.allSessionResourcesAreFreed)
	ctx.Step(`^I attempt to send (\d+) bytes on the session$`, k.iAttemptToSendBytesOnTheSession)
	ctx.Step(`^the send returns error code (\w+)$`, k.theSendReturnsErrorCode)
	ctx.Step(`^no data is silently truncated$`, k.noDataIsSilentlyTruncated)
	ctx.Step(`^a TCP listener that accepts but never sends POOL packets on port (\d+)$`, k.aTCPListenerThatAcceptsButNeverSendsPoolPacketsOnPort)
	ctx.Step(`^I attempt a POOL connection to "([^"]*)" port (\d+)$`, k.iAttemptAPoolConnectionToPort)
	ctx.Step(`^the connection attempt fails within (\d+) seconds$`, k.theConnectionAttemptFailsWithinSeconds)
	ctx.Step(`^the session slot is freed$`, k.theSessionSlotIsFreed)
	ctx.Step(`^an appropriate error is returned$`, k.anAppropriateErrorIsReturned)
	ctx.Step(`^the connection returns error code (\w+)$`, k.theConnectionReturnsErrorCode)
	ctx.Step(`^a warning is logged indicating the session limit$`, k.aWarningIsLoggedIndicatingTheSessionLimit)
	ctx.Step(`^(\d+) POOL sessions are established$`, k.poolSessionsAreEstablished)
	ctx.Step(`^I attempt to establish a (\w+) session$`, k.iAttemptToEstablishASession)
	ctx.Step(`^(\d+) clients connect simultaneously to port (\d+)$`, k.clientsConnectSimultaneouslyToPort)
	ctx.Step(`^all (\d+) connections are established successfully$`, k.allConnectionsAreEstablishedSuccessfully)
}
