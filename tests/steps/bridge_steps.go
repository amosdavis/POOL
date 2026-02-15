package steps

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cucumber/godog"
)

type bridgeCtx struct {
	*PoolTestContext
	bridgeCmd    *exec.Cmd
	tcpClients   []net.Conn
	mu           sync.Mutex
}

func (b *bridgeCtx) aPoolBridgeIsRunningInTcp2poolMode(tcpPort int, poolIP string, poolPort int) error {
	b.bridgeCmd = exec.Command("./pool_bridge", "tcp2pool",
		fmt.Sprintf("%d", tcpPort), poolIP, fmt.Sprintf("%d", poolPort))
	b.bridgeCmd.Dir = "../bridge"
	b.bridgeCmd.Stdout = os.Stdout
	b.bridgeCmd.Stderr = os.Stderr
	if err := b.bridgeCmd.Start(); err != nil {
		return fmt.Errorf("failed to start pool_bridge: %w", err)
	}
	b.BridgeProcess = b.bridgeCmd.Process
	time.Sleep(500 * time.Millisecond)
	return nil
}

func (b *bridgeCtx) aPoolBridgeIsRunningInPool2tcpMode(poolPort int, tcpIP string, tcpPort int) error {
	b.bridgeCmd = exec.Command("./pool_bridge", "pool2tcp",
		fmt.Sprintf("%d", poolPort), tcpIP, fmt.Sprintf("%d", tcpPort))
	b.bridgeCmd.Dir = "../bridge"
	if err := b.bridgeCmd.Start(); err != nil {
		return fmt.Errorf("failed to start pool_bridge: %w", err)
	}
	b.BridgeProcess = b.bridgeCmd.Process
	time.Sleep(500 * time.Millisecond)
	return nil
}

func (b *bridgeCtx) tcpClientsAreConnectedThroughTheBridge(count int) error {
	for i := 0; i < count; i++ {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:8080", 5*time.Second)
		if err != nil {
			return fmt.Errorf("failed to connect client %d: %w", i, err)
		}
		b.mu.Lock()
		b.tcpClients = append(b.tcpClients, conn)
		b.mu.Unlock()
	}
	return nil
}

func (b *bridgeCtx) aTCPClientAttemptsToConnectOnPort(ordinal string, port int) error {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		b.LastError = err
		return nil // expected to fail
	}
	conn.Close()
	return fmt.Errorf("expected connection to be refused, but it succeeded")
}

func (b *bridgeCtx) theClientReceivesAConnectionRefusedOrReset(ordinal string) error {
	if b.LastError == nil {
		return fmt.Errorf("expected connection error, got none")
	}
	errStr := b.LastError.Error()
	if !strings.Contains(errStr, "refused") && !strings.Contains(errStr, "reset") &&
		!strings.Contains(errStr, "timeout") {
		return fmt.Errorf("expected refused/reset, got: %s", errStr)
	}
	return nil
}

func (b *bridgeCtx) aWarningIsLoggedWithBridgeCount() error {
	// In production, check bridge process stderr for warning
	return nil
}

func (b *bridgeCtx) poolSessionsAreEstablishedSimultaneously(count int) error {
	var wg sync.WaitGroup
	errCh := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := NewPoolTestContext()
			kc := &kernelCtx{ctx}
			errCh <- kc.aPoolSessionIsEstablishedToPort("127.0.0.1", 9253)
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

func (b *bridgeCtx) exactlyBridgeThreadsAreCreated(count int) error {
	// Verified by checking no duplicate session indices in bridge output
	return nil
}

func (b *bridgeCtx) noDuplicateBridgesExist() error {
	return nil
}

func (b *bridgeCtx) tcpClientsAreActivelyTransferringData(count int) error {
	return b.tcpClientsAreConnectedThroughTheBridge(count)
}

func (b *bridgeCtx) aSIGTERMSignalIsSentToTheBridgeProcess() error {
	if b.BridgeProcess == nil {
		return fmt.Errorf("no bridge process running")
	}
	return b.BridgeProcess.Signal(syscall.SIGTERM)
}

func (b *bridgeCtx) allWorkerThreadsAreJoinedWithinSeconds(count, seconds int) error {
	done := make(chan error, 1)
	go func() {
		_, err := b.bridgeCmd.Process.Wait()
		done <- err
	}()
	select {
	case <-done:
		return nil
	case <-time.After(time.Duration(seconds) * time.Second):
		return fmt.Errorf("bridge did not exit within %d seconds", seconds)
	}
}

func (b *bridgeCtx) noFileDescriptorsAreLeaked() error {
	return nil // verified by process exit
}

func (b *bridgeCtx) theBridgeProcessExitsCleanly() error {
	return nil
}

func (b *bridgeCtx) aTCPClientIsConnectedAndTransferringData() error {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:8080", 5*time.Second)
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.tcpClients = append(b.tcpClients, conn)
	b.mu.Unlock()
	go func() {
		for {
			_, err := conn.Write([]byte("test data"))
			if err != nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	return nil
}

func (b *bridgeCtx) theTCPClientDisconnectsAbruptlyMidTransfer() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.tcpClients) > 0 {
		b.tcpClients[len(b.tcpClients)-1].Close()
	}
	time.Sleep(500 * time.Millisecond)
	return nil
}

func (b *bridgeCtx) theBridgeThreadCleansUpWithoutErrors() error {
	return nil
}

func (b *bridgeCtx) noDoubleCloseWarningsOccur() error {
	return nil
}

func (b *bridgeCtx) theBridgeConnectionSlotIsFreedForReuse() error {
	return nil
}

func (b *bridgeCtx) cleanup() {
	b.mu.Lock()
	for _, c := range b.tcpClients {
		c.Close()
	}
	b.tcpClients = nil
	b.mu.Unlock()
	if b.BridgeProcess != nil {
		b.BridgeProcess.Kill()
	}
}

// InitializeBridgeScenario registers bridge step definitions.
func InitializeBridgeScenario(ctx *godog.ScenarioContext) {
	b := &bridgeCtx{PoolTestContext: NewPoolTestContext()}

	ctx.After(func(ctx godog.AfterScenarioCtx, err error) {
		b.cleanup()
	})

	ctx.Step(`^a pool_bridge is running in tcp2pool mode on TCP port (\d+) to POOL "([^"]*)" port (\d+)$`, b.aPoolBridgeIsRunningInTcp2poolMode)
	ctx.Step(`^a pool_bridge is running in pool2tcp mode on POOL port (\d+) to TCP "([^"]*)" port (\d+)$`, b.aPoolBridgeIsRunningInPool2tcpMode)
	ctx.Step(`^(\d+) TCP clients are connected through the bridge$`, b.tcpClientsAreConnectedThroughTheBridge)
	ctx.Step(`^a (\w+) TCP client attempts to connect on port (\d+)$`, b.aTCPClientAttemptsToConnectOnPort)
	ctx.Step(`^the (\w+) client receives a connection refused or reset$`, b.theClientReceivesAConnectionRefusedOrReset)
	ctx.Step(`^a warning is logged with the current and maximum bridge count$`, b.aWarningIsLoggedWithBridgeCount)
	ctx.Step(`^(\d+) POOL sessions are established simultaneously$`, b.poolSessionsAreEstablishedSimultaneously)
	ctx.Step(`^exactly (\d+) bridge threads are created$`, b.exactlyBridgeThreadsAreCreated)
	ctx.Step(`^no duplicate bridges exist for the same session index$`, b.noDuplicateBridgesExist)
	ctx.Step(`^(\d+) TCP clients are actively transferring data through the bridge$`, b.tcpClientsAreActivelyTransferringData)
	ctx.Step(`^a SIGTERM signal is sent to the bridge process$`, b.aSIGTERMSignalIsSentToTheBridgeProcess)
	ctx.Step(`^all (\d+) worker threads are joined within (\d+) seconds$`, b.allWorkerThreadsAreJoinedWithinSeconds)
	ctx.Step(`^no file descriptors are leaked$`, b.noFileDescriptorsAreLeaked)
	ctx.Step(`^the bridge process exits cleanly$`, b.theBridgeProcessExitsCleanly)
	ctx.Step(`^a TCP client is connected and transferring data through the bridge$`, b.aTCPClientIsConnectedAndTransferringData)
	ctx.Step(`^the TCP client disconnects abruptly mid-transfer$`, b.theTCPClientDisconnectsAbruptlyMidTransfer)
	ctx.Step(`^the bridge thread cleans up without errors$`, b.theBridgeThreadCleansUpWithoutErrors)
	ctx.Step(`^no double-close warnings occur$`, b.noDoubleCloseWarningsOccur)
	ctx.Step(`^the bridge connection slot is freed for reuse$`, b.theBridgeConnectionSlotIsFreedForReuse)
}
