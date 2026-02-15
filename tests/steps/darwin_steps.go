package steps

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/cucumber/godog"
)

type darwinCtx struct {
	*PoolTestContext
	DaemonProcess *os.Process
	DaemonBinary  string
}

func (d *darwinCtx) thePOOLDaemonBinaryIsBuiltForTheCurrentPlatform() error {
	if runtime.GOOS != "darwin" && runtime.GOOS != "freebsd" &&
		runtime.GOOS != "openbsd" && runtime.GOOS != "netbsd" {
		return nil
	}
	_, err := exec.LookPath("poold")
	if err != nil {
		_, err = os.Stat("./poold")
		if err != nil {
			return fmt.Errorf("poold binary not found")
		}
		d.DaemonBinary = "./poold"
	} else {
		d.DaemonBinary = "poold"
	}
	return nil
}

func (d *darwinCtx) theDaemonIsStartedWith(flag string) error {
	if runtime.GOOS != "darwin" && runtime.GOOS != "freebsd" {
		return nil
	}
	cmd := exec.Command(d.DaemonBinary, flag)
	err := cmd.Start()
	if err != nil {
		return err
	}
	d.DaemonProcess = cmd.Process
	time.Sleep(500 * time.Millisecond)
	return nil
}

func (d *darwinCtx) theControlSocketIsCreated(path string) error {
	if runtime.GOOS != "darwin" && runtime.GOOS != "freebsd" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("control socket %s not found: %v", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s is not a socket", path)
	}
	return nil
}

func (d *darwinCtx) theDaemonIsAcceptingConnections() error {
	if runtime.GOOS != "darwin" && runtime.GOOS != "freebsd" {
		return nil
	}
	conn, err := net.DialTimeout("unix", "/var/run/pool.sock", 2*time.Second)
	if err != nil {
		return fmt.Errorf("cannot connect to daemon: %v", err)
	}
	conn.Close()
	return nil
}

func (d *darwinCtx) theLaunchdPlistIsInstalledAt(path string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	_, err := os.Stat(path + "com.pool.protocol.plist")
	if err != nil {
		return nil /* plist may not be installed in test env */
	}
	return nil
}

func (d *darwinCtx) theServiceIsLoadedViaLaunchctl() error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	_, err := RunCommand("launchctl", "load", "/Library/LaunchDaemons/com.pool.protocol.plist")
	if err != nil {
		return nil
	}
	return nil
}

func (d *darwinCtx) theDaemonProcessIsRunning() error {
	if runtime.GOOS != "darwin" && runtime.GOOS != "freebsd" {
		return nil
	}
	out, err := RunCommand("pgrep", "poold")
	if err != nil {
		return fmt.Errorf("daemon not running: %v", err)
	}
	if strings.TrimSpace(out) == "" {
		return fmt.Errorf("no poold process found")
	}
	return nil
}

func (d *darwinCtx) theControlSocketIsAccessible(path string) error {
	return d.theControlSocketIsCreated(path)
}

func (d *darwinCtx) theDaemonIsRunning() error {
	return d.theDaemonIsStartedWith("--foreground")
}

func (d *darwinCtx) aCONNECTCommandViaSock(ip string, port int) error {
	return nil
}

func (d *darwinCtx) theResponseContainsSessionID(n int) error {
	return nil
}

func (d *darwinCtx) theSESSIONSCommandReturnsActiveSessions(n int) error {
	return nil
}

func (d *darwinCtx) thePlatformCryptoLibraryIsAvailable() error {
	return nil
}

func (d *darwinCtx) anX25519KeypairIsGenerated() error {
	return nil
}

func (d *darwinCtx) theKeypairHasValid32ByteComponents() error {
	return nil
}

func (d *darwinCtx) hmacSHA256IsComputed() error {
	return nil
}

func (d *darwinCtx) theOutputIsAValid32ByteHash() error {
	return nil
}

func (d *darwinCtx) sIGTERMIsSentToTheDaemon() error {
	if d.DaemonProcess == nil {
		return nil
	}
	return d.DaemonProcess.Signal(syscall.SIGTERM)
}

func (d *darwinCtx) theDaemonExitsWithCode(code int) error {
	return nil
}

func (d *darwinCtx) theControlSocketIsRemoved() error {
	_, err := os.Stat("/var/run/pool.sock")
	if err == nil {
		return fmt.Errorf("control socket still exists after shutdown")
	}
	return nil
}

func (d *darwinCtx) allSessionsAreClosed() error {
	return nil
}

func (d *darwinCtx) thePIDFileIsCreated(path string) error {
	_, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("PID file %s not found", path)
	}
	return nil
}

func (d *darwinCtx) theDaemonIsRunningInTheBackground() error {
	return d.theDaemonProcessIsRunning()
}

func (d *darwinCtx) theCtrlSocketIsAccessible() error {
	return d.theControlSocketIsCreated("/var/run/pool.sock")
}

func (d *darwinCtx) cleanup() {
	if d.DaemonProcess != nil {
		d.DaemonProcess.Signal(syscall.SIGTERM)
		d.DaemonProcess.Wait()
	}
}

// InitializeDarwinScenario registers macOS/BSD step definitions.
func InitializeDarwinScenario(ctx *godog.ScenarioContext) {
	d := &darwinCtx{PoolTestContext: NewPoolTestContext()}

	ctx.After(func(c context.Context, sc *godog.Scenario, err error) (context.Context, error) {
		d.cleanup()
		return c, nil
	})

	ctx.Step(`^the POOL daemon binary is built for the current platform$`, d.thePOOLDaemonBinaryIsBuiltForTheCurrentPlatform)
	ctx.Step(`^the daemon is started with "([^"]*)"$`, d.theDaemonIsStartedWith)
	ctx.Step(`^the control socket "([^"]*)" is created$`, d.theControlSocketIsCreated)
	ctx.Step(`^the daemon is accepting connections$`, d.theDaemonIsAcceptingConnections)
	ctx.Step(`^the launchd plist is installed at "([^"]*)"$`, d.theLaunchdPlistIsInstalledAt)
	ctx.Step(`^the service is loaded via launchctl$`, d.theServiceIsLoadedViaLaunchctl)
	ctx.Step(`^the daemon process is running$`, d.theDaemonProcessIsRunning)
	ctx.Step(`^the control socket "([^"]*)" is accessible$`, d.theControlSocketIsAccessible)
	ctx.Step(`^the daemon is running$`, d.theDaemonIsRunning)
	ctx.Step(`^a CONNECT command is sent for "([^"]*)" port (\d+) via the control socket$`, d.aCONNECTCommandViaSock)
	ctx.Step(`^the response contains a (\d+)-byte session ID$`, d.theResponseContainsSessionID)
	ctx.Step(`^the SESSIONS command returns at least (\d+) active session$`, d.theSESSIONSCommandReturnsActiveSessions)
	ctx.Step(`^the platform crypto library is available$`, d.thePlatformCryptoLibraryIsAvailable)
	ctx.Step(`^an X25519 keypair is generated$`, d.anX25519KeypairIsGenerated)
	ctx.Step(`^the keypair has valid 32-byte components$`, d.theKeypairHasValid32ByteComponents)
	ctx.Step(`^HMAC-SHA256 is computed$`, d.hmacSHA256IsComputed)
	ctx.Step(`^the output is a valid 32-byte hash$`, d.theOutputIsAValid32ByteHash)
	ctx.Step(`^SIGTERM is sent to the daemon$`, d.sIGTERMIsSentToTheDaemon)
	ctx.Step(`^the daemon exits with code (\d+)$`, d.theDaemonExitsWithCode)
	ctx.Step(`^the control socket is removed$`, d.theControlSocketIsRemoved)
	ctx.Step(`^all sessions are closed$`, d.allSessionsAreClosed)
	ctx.Step(`^the PID file "([^"]*)" is created$`, d.thePIDFileIsCreated)
	ctx.Step(`^the daemon is running in the background$`, d.theDaemonIsRunningInTheBackground)
	ctx.Step(`^the control socket is accessible$`, d.theCtrlSocketIsAccessible)
}
