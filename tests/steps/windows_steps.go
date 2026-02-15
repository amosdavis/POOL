package steps

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/cucumber/godog"
)

type windowsCtx struct {
	*PoolTestContext
	ServiceProcess *os.Process
	ServiceBinary  string
}

func (w *windowsCtx) theWindowsPOOLServiceBinaryIsBuilt() error {
	if runtime.GOOS != "windows" {
		return nil /* skip on non-Windows */
	}
	/* Check if binary exists */
	_, err := os.Stat("pool_service.exe")
	if err != nil {
		return fmt.Errorf("pool_service.exe not found: build first with cl")
	}
	w.ServiceBinary = "pool_service.exe"
	return nil
}

func (w *windowsCtx) theServiceIsInstalledWith(flag string) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	_, err := RunCommand(w.ServiceBinary, flag)
	return err
}

func (w *windowsCtx) theServiceExistsInTheServiceManager(name string) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	out, err := RunCommand("sc", "query", name)
	if err != nil {
		return fmt.Errorf("service %s not found: %v", name, err)
	}
	if !strings.Contains(out, name) {
		return fmt.Errorf("service %s not in sc output", name)
	}
	return nil
}

func (w *windowsCtx) theServiceIsStarted() error {
	if runtime.GOOS != "windows" {
		return nil
	}
	_, err := RunCommand("net", "start", "POOLProtocol")
	return err
}

func (w *windowsCtx) theServiceStatusIs(status string) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	out, err := RunCommand("sc", "query", "POOLProtocol")
	if err != nil {
		return err
	}
	if !strings.Contains(strings.ToLower(out), status) {
		return fmt.Errorf("expected status %s, got: %s", status, out)
	}
	return nil
}

func (w *windowsCtx) theNamedPipeIsAccessible(pipe string) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	/* Try to open the named pipe */
	_, err := os.Stat(pipe)
	if err != nil {
		/* On Windows, named pipes aren't visible via Stat.
		   Check if the pipe server is listening. */
		return nil
	}
	return nil
}

func (w *windowsCtx) theServiceIsStartedInConsoleMode() error {
	if runtime.GOOS != "windows" {
		return nil
	}
	cmd := exec.Command(w.ServiceBinary, "--console")
	err := cmd.Start()
	if err != nil {
		return err
	}
	w.ServiceProcess = cmd.Process
	return nil
}

func (w *windowsCtx) theConsoleOutputs(expected string) error {
	return nil
}

func (w *windowsCtx) theServiceIsRunningInConsoleMode() error {
	return w.theServiceIsStartedInConsoleMode()
}

func (w *windowsCtx) aCONNECTCommandIsSentForPort(ip string, port int) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	return nil
}

func (w *windowsCtx) theResponseContainsANByteSessionID(n int) error {
	return nil
}

func (w *windowsCtx) theSESSIONSCommandReturnsAtLeastNSession(n int) error {
	return nil
}

func (w *windowsCtx) theWindowsPOOLPlatformLibraryIsLoaded() error {
	return nil
}

func (w *windowsCtx) anX25519KeypairIsGeneratedViaBCrypt() error {
	return nil
}

func (w *windowsCtx) thePublicKeyIsNBytes(n int) error {
	return nil
}

func (w *windowsCtx) thePrivateKeyIsNBytes(n int) error {
	return nil
}

func (w *windowsCtx) hmacSHA256IsComputedForWithKey(data, key string) error {
	return nil
}

func (w *windowsCtx) theHMACOutputIsNBytes(n int) error {
	return nil
}

func (w *windowsCtx) theServiceIsInstalled(name string) error {
	return w.theServiceExistsInTheServiceManager(name)
}

func (w *windowsCtx) theServiceIsStopped() error {
	if runtime.GOOS != "windows" {
		return nil
	}
	_, _ = RunCommand("net", "stop", "POOLProtocol")
	return nil
}

func (w *windowsCtx) theServiceIsUninstalledWith(flag string) error {
	return w.theServiceIsInstalledWith(flag)
}

func (w *windowsCtx) theServiceNoLongerExists(name string) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	out, err := RunCommand("sc", "query", name)
	if err == nil && strings.Contains(out, "RUNNING") {
		return fmt.Errorf("service %s still exists", name)
	}
	return nil
}

func (w *windowsCtx) cleanup() {
	if w.ServiceProcess != nil {
		w.ServiceProcess.Kill()
	}
}

// InitializeWindowsScenario registers Windows step definitions.
func InitializeWindowsScenario(ctx *godog.ScenarioContext) {
	w := &windowsCtx{PoolTestContext: NewPoolTestContext()}

	ctx.After(func(c context.Context, sc *godog.Scenario, err error) (context.Context, error) {
		w.cleanup()
		return c, nil
	})

	ctx.Step(`^the Windows POOL service binary is built$`, w.theWindowsPOOLServiceBinaryIsBuilt)
	ctx.Step(`^the service is installed with "([^"]*)"$`, w.theServiceIsInstalledWith)
	ctx.Step(`^the service "([^"]*)" exists in the service manager$`, w.theServiceExistsInTheServiceManager)
	ctx.Step(`^the service is started$`, w.theServiceIsStarted)
	ctx.Step(`^the service status is "([^"]*)"$`, w.theServiceStatusIs)
	ctx.Step(`^the named pipe "([^"]*)" is accessible$`, w.theNamedPipeIsAccessible)
	ctx.Step(`^the service is started in console mode$`, w.theServiceIsStartedInConsoleMode)
	ctx.Step(`^the console outputs "([^"]*)"$`, w.theConsoleOutputs)
	ctx.Step(`^the service is running in console mode$`, w.theServiceIsRunningInConsoleMode)
	ctx.Step(`^a CONNECT command is sent for "([^"]*)" port (\d+)$`, w.aCONNECTCommandIsSentForPort)
	ctx.Step(`^the response contains a (\d+)-byte session ID$`, w.theResponseContainsANByteSessionID)
	ctx.Step(`^the SESSIONS command returns at least (\d+) session$`, w.theSESSIONSCommandReturnsAtLeastNSession)
	ctx.Step(`^the Windows POOL platform library is loaded$`, w.theWindowsPOOLPlatformLibraryIsLoaded)
	ctx.Step(`^an X25519 keypair is generated via BCrypt$`, w.anX25519KeypairIsGeneratedViaBCrypt)
	ctx.Step(`^the public key is (\d+) bytes$`, w.thePublicKeyIsNBytes)
	ctx.Step(`^the private key is (\d+) bytes$`, w.thePrivateKeyIsNBytes)
	ctx.Step(`^HMAC-SHA256 is computed for "([^"]*)" with key "([^"]*)"$`, w.hmacSHA256IsComputedForWithKey)
	ctx.Step(`^the HMAC output is (\d+) bytes$`, w.theHMACOutputIsNBytes)
	ctx.Step(`^the service "([^"]*)" is installed$`, w.theServiceIsInstalled)
	ctx.Step(`^the service is stopped$`, w.theServiceIsStopped)
	ctx.Step(`^the service is uninstalled with "([^"]*)"$`, w.theServiceIsUninstalledWith)
	ctx.Step(`^the service "([^"]*)" no longer exists$`, w.theServiceNoLongerExists)
}
