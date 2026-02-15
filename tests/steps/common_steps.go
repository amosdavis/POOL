package steps

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// PoolTestContext holds shared state across step definitions.
type PoolTestContext struct {
	ModuleLoaded  bool
	ListenerPort  uint16
	SessionIdx    int
	PoolFD        int
	LastError     error
	LastErrno     syscall.Errno
	BridgeProcess *os.Process
	ShimProcess   *os.Process
	ReceivedData  []byte
	RequiredSize  int
	StartTime     time.Time
}

// NewPoolTestContext creates a fresh test context.
func NewPoolTestContext() *PoolTestContext {
	return &PoolTestContext{
		SessionIdx: -1,
		PoolFD:     -1,
	}
}

// RunCommand executes a shell command and returns combined output.
func RunCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// RunCommandWithTimeout executes a command with a timeout.
func RunCommandWithTimeout(timeout time.Duration, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	done := make(chan error, 1)
	var out []byte

	go func() {
		var err error
		out, err = cmd.CombinedOutput()
		done <- err
	}()

	select {
	case err := <-done:
		return strings.TrimSpace(string(out)), err
	case <-time.After(timeout):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return "", fmt.Errorf("command timed out after %v", timeout)
	}
}

// IsModuleLoaded checks if pool.ko is loaded.
func IsModuleLoaded() bool {
	out, err := RunCommand("lsmod")
	if err != nil {
		return false
	}
	return strings.Contains(out, "pool")
}

// LoadModule loads pool.ko.
func LoadModule() error {
	_, err := RunCommand("insmod", "pool.ko")
	return err
}

// UnloadModule unloads pool.ko.
func UnloadModule() error {
	_, err := RunCommand("rmmod", "pool")
	return err
}

// CheckDmesg searches dmesg for a pattern.
func CheckDmesg(pattern string) (bool, error) {
	out, err := RunCommand("dmesg")
	if err != nil {
		return false, err
	}
	return strings.Contains(out, pattern), nil
}

// ReadFile reads the contents of a file and returns it as a string.
func ReadFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// WaitForCondition polls a condition until it becomes true or times out.
func WaitForCondition(timeout time.Duration, interval time.Duration, condition func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(interval)
	}
	return false
}
