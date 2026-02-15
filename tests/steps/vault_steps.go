package steps

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

type vaultCtx struct {
	*PoolTestContext
	serveDir    string
	serverCmd   *exec.Cmd
	testFile    string
	pulledFile  string
	fileData    []byte
	cmdOutput   string
	cmdExitCode int
}

func (v *vaultCtx) aVaultServerIsServingDirectory(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("cannot create serve directory: %w", err)
	}
	v.serveDir = dir

	v.serverCmd = exec.Command("pool_vault", "serve", dir)
	if err := v.serverCmd.Start(); err != nil {
		return fmt.Errorf("failed to start vault server: %w", err)
	}
	time.Sleep(1 * time.Second)
	return nil
}

func (v *vaultCtx) iPushANByteTestFileToTheVaultServer(size int) error {
	v.fileData = make([]byte, size)
	if size > 0 {
		rand.Read(v.fileData)
	}

	v.testFile = filepath.Join(os.TempDir(), "pool_vault_push_test.dat")
	if err := os.WriteFile(v.testFile, v.fileData, 0644); err != nil {
		return fmt.Errorf("cannot write test file: %w", err)
	}

	remotePath := "/incoming/test.dat"
	out, err := RunCommandWithTimeout(30*time.Second,
		"pool_vault", "push", "127.0.0.1", v.testFile, remotePath)
	v.cmdOutput = out
	v.LastError = err
	if err != nil {
		v.cmdExitCode = 1
	}
	return nil
}

func (v *vaultCtx) thePushCompletesSuccessfully() error {
	if v.LastError != nil {
		return fmt.Errorf("push failed: %v\nOutput: %s", v.LastError, v.cmdOutput)
	}
	return nil
}

func (v *vaultCtx) theFileExistsOnTheVaultServerAtTheExpectedPath() error {
	expected := filepath.Join(v.serveDir, "incoming", "test.dat")
	if _, err := os.Stat(expected); os.IsNotExist(err) {
		return fmt.Errorf("file not found at %s", expected)
	}
	return nil
}

func (v *vaultCtx) iPullTheFileBackFromTheVaultServer() error {
	v.pulledFile = filepath.Join(os.TempDir(), "pool_vault_pull_test.dat")
	out, err := RunCommandWithTimeout(30*time.Second,
		"pool_vault", "pull", "127.0.0.1", "/incoming/test.dat", v.pulledFile)
	v.cmdOutput = out
	v.LastError = err
	return nil
}

func (v *vaultCtx) thePullCompletesSuccessfully() error {
	if v.LastError != nil {
		return fmt.Errorf("pull failed: %v\nOutput: %s", v.LastError, v.cmdOutput)
	}
	return nil
}

func (v *vaultCtx) thePulledFileMatchesTheOriginalByteForByte() error {
	pulled, err := os.ReadFile(v.pulledFile)
	if err != nil {
		return fmt.Errorf("cannot read pulled file: %w", err)
	}
	if !bytes.Equal(pulled, v.fileData) {
		return fmt.Errorf("pulled file differs: expected %d bytes, got %d bytes",
			len(v.fileData), len(pulled))
	}
	return nil
}

func (v *vaultCtx) iAttemptToPullANonexistentFile(path string) error {
	v.pulledFile = filepath.Join(os.TempDir(), "pool_vault_noexist.dat")
	out, err := RunCommandWithTimeout(10*time.Second,
		"pool_vault", "pull", "127.0.0.1", path, v.pulledFile)
	v.cmdOutput = out
	v.LastError = err
	return nil
}

func (v *vaultCtx) thePullFailsWithAnErrorMessage() error {
	if v.LastError == nil {
		return fmt.Errorf("expected pull to fail, but it succeeded")
	}
	return nil
}

func (v *vaultCtx) noPartialFileIsCreatedLocally() error {
	if _, err := os.Stat(v.pulledFile); err == nil {
		info, _ := os.Stat(v.pulledFile)
		if info.Size() > 0 {
			return fmt.Errorf("partial file exists at %s (%d bytes)", v.pulledFile, info.Size())
		}
	}
	return nil
}

func (v *vaultCtx) theVaultServeDirectoryIsReadOnly() error {
	return os.Chmod(v.serveDir, 0555)
}

func (v *vaultCtx) iAttemptToPushAFileToTheVaultServer() error {
	return v.iPushANByteTestFileToTheVaultServer(100)
}

func (v *vaultCtx) thePushFailsWithAPermissionError() error {
	if v.LastError == nil {
		return fmt.Errorf("expected push to fail with permission error, but it succeeded")
	}
	if !strings.Contains(v.cmdOutput, "ermission") &&
		!strings.Contains(v.cmdOutput, "denied") &&
		!strings.Contains(v.cmdOutput, "ERR") {
		return fmt.Errorf("expected permission error, got: %s", v.cmdOutput)
	}
	return nil
}

func (v *vaultCtx) thePulledFileIsEmpty() error {
	info, err := os.Stat(v.pulledFile)
	if err != nil {
		return fmt.Errorf("cannot stat pulled file: %w", err)
	}
	if info.Size() != 0 {
		return fmt.Errorf("expected empty file, got %d bytes", info.Size())
	}
	return nil
}

func (v *vaultCtx) iRunPoolVaultStatus() error {
	out, err := RunCommandWithTimeout(5*time.Second, "pool_vault", "status")
	v.cmdOutput = out
	v.LastError = err
	return nil
}

func (v *vaultCtx) theOutputIncludes(expected string) error {
	if !strings.Contains(v.cmdOutput, expected) {
		return fmt.Errorf("expected output to contain %q, got: %s", expected, v.cmdOutput)
	}
	return nil
}

func (v *vaultCtx) cleanup() {
	if v.serverCmd != nil && v.serverCmd.Process != nil {
		v.serverCmd.Process.Kill()
	}
	if v.testFile != "" {
		os.Remove(v.testFile)
	}
	if v.pulledFile != "" {
		os.Remove(v.pulledFile)
	}
	if v.serveDir != "" {
		os.Chmod(v.serveDir, 0755)
		os.RemoveAll(v.serveDir)
	}
}

// InitializeVaultScenario registers vault step definitions.
func InitializeVaultScenario(ctx *godog.ScenarioContext) {
	v := &vaultCtx{PoolTestContext: NewPoolTestContext()}

	ctx.After(func(c context.Context, sc *godog.Scenario, err error) (context.Context, error) {
		v.cleanup()
		return c, nil
	})

	ctx.Step(`^a vault server is serving directory "([^"]*)"$`, v.aVaultServerIsServingDirectory)
	ctx.Step(`^I push a (\d+)-byte test file to the vault server$`, v.iPushANByteTestFileToTheVaultServer)
	ctx.Step(`^the push completes successfully$`, v.thePushCompletesSuccessfully)
	ctx.Step(`^the file exists on the vault server at the expected path$`, v.theFileExistsOnTheVaultServerAtTheExpectedPath)
	ctx.Step(`^I pull the file back from the vault server$`, v.iPullTheFileBackFromTheVaultServer)
	ctx.Step(`^the pull completes successfully$`, v.thePullCompletesSuccessfully)
	ctx.Step(`^the pulled file matches the original byte-for-byte$`, v.thePulledFileMatchesTheOriginalByteForByte)
	ctx.Step(`^I attempt to pull a nonexistent file "([^"]*)"$`, v.iAttemptToPullANonexistentFile)
	ctx.Step(`^the pull fails with an error message$`, v.thePullFailsWithAnErrorMessage)
	ctx.Step(`^no partial file is created locally$`, v.noPartialFileIsCreatedLocally)
	ctx.Step(`^the vault serve directory is read-only$`, v.theVaultServeDirectoryIsReadOnly)
	ctx.Step(`^I attempt to push a file to the vault server$`, v.iAttemptToPushAFileToTheVaultServer)
	ctx.Step(`^the push fails with a permission error$`, v.thePushFailsWithAPermissionError)
	ctx.Step(`^the pulled file is empty$`, v.thePulledFileIsEmpty)
	ctx.Step(`^I run pool_vault status$`, v.iRunPoolVaultStatus)
	ctx.Step(`^the output includes "([^"]*)"$`, v.theOutputIncludes)
}
