package steps

import (
	"os"
	"testing"

	"github.com/cucumber/godog"
	"github.com/cucumber/godog/colors"
)

var opts = godog.Options{
	Output: colors.Colored(os.Stdout),
	Format: "pretty",
	Paths:  []string{"features"},
}

func TestFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: func(ctx *godog.ScenarioContext) {
			InitializeKernelScenario(ctx)
			InitializeBridgeScenario(ctx)
			InitializeShimScenario(ctx)
			InitializeVaultScenario(ctx)
			InitializeRelayScenario(ctx)
			InitializeWindowsScenario(ctx)
			InitializeDarwinScenario(ctx)
			InitializeIPv6Scenario(ctx)
			InitializeFailureModeScenario(ctx)
		},
		Options: &opts,
	}

	if suite.Run() != 0 {
		t.Fatal("non-zero status returned, failed to run feature tests")
	}
}
