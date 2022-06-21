package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/format"
	"github.com/snyk/policy-engine/pkg/inputs"
	"github.com/snyk/policy-engine/pkg/loader"
	"github.com/spf13/cobra"
)

var (
	cmdFixturePackage string
)

var fixtureCmd = &cobra.Command{
	Use:   "fixture",
	Short: "Generate test fixture",
	RunE: func(cmd *cobra.Command, args []string) error {
		configLoader := loader.LocalConfigurationLoader(loader.LoadPathsOptions{
			Paths: args,
			InputTypes: inputs.InputTypes{
				loader.Auto,
				loader.StreamlinedState,
			},
			NoGitIgnore: false,
			IgnoreDirs:  false,
		})
		loadedConfigs, errs := configLoader()
		if len(errs) > 0 {
			for _, err := range errs {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			}
			return fmt.Errorf("Could not load configuration")
		}

		packageName := cmdFixturePackage
		if packageName == "" {
			if len(args) != 1 {
				return fmt.Errorf("Cannot guess package names because multiple inputs are given")
			}

			normalized := filepath.ToSlash(args[0])
			normalized = strings.TrimSuffix(normalized, filepath.Ext(normalized))
			normalized = strings.ReplaceAll(normalized, "-", "_")
			parts := []string{}
			for _, part := range strings.Split(normalized, "/") {
				if part != "" {
					parts = append(parts, part)
				}
			}
			packageName = strings.Join(parts, ".")
		}

		states := loadedConfigs.ToStates()
		if len(states) != 1 {
			return fmt.Errorf("Expected a single state but got %d", len(states))
		}

		bytes, err := json.MarshalIndent(states[0], "", "  ")
		if err != nil {
			return err
		}
		bytes = []byte(fmt.Sprintf(`package %s
mock_input = %s`, packageName, string(bytes)))

		bytes, err = format.Source("-", bytes)
		if err != nil {
			return err
		}

		fmt.Printf("%s", string(bytes))
		return nil
	},
}

func init() {
	fixtureCmd.PersistentFlags().StringVar(&cmdFixturePackage, "package", "", "Explicitly set package name")
}
