package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/snyk/unified-policy-engine/pkg/loader"
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
			Paths:       args,
			InputTypes:  []loader.InputType{loader.Auto},
			NoGitIgnore: false,
			IgnoreDirs:  false,
		})
		loadedConfigs, err := configLoader()
		if err != nil {
			return err
		}

		packageName := cmdFixturePackage
		if packageName == "" {
			if len(args) != 1 {
				return fmt.Errorf("Cannot guess package names because multiple inputs are given")
			}

			normalized := filepath.ToSlash(args[0])
			normalized = strings.TrimSuffix(normalized, filepath.Ext(normalized))
			parts := []string{}
			for _, part := range strings.Split(normalized, "/") {
				if part != "" {
					parts = append(parts, part)
				}
			}
			packageName = strings.Join(parts, ".")
		}

		states := loadedConfigs.ToStates()
		bytes, err := json.MarshalIndent(states, "", "  ")
		if err != nil {
			return err
		}

		fmt.Fprintf(os.Stdout, `package %s
mock_input = %s`, packageName, string(bytes))
		return nil
	},
}

func init() {
	fixtureCmd.PersistentFlags().StringVar(&cmdFixturePackage, "package", "", "Explicitly set package name")
}
