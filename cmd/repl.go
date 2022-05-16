package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/repl"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/snyk/unified-policy-engine/pkg/data"
	"github.com/snyk/unified-policy-engine/pkg/inputtypes"
	"github.com/snyk/unified-policy-engine/pkg/loader"
	"github.com/snyk/unified-policy-engine/pkg/upe"
	"github.com/spf13/cobra"
)

var replCmd = &cobra.Command{
	Use:   "repl [-d <rules/metadata>...] [input]",
	Short: "Unified Policy Engine",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		consumer := upe.NewPolicyConsumer()
		if len(args) > 1 {
			return fmt.Errorf("Expected at most 1 input")
		} else if len(args) == 1 {
			configLoader := loader.LocalConfigurationLoader(loader.LoadPathsOptions{
				Paths: args,
				InputTypes: inputtypes.InputTypes{
					loader.Auto,
					loader.StreamlinedState,
				},
				NoGitIgnore: false,
				IgnoreDirs:  false,
			})
			loadedConfigs, err := configLoader()
			if err != nil {
				return err
			}
			states := loadedConfigs.ToStates()
			if len(states) != 1 {
				return fmt.Errorf("Expected a single state but got %d", len(states))
			}
			replInput, err := jsonMarshalUnmarshal(states[0])
			if err != nil {
				return err
			}
			consumer.DataDocument(ctx, "repl/input/state.json", replInput)
		}
		data.PureRegoProvider()(ctx, consumer)
		for _, path := range rootCmdRegoPaths {
			if isTgz(path) {
				f, err := os.Open(path)
				if err != nil {
					return err
				}
				data.TarGzProvider(f)(ctx, consumer)
			} else {
				data.LocalProvider(path)(ctx, consumer)
			}
		}
		store := inmem.NewFromObject(consumer.Documents)
		txn, err := store.NewTransaction(ctx, storage.TransactionParams{
			Write: true,
		})
		if err != nil {
			return err
		}
		for p, m := range consumer.Modules {
			store.UpsertPolicy(ctx, txn, p, []byte(m.String()))
		}
		if err = store.Commit(ctx, txn); err != nil {
			return err
		}
		var historyPath string
		if homeDir, err := os.UserHomeDir(); err == nil {
			historyPath = filepath.Join(homeDir, ".upe-history")
		} else {
			historyPath = filepath.Join(".", ".upe-history")
		}
		r := repl.New(
			store,
			historyPath,
			os.Stdout,
			"pretty",
			ast.CompileErrorLimitDefault,
			"",
		)
		r.OneShot(ctx, "strict-builtin-errors")
		r.Loop(ctx)
		return nil
	},
}

func jsonMarshalUnmarshal(v interface{}) (map[string]interface{}, error) {
	if b, err := json.Marshal(v); err != nil {
		return nil, err
	} else {
		out := map[string]interface{}{}
		if err := json.Unmarshal(b, &out); err != nil {
			return nil, err
		}
		return out, nil
	}
}
