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
	"github.com/snyk/unified-policy-engine/pkg/loader"
	"github.com/snyk/unified-policy-engine/pkg/upe"
	"github.com/spf13/cobra"
)

var replCmd = &cobra.Command{
	Use:   "repl [-d <rules/metadata>...] [input]",
	Short: "Unified Policy Engine",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()
		consumer := upe.NewPolicyConsumer()
		if len(args) > 1 {
			check(fmt.Errorf("Expected at most 1 input"))
		} else if len(args) == 1 {
			configLoader := loader.LocalConfigurationLoader(loader.LoadPathsOptions{
				Paths: args,
				InputTypes: []loader.InputType{
					loader.Auto,
					loader.TfRuntime,
				},
				NoGitIgnore: false,
				IgnoreDirs:  false,
			})
			loadedConfigs, err := configLoader()
			check(err)
			states := loadedConfigs.ToStates()
			consumer.DataDocument(ctx, "repl/input/state.json", jsonMarshalUnmarshal(&states[0]))
		}
		data.PureRegoProvider()(ctx, consumer)
		for _, path := range rootCmdRegoPaths {
			if isTgz(path) {
				f, err := os.Open(path)
				check(err)
				data.TarGzProvider(f)(ctx, consumer)
			} else {
				data.LocalProvider(path)(ctx, consumer)
			}
		}
		store := inmem.NewFromObject(consumer.Documents)
		txn, err := store.NewTransaction(ctx, storage.TransactionParams{
			Write: true,
		})
		check(err)
		for p, m := range consumer.Modules {
			store.UpsertPolicy(ctx, txn, p, []byte(m.String()))
		}
		err = store.Commit(ctx, txn)
		check(err)
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
	},
}

func jsonMarshalUnmarshal(v interface{}) map[string]interface{} {
	b, err := json.Marshal(v)
	check(err)
	out := map[string]interface{}{}
	json.Unmarshal(b, &out)
	return out
}
