package policy

import (
	"github.com/open-policy-agent/opa/ast"
)

func moduleSetsHelper(
	path ast.Ref,
	node *ast.ModuleTreeNode,
) []ModuleSet {
	var mods []ModuleSet
	if len(node.Modules) > 0 {
		mods = append(mods, ModuleSet{
			Path:    path,
			Modules: node.Modules,
		})
	}
	for k, child := range node.Children {
		nextPath := append(path.Copy(), ast.NewTerm(k))
		mods = append(mods, moduleSetsHelper(nextPath, child)...)
	}
	return mods
}

// moduleSetsWithPrefix is a recursive function that extracts all ModuleSets under the
// specified prefix from a ModuleTreeNode.
func moduleSetsWithPrefix(
	prefix ast.Ref,
	node *ast.ModuleTreeNode,
) []ModuleSet {
	if parent := treeNodeAt(prefix, node); parent != nil {
		return moduleSetsHelper(prefix, parent)
	}
	return []ModuleSet{}
}

func treeNodeAt(ref ast.Ref, node *ast.ModuleTreeNode) *ast.ModuleTreeNode {
	curr := node
	for _, key := range ref {
		if child, ok := curr.Children[key.Value]; ok {
			curr = child
		} else {
			return nil
		}
	}
	return curr
}

func ExtractModuleSets(tree *ast.ModuleTreeNode) []ModuleSet {
	// Current policies, legacy Fugue policies, and legacy IaC custom policies
	mods := moduleSetsWithPrefix(ast.Ref{
		ast.DefaultRootDocument,
		ast.StringTerm("rules"),
	}, tree)

	// Legacy IaC policies
	if schemas := treeNodeAt(ast.Ref{
		ast.DefaultRootDocument,
		ast.StringTerm("schemas"),
	}, tree); schemas != nil {
		for key, child := range schemas.Children {
			if len(child.Modules) < 1 {
				continue
			}
			mods = append(mods, ModuleSet{
				Path: ast.Ref{
					ast.DefaultRootDocument,
					ast.StringTerm("schemas"),
					ast.NewTerm(key),
				},
				Modules: child.Modules,
			})
		}
	}

	return mods
}

// TODO support array values?
func ScopeMatches(query map[string]string, input map[string]interface{}) bool {
	for queryKey, queryVal := range query {
		inputVal, present := input[queryKey]
		if present && ((queryVal == "" || queryVal == "*") || (inputVal == "*")) {
			continue
		}
		if queryVal == inputVal {
			continue
		}
		return false
	}
	return true
}
