package policy

import "github.com/open-policy-agent/opa/ast"

func moduleSetsHelper(
	prefix ast.Ref,
	node *ast.ModuleTreeNode,
	traversedPath ast.Ref,
) []ModuleSet {
	if len(prefix) < 1 {
		var mods []ModuleSet
		if len(node.Modules) > 0 {
			mods = append(mods, ModuleSet{
				Path:    traversedPath,
				Modules: node.Modules,
			})
		}
		for k, child := range node.Children {
			nextPath := append(traversedPath, ast.NewTerm(k))
			mods = append(mods, moduleSetsHelper(prefix, child, nextPath)...)
		}
		return mods
	} else {
		head := prefix[0]
		if child, ok := node.Children[head.Value]; ok {
			nextPath := append(traversedPath, head)
			return moduleSetsHelper(prefix[1:], child, nextPath)
		}
	}
	return []ModuleSet{}
}

// ModuleSetsWithPrefix is a recursive function that extracts all ModuleSets under the
// specified prefix from a ModuleTreeNode.
func ModuleSetsWithPrefix(
	prefix ast.Ref,
	node *ast.ModuleTreeNode,
) []ModuleSet {
	return moduleSetsHelper(prefix, node, nil)
}
