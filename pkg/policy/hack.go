package policy

import (
	"fmt"
	"os"
	"reflect"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/ast/location"
)

type PointerSet map[uintptr]struct{}

func ValuePointerSet(top ast.Value) PointerSet {
	ps := PointerSet{}

	var visit func(ast.Value)
	path := []interface{}{}
	visit = func(val ast.Value) {
		ref := reflect.ValueOf(val)
		if ref.Kind() == reflect.Pointer {
			ps[ref.Pointer()] = struct{}{}
			fmt.Fprintf(os.Stderr, "%v: %d\n", path, ref.Pointer())
		}

		switch v := val.(type) {
		case *ast.Array:
			for i := 0; i < v.Len(); i++ {
				path = append(path, i)
				visit(v.Elem(i).Value)
				path = path[:len(path)-1]
			}
		case ast.Object:
			v.Iter(func(k, c *ast.Term) error {
				path = append(path, k)
				visit(c.Value)
				path = path[:len(path)-1]
				return nil
			})
		default:
			fmt.Fprintf(os.Stderr, "%t: %v\n", v, v)
		}
	}

	visit(top)
	return ps
}

func WoopsInterfaceToTerm(top interface{}) (*ast.Term, error) {
    path := []interface{}{}
    var convert func(interface{}) (*ast.Term, error)
    convert = func(x interface{}) (*ast.Term, error) {
    	var val ast.Value
    	switch x := x.(type) {
    	case []interface{}:
    		terms := []*ast.Term{}
    		for k, v := range x {
        		fmt.Fprintf(os.Stderr, "Inside %d...\n", k)
        		path = append(path, k)
    			v, err := convert(v)
    			if err != nil {
    				return nil, err
    			}
    			path = path[:len(path)-1]
    			terms = append(terms, v)
    		}
    		val = ast.NewArray(terms...)
    	case map[string]interface{}:
    		/*
    			r := newobject(len(x))
    			for k, v := range x {
    				k, err := InterfaceToValue(k)
    				if err != nil {
    					return nil, err
    				}
    				v, err := InterfaceToValue(v)
    				if err != nil {
    					return nil, err
    				}
    				r.Insert(NewTerm(k), NewTerm(v))
    			}
    			return r, nil
    		*/
    		terms := [][2]*ast.Term{}
    		for k, v := range x {
        		fmt.Fprintf(os.Stderr, "Inside %v...\n", k)
    			k, err := convert(k)
    			if err != nil {
    				return nil, err
    			}
        		path = append(path, k)
    			v, err := convert(v)
    			if err != nil {
    				return nil, err
    			}
    			path = path[:len(path)-1]
    			terms = append(terms, [2]*ast.Term{k, v})
    		}
    		val = ast.NewObject(terms...)
    	default:
        	fmt.Fprintf(os.Stderr, "Stop on %s\n", reflect.ValueOf(x).Type().String())
    		if v, err := ast.InterfaceToValue(x); err == nil {
    			val = v
    		} else {
    			return nil, err
    		}
    	}

    	term := ast.NewTerm(val)
    	file := fmt.Sprintf("HAHA: %v\n", path)
    	term.Location = &location.Location{File: file}
    	return term, nil
    }

    return convert(top)
}
