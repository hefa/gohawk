package factscope_test

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"github.com/kojah/gohawk/internal/analysis/factscope"
)

// Every method an importer can reach through the API is visible, however it
// is reached; a method of a type the API never names is not.
func TestAPIVisibility(t *testing.T) {
	const source = `package p

type returned struct{}
func (returned) Close() error { return nil }
func New() *returned { return nil }

type inner struct{}
func (*inner) Flush() {}
type Outer struct{ inner }

type constraint interface{ Wait() }
type waiter struct{}
func (waiter) Wait() {}
func Use[T constraint](T) {}

type hidden struct{}
func (hidden) Stop() {}
func helper() hidden { return hidden{} }

func Exported() {}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "p.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := (&types.Config{Importer: importer.Default()}).Check("p", fset, []*ast.File{file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	visible := factscope.API(pkg)
	method := func(typeName, name string) types.Object {
		object, _, _ := types.LookupFieldOrMethod(pkg.Scope().Lookup(typeName).Type(), true, pkg, name)
		return object
	}
	for _, test := range []struct {
		name   string
		object types.Object
		want   bool
	}{
		{"exported function", pkg.Scope().Lookup("Exported"), true},
		{"method of a returned unexported type", method("returned", "Close"), true},
		{"method promoted through an unexported embedded field", method("inner", "Flush"), true},
		{"method of a constraint", method("constraint", "Wait"), true},
		{"method of a type only an unexported function names", method("hidden", "Stop"), false},
	} {
		if got := visible.Contains(test.object); got != test.want {
			t.Errorf("%s: visible=%v, want %v", test.name, got, test.want)
		}
	}
}
