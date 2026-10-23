// Package factscope decides which of a package's objects its importers can
// see, so a pass need not publish facts no importer can read.
//
// An importer knows a dependency only through its export data, which holds
// the objects reachable from the package's exported API: exported
// package-level names and everything their types reach, through fields
// (exported or not), method sets, signatures, interface methods, type
// parameters and aliases. Function bodies are not loaded into go/types, so
// nothing an unexported body alone names becomes an object an importer can
// hold. A method outside that set is never an importer's callee, and its fact
// is never read; x/tools would still carry it to every importer down the
// build, since it re-exports every imported fact about a method.
package factscope

import (
	"go/token"
	"go/types"
	"sync"
)

// Visible is the set of a package's objects its importers can see.
type Visible struct {
	objects map[types.Object]bool
}

// API returns the objects of pkg its importers can see. Only pkg's own
// objects are of interest, since a pass publishes facts about nothing else,
// so the walk does not descend into another package's types beyond the type
// arguments that may name pkg's own. The fact passes of one unit share the
// answer.
func API(pkg *types.Package) Visible {
	visibleCache.Lock()
	defer visibleCache.Unlock()
	if visibleCache.pkg == pkg {
		return visibleCache.visible
	}
	walk := walker{pkg: pkg, objects: map[types.Object]bool{}, types: map[types.Type]bool{}}
	scope := pkg.Scope()
	for _, name := range scope.Names() {
		if token.IsExported(name) {
			walk.object(scope.Lookup(name))
		}
	}
	visibleCache.pkg, visibleCache.visible = pkg, Visible{objects: walk.objects}
	return visibleCache.visible
}

// visibleCache keeps the last package's answer; a unit has one package.
var visibleCache struct {
	sync.Mutex
	pkg     *types.Package
	visible Visible
}

// Contains reports whether importers can see object. A package-level
// exported object is always visible.
func (visible Visible) Contains(object types.Object) bool {
	return visible.objects[object]
}

type walker struct {
	pkg     *types.Package
	objects map[types.Object]bool
	types   map[types.Type]bool
}

func (walk walker) object(object types.Object) {
	if object == nil || walk.objects[object] {
		return
	}
	walk.objects[object] = true
	walk.typ(object.Type())
}

func (walk walker) typ(typ types.Type) {
	switch typed := typ.(type) {
	case *types.Named:
		walk.named(typed)
	case *types.Alias:
		walk.alias(typed)
	case *types.Pointer:
		walk.typ(typed.Elem())
	case *types.Slice:
		walk.typ(typed.Elem())
	case *types.Array:
		walk.typ(typed.Elem())
	case *types.Chan:
		walk.typ(typed.Elem())
	case *types.Map:
		walk.typ(typed.Key())
		walk.typ(typed.Elem())
	case *types.Signature:
		walk.signature(typed)
	case *types.Struct:
		for field := range typed.Fields() {
			walk.object(field)
		}
	case *types.Tuple:
		for variable := range typed.Variables() {
			walk.object(variable)
		}
	case *types.Interface:
		for method := range typed.Methods() {
			walk.object(method)
		}
		for embedded := range typed.EmbeddedTypes() {
			walk.typ(embedded)
		}
	case *types.Union:
		for term := range typed.Terms() {
			walk.typ(term.Type())
		}
	case *types.TypeParam:
		walk.parameter(typed)
	}
}

func (walk walker) named(typed *types.Named) {
	if arguments := typed.TypeArgs(); arguments != nil {
		for argument := range arguments.Types() {
			walk.typ(argument)
		}
	}
	origin := typed.Origin()
	if walk.types[origin] || origin.Obj().Pkg() != walk.pkg {
		return
	}
	walk.types[origin] = true
	walk.object(origin.Obj())
	walk.parameters(origin.TypeParams())
	walk.typ(origin.Underlying())
	for method := range origin.Methods() {
		walk.object(method)
	}
}

func (walk walker) alias(typed *types.Alias) {
	if walk.types[typed] {
		return
	}
	walk.types[typed] = true
	walk.object(typed.Obj())
	walk.typ(typed.Rhs())
}

func (walk walker) signature(typed *types.Signature) {
	walk.typ(typed.Params())
	walk.typ(typed.Results())
	walk.parameters(typed.TypeParams())
}

func (walk walker) parameters(parameters *types.TypeParamList) {
	if parameters == nil {
		return
	}
	for parameter := range parameters.TypeParams() {
		walk.typ(parameter)
	}
}

func (walk walker) parameter(typed *types.TypeParam) {
	if walk.types[typed] {
		return
	}
	walk.types[typed] = true
	walk.object(typed.Obj())
	walk.typ(typed.Constraint())
}

// Receiver returns the declared type a method belongs to, or nil for a
// package-level function or a method of an undeclared type.
func Receiver(object *types.Func) *types.TypeName {
	signature, ok := object.Type().(*types.Signature)
	if !ok || signature.Recv() == nil {
		return nil
	}
	receiver := signature.Recv().Type()
	if pointer, ok := receiver.(*types.Pointer); ok {
		receiver = pointer.Elem()
	}
	named, ok := receiver.(*types.Named)
	if !ok {
		return nil
	}
	return named.Origin().Obj()
}
