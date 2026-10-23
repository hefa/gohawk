// Package factscope decides which of a package's objects its importers can
// see, so a pass need not publish facts no importer can read.
//
// An importer knows a dependency only through its export data, and can hold
// a value only of a type the package's exported API leads it to: from
// exported package-level names through exported and embedded fields, method
// sets, exported methods' signatures, interface methods, type parameters and
// aliases. Code in another package can follow neither an unexported field,
// unless it is embedded and so promotes its type's methods, nor an
// unexported method. Function bodies are not loaded into go/types, so
// nothing an unexported body alone names is reachable either. A method of a
// type outside that set is never an importer's callee, and its fact is
// never read; x/tools would still carry it to every importer down the
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
	// pkg, when set, keeps the walk to its own types.
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
		walk.structure(typed)
	case *types.Tuple:
		for variable := range typed.Variables() {
			walk.object(variable)
		}
	case *types.Interface:
		walk.iface(typed)
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
	if walk.types[origin] || walk.pkg != nil && origin.Obj().Pkg() != walk.pkg {
		return
	}
	walk.types[origin] = true
	walk.object(origin.Obj())
	walk.parameters(origin.TypeParams())
	walk.typ(origin.Underlying())
	for method := range origin.Methods() {
		walk.method(method)
	}
}

func (walk walker) structure(typed *types.Struct) {
	for field := range typed.Fields() {
		if field.Exported() || field.Embedded() {
			walk.object(field)
		}
	}
}

func (walk walker) iface(typed *types.Interface) {
	for method := range typed.Methods() {
		walk.method(method)
	}
	for embedded := range typed.EmbeddedTypes() {
		walk.typ(embedded)
	}
}

// method marks a method visible. Code in another package can call only an
// exported one, so only its signature leads anywhere; an unexported method
// is still visible, since an importer asking which methods of a result type
// release its fields reads their summaries.
func (walk walker) method(method *types.Func) {
	if method.Exported() {
		walk.object(method)
		return
	}
	walk.objects[method] = true
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

// Types returns every declared type, of pkg or of another package, that
// code importing pkg can hold a value of and call a method on through pkg's
// API: the types whose method facts pkg must carry for its importers.
// Unlike API it follows other packages' types. The fact
// passes of one unit share the answer.
func Types(pkg *types.Package) map[*types.TypeName]bool {
	typesCache.Lock()
	defer typesCache.Unlock()
	if typesCache.pkg == pkg {
		return typesCache.types
	}
	walk := walker{objects: map[types.Object]bool{}, types: map[types.Type]bool{}}
	scope := pkg.Scope()
	for _, name := range scope.Names() {
		if token.IsExported(name) {
			walk.object(scope.Lookup(name))
		}
	}
	reached := map[*types.TypeName]bool{}
	for object := range walk.objects {
		if name, ok := object.(*types.TypeName); ok {
			reached[name] = true
		}
	}
	typesCache.pkg, typesCache.types = pkg, reached
	return reached
}

var typesCache struct {
	sync.Mutex
	pkg   *types.Package
	types map[*types.TypeName]bool
}
