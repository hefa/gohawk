package factcodec

import (
	"errors"
	"go/types"
	"maps"
	"slices"
	"sync"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/tools/go/analysis"
)

// A summary per function was most of what every importer down a build
// decoded, and x/tools carries each fact with its package and object paths.
// A Group publishes the summaries of one type's methods, or of one package's
// functions, as one fact. Each entry keeps its own encoding and is decoded
// only when it is asked for, once, whether the group arrived encoded or, from
// a driver that passes facts in memory, as the published value.

// Group is a set of named summaries, sorted by name.
type Group[T any] struct {
	_       struct{} `cbor:",toarray"`
	Names   []string
	Entries []cbor.RawMessage
	// decoded holds each entry once decoded; copies of a group share it.
	decoded *groupDecodes[T]
}

type groupDecodes[T any] struct {
	once    []sync.Once
	entries []T
	ok      []bool
}

func newGroupDecodes[T any](count int) *groupDecodes[T] {
	return &groupDecodes[T]{once: make([]sync.Once, count), entries: make([]T, count), ok: make([]bool, count)}
}

var errGroup = errors.New("a group is not one sorted entry per name")

// NewGroup encodes the named summaries for publication.
func NewGroup[T any](entries map[string]T) (Group[T], error) {
	names := slices.Sorted(maps.Keys(entries))
	encoded := make([]cbor.RawMessage, len(names))
	for index, name := range names {
		entry := entries[name]
		data, err := MarshalPart(&entry)
		if err != nil {
			return Group[T]{}, err
		}
		encoded[index] = data
	}
	return Group[T]{Names: names, Entries: encoded, decoded: newGroupDecodes[T](len(names))}, nil
}

// UnmarshalCBOR decodes the group and prepares its per-entry decodes.
func (group *Group[T]) UnmarshalCBOR(data []byte) error {
	type plain Group[T]
	var decoded plain
	if err := UnmarshalPart(data, &decoded); err != nil {
		return err
	}
	if len(decoded.Names) != len(decoded.Entries) || !slices.IsSorted(decoded.Names) {
		return errGroup
	}
	*group = Group[T](decoded)
	group.decoded = newGroupDecodes[T](len(group.Names))
	return nil
}

// Lookup returns the named entry.
func (group *Group[T]) Lookup(name string) (T, bool) {
	var zero T
	index, found := slices.BinarySearch(group.Names, name)
	if !found || group.decoded == nil {
		return zero, false
	}
	decodes := group.decoded
	decodes.once[index].Do(func() {
		var entry T
		if err := UnmarshalPart(group.Entries[index], &entry); err == nil {
			decodes.entries[index], decodes.ok[index] = entry, true
		}
	})
	return decodes.entries[index], decodes.ok[index]
}

// Members returns the group's entries as the object facts they replace, for
// a dump: the methods of owner when it is a type, the functions of pkg
// otherwise. wrap makes an entry the fact its function's own would have been.
func (group *Group[T]) Members(owner types.Object, pkg *types.Package, wrap func(T) analysis.Fact) []analysis.ObjectFact {
	var members []analysis.ObjectFact
	for _, name := range group.Names {
		var member types.Object
		if typeName, ok := owner.(*types.TypeName); ok {
			if named, ok := typeName.Type().(*types.Named); ok {
				for method := range named.Methods() {
					if method.Name() == name {
						member = method
					}
				}
			}
		} else if pkg != nil {
			member = pkg.Scope().Lookup(name)
		}
		entry, ok := group.Lookup(name)
		if member == nil || !ok {
			continue
		}
		members = append(members, analysis.ObjectFact{Object: member, Fact: wrap(entry)})
	}
	return members
}

// Raw returns the named entry's encoding, to publish again unchanged.
func (group *Group[T]) Raw(name string) (cbor.RawMessage, bool) {
	index, found := slices.BinarySearch(group.Names, name)
	if !found {
		return nil, false
	}
	return group.Entries[index], true
}

// NewRawGroup makes a group of entries already encoded.
func NewRawGroup[T any](entries map[string]cbor.RawMessage) Group[T] {
	names := slices.Sorted(maps.Keys(entries))
	encoded := make([]cbor.RawMessage, len(names))
	for index, name := range names {
		encoded[index] = entries[name]
	}
	return Group[T]{Names: names, Entries: encoded, decoded: newGroupDecodes[T](len(names))}
}
