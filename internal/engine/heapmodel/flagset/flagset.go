// Package flagset provides a set whose members each carry one flag bit,
// sized for the common case of a few members.
//
// A set holds up to Inline members in place, with their flags in a mask,
// and moves them to a map beyond that. A map-backed set costs two
// allocations and a group sized for eight members even when it holds one.
package flagset

import (
	"iter"
	"maps"
)

// Inline is how many members a set holds before it spills to a map. Two
// keeps a heap pointee set in a 64-byte size class; profiles of real
// repositories allocated less with two than with one or four.
const Inline = 2

// Set is a set of keys with a flag each. Its zero value is empty and ready
// to use; reads through a nil *Set see an empty set. A Set holds its members
// inline while spill is nil and only in spill otherwise.
type Set[K comparable] struct {
	inline [Inline]K
	count  uint8
	flags  uint8
	spill  map[K]bool
}

// Len returns the number of members.
func (set *Set[K]) Len() int {
	switch {
	case set == nil:
		return 0
	case set.spill != nil:
		return len(set.spill)
	}
	return int(set.count)
}

// Lookup returns key's flag and whether key is a member.
func (set *Set[K]) Lookup(key K) (flag, ok bool) {
	if set == nil {
		return false, false
	}
	if set.spill != nil {
		flag, ok = set.spill[key]
		return flag, ok
	}
	if index := set.find(key); index >= 0 {
		return set.flags&(1<<index) != 0, true
	}
	return false, false
}

func (set *Set[K]) find(key K) int {
	for index := range set.count {
		if set.inline[index] == key {
			return int(index)
		}
	}
	return -1
}

// Put adds key with flag, or replaces the flag of a member.
func (set *Set[K]) Put(key K, flag bool) {
	if set.spill != nil {
		set.spill[key] = flag
		return
	}
	index := set.find(key)
	if index < 0 {
		if set.count == Inline {
			set.spillAll()
			set.spill[key] = flag
			return
		}
		index = int(set.count)
		set.inline[index] = key
		set.count++
	}
	set.setFlag(index, flag)
}

func (set *Set[K]) setFlag(index int, flag bool) {
	if flag {
		set.flags |= 1 << index
	} else {
		set.flags &^= 1 << index
	}
}

func (set *Set[K]) spillAll() {
	spill := make(map[K]bool, 2*Inline)
	for index := range set.count {
		spill[set.inline[index]] = set.flags&(1<<index) != 0
	}
	*set = Set[K]{spill: spill}
}

// Remove deletes key if it is a member.
func (set *Set[K]) Remove(key K) {
	switch {
	case set == nil:
		return
	case set.spill != nil:
		delete(set.spill, key)
		return
	}
	index := set.find(key)
	if index < 0 {
		return
	}
	last := int(set.count) - 1
	set.inline[index] = set.inline[last]
	set.setFlag(index, set.flags&(1<<last) != 0)
	var zero K
	set.inline[last] = zero
	set.setFlag(last, false)
	set.count--
}

// Clear removes every member and returns the set to inline storage.
func (set *Set[K]) Clear() {
	if set != nil {
		*set = Set[K]{}
	}
}

// All yields each member and its flag in no particular order. An inline set
// is iterated from a copy, so changes during iteration affect only later
// iterations, as a spilled set's may.
func (set *Set[K]) All() iter.Seq2[K, bool] {
	return func(yield func(K, bool) bool) {
		if set == nil {
			return
		}
		if set.spill != nil {
			for key, flag := range set.spill {
				if !yield(key, flag) {
					return
				}
			}
			return
		}
		inline, count, flags := set.inline, set.count, set.flags
		for index, key := range inline[:count] {
			if !yield(key, flags&(1<<index) != 0) {
				return
			}
		}
	}
}

// Clone returns an independent copy; cloning a nil set returns an empty one.
func (set *Set[K]) Clone() *Set[K] {
	switch {
	case set == nil:
		return &Set[K]{}
	case set.spill != nil:
		return &Set[K]{spill: maps.Clone(set.spill)}
	}
	copied := *set
	return &copied
}
