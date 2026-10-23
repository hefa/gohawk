// Package flagset provides a set whose members each carry one flag bit,
// sized for the common case of a few members.
//
// A set holds up to Inline members in place, with their flags in a mask,
// moves them to one spilled block of up to Spilled members beyond that, and
// to a map in that block beyond Spilled. A map costs two allocations and a
// group of eight slots even when it holds three members, and most sets that
// outgrow Inline stay small.
package flagset

import (
	"iter"
	"maps"
)

// Inline is how many members a set holds before it spills to a map. Two
// keeps a heap pointee set in a 64-byte size class; profiles of real
// repositories allocated less with two than with one or four.
const Inline = 2

// Spilled is how many members a spilled block holds before it moves them
// to a map: as many as one flag byte has bits.
const Spilled = 8

// Set is a set of keys with a flag each. Its zero value is empty and ready
// to use; reads through a nil *Set see an empty set. A Set holds its members
// inline while spill is nil and only in spill otherwise.
type Set[K comparable] struct {
	inline [Inline]K
	count  uint8
	flags  uint8
	// version counts the changes to the set's members or flags, so a
	// caller can tell whether an update changed anything.
	version uint32
	spill   *spilled[K]
}

// spilled holds a set's members in keys while many is nil, and only in
// many otherwise.
type spilled[K comparable] struct {
	keys  [Spilled]K
	count uint8
	flags uint8
	many  map[K]bool
}

// Version changes whenever the set's members or their flags do; a nil set
// has version zero.
func (set *Set[K]) Version() uint32 {
	if set == nil {
		return 0
	}
	return set.version
}

// Len returns the number of members.
func (set *Set[K]) Len() int {
	switch {
	case set == nil:
		return 0
	case set.spill != nil:
		return set.spill.len()
	}
	return int(set.count)
}

// Lookup returns key's flag and whether key is a member.
func (set *Set[K]) Lookup(key K) (flag, ok bool) {
	if set == nil {
		return false, false
	}
	if set.spill != nil {
		return set.spill.lookup(key)
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
		if set.spill.put(key, flag) {
			set.version++
		}
		return
	}
	index := set.find(key)
	if index < 0 {
		if set.count == Inline {
			set.spillAll()
			set.spill.put(key, flag)
			set.version++
			return
		}
		index = int(set.count)
		set.inline[index] = key
		set.count++
		set.setFlag(index, flag)
		set.version++
		return
	}
	if (set.flags&(1<<index) != 0) != flag {
		set.setFlag(index, flag)
		set.version++
	}
}

func (set *Set[K]) setFlag(index int, flag bool) {
	if flag {
		set.flags |= 1 << index
	} else {
		set.flags &^= 1 << index
	}
}

func (set *Set[K]) spillAll() {
	spill := &spilled[K]{count: set.count, flags: set.flags}
	copy(spill.keys[:], set.inline[:set.count])
	*set = Set[K]{spill: spill, version: set.version}
}

// Remove deletes key if it is a member.
func (set *Set[K]) Remove(key K) {
	switch {
	case set == nil:
		return
	case set.spill != nil:
		if set.spill.remove(key) {
			set.version++
		}
		return
	}
	index := set.find(key)
	if index < 0 {
		return
	}
	set.version++
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
	if set != nil && set.Len() != 0 {
		*set = Set[K]{version: set.version + 1}
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
			set.spill.all(yield)
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
		spill := *set.spill
		spill.many = maps.Clone(spill.many)
		return &Set[K]{spill: &spill}
	}
	copied := *set
	return &copied
}

func (spill *spilled[K]) len() int {
	if spill.many != nil {
		return len(spill.many)
	}
	return int(spill.count)
}

func (spill *spilled[K]) find(key K) int {
	for index := range spill.count {
		if spill.keys[index] == key {
			return int(index)
		}
	}
	return -1
}

func (spill *spilled[K]) lookup(key K) (flag, ok bool) {
	if spill.many != nil {
		flag, ok = spill.many[key]
		return flag, ok
	}
	if index := spill.find(key); index >= 0 {
		return spill.flags&(1<<index) != 0, true
	}
	return false, false
}

// put adds key with flag, or replaces a member's flag, and reports whether
// that changed the set.
func (spill *spilled[K]) put(key K, flag bool) bool {
	if spill.many != nil {
		if old, ok := spill.many[key]; ok && old == flag {
			return false
		}
		spill.many[key] = flag
		return true
	}
	index := spill.find(key)
	if index >= 0 {
		if (spill.flags&(1<<index) != 0) == flag {
			return false
		}
		spill.flags ^= 1 << index
		return true
	}
	if spill.count == Spilled {
		many := make(map[K]bool, 2*Spilled)
		for index, member := range spill.keys {
			many[member] = spill.flags&(1<<index) != 0
		}
		many[key] = flag
		*spill = spilled[K]{many: many}
		return true
	}
	spill.keys[spill.count] = key
	if flag {
		spill.flags |= 1 << spill.count
	}
	spill.count++
	return true
}

// remove deletes key and reports whether it was a member.
func (spill *spilled[K]) remove(key K) bool {
	if spill.many != nil {
		if _, ok := spill.many[key]; !ok {
			return false
		}
		delete(spill.many, key)
		return true
	}
	index := spill.find(key)
	if index < 0 {
		return false
	}
	last := int(spill.count) - 1
	spill.keys[index] = spill.keys[last]
	if spill.flags&(1<<last) != 0 {
		spill.flags |= 1 << index
	} else {
		spill.flags &^= 1 << index
	}
	var zero K
	spill.keys[last] = zero
	spill.flags &^= 1 << last
	spill.count--
	return true
}

// all yields the members from a copy of the block, as an inline set is
// iterated, so changes during iteration affect only later iterations.
func (spill *spilled[K]) all(yield func(K, bool) bool) {
	if spill.many != nil {
		for key, flag := range spill.many {
			if !yield(key, flag) {
				return
			}
		}
		return
	}
	keys, count, flags := spill.keys, spill.count, spill.flags
	for index, key := range keys[:count] {
		if !yield(key, flags&(1<<index) != 0) {
			return
		}
	}
}
