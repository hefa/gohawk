package factcodec

import (
	"fmt"
	"sync/atomic"
)

// Envelope hides a summary's fields from gob's type-descriptor traversal.
// Embed an unexported alias of it in a domain-owned fact type to also hide the
// envelope's descriptor; the domain still owns publication and validation.
// Values and everything reachable from them must stay immutable
// after publication. Each decode produces an independently owned value.
//
// An imported envelope keeps its encoding and decodes it on first use. A
// package imports the facts of every dependency whose objects its API can
// reach, but consults few of them, and decoding dominated whole-run cost.
// Re-exporting an imported fact reuses the bytes it arrived as.
type Envelope[T any] struct {
	state *envelopeState[T]
}

// This indirection matters: go/analysis copies fact values with reflection.
// Copies share the immutable payload and its state.
//
// A state starts with one half, the value of a published fact or the bytes of
// an imported one, and computes the other on first need. An imported state
// has its bytes, which framing never leaves empty; a published one has none.
// The decoded value is held behind one pointer, set once: a unit imports
// millions of facts it never consults, and the state of each was most of
// what importing them allocated. Two first readers may both decode; they
// produce the same value and one of them is kept. A published value keeps its
// encoding beside it the same way.
type envelopeState[T any] struct {
	data    []byte
	decoded atomic.Pointer[decodedValue[T]]
}

// decodedValue is a state's value, or why an encoding did not decode, and
// for a published value its encoding once made.
type decodedValue[T any] struct {
	value   T
	err     error
	encoded atomic.Pointer[[]byte]
}

// Wrap prepares a summary for publication without copying its reachable data.
func Wrap[T any](value T) Envelope[T] {
	state := &envelopeState[T]{}
	state.decoded.Store(&decodedValue[T]{value: value})
	return Envelope[T]{state: state}
}

// Value returns the summary. Its slices, maps, and pointers remain read-only.
// For an imported envelope, the first call decodes and validates the
// encoding; an error means the fact is unusable and must be treated as
// absent, never as an empty summary.
func (envelope *Envelope[T]) Value() (T, error) {
	state := envelope.state
	var zero T
	if state == nil {
		return zero, errNoPayload
	}
	decoded := state.decoded.Load()
	if decoded == nil {
		decoded = &decodedValue[T]{}
		decoded.err = Decode(state.data, &decoded.value)
		if !state.decoded.CompareAndSwap(nil, decoded) {
			decoded = state.decoded.Load()
		}
	}
	if decoded.err != nil {
		return zero, decoded.err
	}
	return decoded.value, nil
}

// AFact marks the enclosing domain type as an analysis fact.
func (*Envelope[T]) AFact() {}

// String preserves the domain's human-readable fact rendering.
func (envelope *Envelope[T]) String() string {
	value, err := envelope.Value()
	if err != nil {
		return fmt.Sprintf("undecodable fact: %v", err)
	}
	return fmt.Sprint(&value)
}

// GobEncode encodes only the payload, not its nested gob descriptors. The
// returned bytes belong to the envelope and must not be modified by callers.
func (envelope *Envelope[T]) GobEncode() ([]byte, error) {
	state := envelope.state
	if state == nil {
		return nil, errNoPayload
	}
	if len(state.data) != 0 {
		return state.data, nil
	}
	published := state.decoded.Load()
	if encoded := published.encoded.Load(); encoded != nil {
		return *encoded, nil
	}
	data, err := Encode(&published.value)
	if err != nil {
		return nil, err
	}
	if !published.encoded.CompareAndSwap(nil, &data) {
		return *published.encoded.Load(), nil
	}
	return data, nil
}

// GobDecode accepts an encoding after its framing checks and defers the full
// validating decode to Value. It replaces the envelope only on success.
//
// The envelope keeps data itself rather than a copy. gob reads each message
// into a buffer of its own and hands a GobDecoder a slice of it that it never
// writes again; copying every imported payload was a tenth of all the bytes
// a vet unit allocated. TestEnvelopeKeepsGobBufferSafely pins that behavior.
// A caller outside gob must not change data afterwards.
func (envelope *Envelope[T]) GobDecode(data []byte) error {
	if err := checkFraming(data); err != nil {
		return err
	}
	*envelope = Envelope[T]{state: &envelopeState[T]{data: data}}
	return nil
}
