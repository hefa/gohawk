package factcodec

import (
	"fmt"
	"sync"
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
// Copies share the immutable payload and its state, never copy a used mutex.
type envelopeState[T any] struct {
	encodeOnce sync.Once
	data       []byte
	encodeErr  error

	decodeOnce sync.Once
	value      T
	decodeErr  error
}

// Wrap prepares a summary for publication without copying its reachable data.
func Wrap[T any](value T) Envelope[T] {
	state := &envelopeState[T]{value: value}
	state.decodeOnce.Do(func() {})
	return Envelope[T]{state: state}
}

// Value returns the summary. Its slices, maps, and pointers remain read-only.
// For an imported envelope, the first call decodes and validates the
// encoding; an error means the fact is unusable and must be treated as
// absent, never as an empty summary.
func (envelope *Envelope[T]) Value() (T, error) {
	state := envelope.state
	if state == nil {
		var zero T
		return zero, errNoPayload
	}
	state.decodeOnce.Do(func() { state.decodeErr = Decode(state.data, &state.value) })
	return state.value, state.decodeErr
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
	state.encodeOnce.Do(func() {
		if state.data == nil {
			state.data, state.encodeErr = Encode(&state.value)
		}
	})
	return state.data, state.encodeErr
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
	state := &envelopeState[T]{data: data}
	state.encodeOnce.Do(func() {})
	*envelope = Envelope[T]{state: state}
	return nil
}
