package factcodec

import (
	"bytes"
	"encoding/gob"
	"reflect"
	"sync"
	"testing"
)

type testPayload struct {
	Mask  uint64
	Items []int
	Names map[string]int
	Child *testPayload
}

func TestEnvelopeValues(t *testing.T) {
	for _, value := range []testPayload{
		{},
		{Mask: ^uint64(0), Items: []int{}, Names: map[string]int{}, Child: &testPayload{}},
		{Items: []int{-1, 0, 42}, Names: map[string]int{"z": 1, "a": 2}},
	} {
		envelope := Wrap(value)
		data, err := envelope.GobEncode()
		if err != nil {
			t.Fatal(err)
		}
		var decoded Envelope[testPayload]
		if err := decoded.GobDecode(data); err != nil {
			t.Fatal(err)
		}
		if got := mustValue(t, &decoded); !reflect.DeepEqual(value, got) {
			t.Fatalf("got %#v, want %#v", got, value)
		}
		fresh, err := Encode(&value)
		if err != nil || !bytes.Equal(data, fresh) {
			t.Fatalf("unstable encoding: %v", err)
		}
	}
}

func TestEnvelopeReplacement(t *testing.T) {
	envelope := Wrap(testPayload{Mask: 99, Items: []int{1}, Child: &testPayload{Mask: 2}})
	if _, err := envelope.GobEncode(); err != nil {
		t.Fatal(err)
	}
	data, err := Encode(&testPayload{})
	if err != nil {
		t.Fatal(err)
	}
	if err := envelope.GobDecode(data); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(mustValue(t, &envelope), testPayload{}) {
		t.Fatal("decode retained old fields")
	}
	encoded, err := envelope.GobEncode()
	if err != nil || !bytes.Equal(encoded, data) {
		t.Fatal("decode retained old encoding")
	}
}

func TestEnvelopeRejectsInvalidData(t *testing.T) {
	valid, err := Encode(testPayload{Mask: 1})
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"legacy-json":   []byte(`{"Mask":1}`),
		"wrong-version": []byte("GHF\x03\xa0"),
		"truncated":     valid[:len(valid)-1],
		"trailing":      append(bytes.Clone(valid), 0),
		"null":          []byte(wireHeader + "\xf6"),
		"undefined":     []byte(wireHeader + "\xf7"),
		"duplicate":     []byte(wireHeader + "\xa2\x64Mask\x01\x64Mask\x02"),
		"unknown-field": []byte(wireHeader + "\xa1\x61X\x01"),
		"overflow":      []byte(wireHeader + "\xa1\x64Mask\x20"),
		"huge-array":    []byte(wireHeader + "\x9a\xff\xff\xff\xff"),
		"oversized":     make([]byte, maxPayloadBytes+len(wireHeader)+1),
	} {
		t.Run(name, func(t *testing.T) {
			// Framing errors fail the decode and keep the old evidence; payload
			// errors surface on first use, so the fact is never usable.
			envelope := Wrap(testPayload{Mask: 42})
			if err := envelope.GobDecode(data); err != nil {
				if mustValue(t, &envelope).Mask != 42 {
					t.Fatal("failed decode changed evidence")
				}
				return
			}
			if _, err := envelope.Value(); err == nil {
				t.Fatal("accepted invalid fact")
			}
		})
	}
}

// TestEnvelopeReexportsImportedBytes pins that an imported fact is passed on
// exactly as it arrived, whether or not it was decoded in between.
func TestEnvelopeReexportsImportedBytes(t *testing.T) {
	data, err := Encode(&testPayload{Items: []int{3, 1}, Names: map[string]int{"b": 2, "a": 1}})
	if err != nil {
		t.Fatal(err)
	}
	for _, decodeFirst := range []bool{false, true} {
		var envelope Envelope[testPayload]
		if err := envelope.GobDecode(data); err != nil {
			t.Fatal(err)
		}
		if decodeFirst {
			mustValue(t, &envelope)
		}
		if encoded, err := envelope.GobEncode(); err != nil || !bytes.Equal(encoded, data) {
			t.Fatalf("re-exported %x, %v; want %x", encoded, err, data)
		}
	}
}

// TestEnvelopeKeepsGobBufferSafely pins the gob behavior GobDecode relies on to
// keep a payload without copying it: decoding later messages from the same
// stream leaves an earlier envelope's bytes intact.
func TestEnvelopeKeepsGobBufferSafely(t *testing.T) {
	var stream bytes.Buffer
	encoder := gob.NewEncoder(&stream)
	first := testPayload{Mask: 1, Items: []int{1, 2, 3}}
	for _, value := range []testPayload{first, {Mask: 2, Names: map[string]int{"overwrite": 9}}, {Mask: 3}} {
		envelope := Wrap(value)
		if err := encoder.Encode(&envelope); err != nil {
			t.Fatal(err)
		}
	}
	decoder := gob.NewDecoder(&stream)
	var kept Envelope[testPayload]
	if err := decoder.Decode(&kept); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		var later Envelope[testPayload]
		if err := decoder.Decode(&later); err != nil {
			t.Fatal(err)
		}
	}
	if got := mustValue(t, &kept); !reflect.DeepEqual(got, first) {
		t.Fatalf("kept envelope changed after later decodes: %#v", got)
	}
}

func mustValue(t *testing.T, envelope *Envelope[testPayload]) testPayload {
	t.Helper()
	value, err := envelope.Value()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestEnvelopeConcurrentCopies(t *testing.T) {
	envelope := Wrap(testPayload{Names: map[string]int{"z": 3, "a": 7}})
	want, err := Encode(mustValue(t, &envelope))
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for range 16 {
		group.Go(func() {
			copy := envelope
			for range 20 {
				got, err := copy.GobEncode()
				if err != nil || !bytes.Equal(got, want) {
					t.Errorf("concurrent encoding: %x, %v", got, err)
				}
			}
		})
	}
	group.Wait()
}

func FuzzEnvelopeDecode(f *testing.F) {
	data, err := Encode(&testPayload{Items: []int{1, 2}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte(wireHeader + "\xf6"))
	f.Fuzz(func(t *testing.T, data []byte) {
		envelope := Wrap(testPayload{Mask: 99})
		if err := envelope.GobDecode(data); err != nil {
			return
		}
		encoded, err := envelope.GobEncode()
		if err != nil {
			t.Fatal(err)
		}
		var again Envelope[testPayload]
		if err := again.GobDecode(encoded); err != nil {
			t.Fatal(err)
		}
		value, err := envelope.Value()
		if err != nil {
			return
		}
		if !reflect.DeepEqual(value, mustValue(t, &again)) {
			t.Fatal("unstable decode")
		}
	})
}
