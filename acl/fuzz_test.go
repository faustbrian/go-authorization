package acl

import "testing"

// FuzzDecodeDocument exercises parser/constructor panic safety; it intentionally ignores
// accepted/rejected results and is not a semantic round-trip or conformance oracle.
func FuzzDecodeDocument(f *testing.F) {
	f.Add([]byte(`{"version":1,"entries":[]}`))
	f.Add([]byte(`{"version":1,"unknown":true,"entries":[]}`))
	f.Add([]byte{0xff, 0x00, 0x01})
	f.Fuzz(func(t *testing.T, encoded []byte) {
		_, _ = DecodeDocument(encoded)
	})
}
