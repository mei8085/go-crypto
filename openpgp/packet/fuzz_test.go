//go:build go1.18
// +build go1.18

package packet

import (
	"bytes"
	"testing"
)

func FuzzPackets(f *testing.F) {
	f.Add([]byte("\x980\x040000\x16\t+\x06\x01\x04\x01\xdaG\x0f\x01\x00\x00"))
	// Seeds shared with TestMalformedPacketBoundaries and
	// TestLegalPacketRoundTrips. They are the minimal inputs that drive the
	// parser to each interesting boundary, so a local, offline run of
	// `go test -fuzz=FuzzPackets` starts from the same states the unit tests
	// pin down instead of rediscovering them.
	for _, seed := range boundaryFuzzSeeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Read(bytes.NewReader(data))
	})
}

// boundaryFuzzSeeds lists the minimal malformed samples from the boundary
// tests (openpgp/packet/malformed_boundary_test.go) together with a few legal
// packets, so a local fuzz run starts from the states those tests pin down.
var boundaryFuzzSeeds = [][]byte{
	// malformed
	{0xd1, 0x07, 0x02, 0x01, 0x00, 0x05, 0x01, 0x7f, 0xaa},             // user attribute, truncated subpacket
	{0xd1, 0x04, 0x02, 0x01, 0x00, 0x00},                               // user attribute, zero-length subpacket
	{0xc6, 0x09, 0x04, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x40, 0x01}, // public key, MPI overrun
	{0xc6, 0x08, 0x04, 0x00, 0x00, 0x00, 0x01, 0x63, 0xde, 0xad},       // public key, unknown algorithm
	{0xd2, 0x01, 0x03},                   // unknown SEIPD version
	{0xd4, 0x04, 0xd4, 0x01, 0x09, 0x00}, // AEAD packet, unknown mode
	{0xc8, 0x01, 0x09},                   // compressed, unknown algorithm
	{0xc8, 0x03, 0x02, 0xff, 0xff},       // compressed, invalid zlib header
	{0xcb, 0x04, 0x62, 0x00, 0x00, 0x00}, // literal, truncated metadata
	{0xc3, 0x03, 0x04, 0x07, 0x00},       // SKESK, truncated s2k specifier
	{0xd5, 0x06, 0xaa, 0xbb},             // padding, short body
	// legal
	{0xca, 0x03, 'P', 'G', 'P'},         // marker
	{0xcd, 0x01, 'Z'},                   // user id
	{0xcb, 0x06, 'b', 0x00, 0, 0, 0, 0}, // empty literal data
	{0xc8, 0x04, 0x00, 0xcd, 0x01, 'a'}, // uncompressed compressed packet
	{0xd5, 0x02, 0xaa, 0xbb},            // padding
}
