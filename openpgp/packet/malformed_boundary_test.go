// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

// This file pins down how the packet parser behaves on truncated and
// otherwise malformed input. The samples are minimal: each one is the
// byte string that drives the parser into a particular state, so a failure
// points at one boundary instead of a whole message.
//
// The tests cover three properties:
//
//   - Parsing boundaries are reproducible. The exact error class and the
//     exact number of bytes consumed are asserted, and every sample is parsed
//     several times to confirm the same result each time.
//   - A failed packet never swallows the bytes of the following packet. Each
//     sample is followed by a sentinel packet; after the failure the sentinel
//     must still parse.
//   - A packet that failed to parse is not left behind as a usable half
//     product: calling Decrypt on it returns an error instead of panicking,
//     and integrity failures are sticky once observed.
//
// Legal packets and messages are exercised by the round-trip tests in the
// second half of this file (and by the pre-existing tests in this package).
// Everything runs offline.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
)

// sentinelPacket is a minimal well-formed UserId packet ("Z"). It is appended
// after every malformed sample: if the malformed packet read past its declared
// body, the sentinel can no longer be parsed.
var sentinelPacket = []byte{0xcd, 0x01, 'Z'}

// errClass is the error class expected from a malformed sample.
type errClass int

const (
	wantErrAny errClass = iota
	wantStructural
	wantUnsupported
	wantUnexpectedEOF
)

func (c errClass) check(t *testing.T, name string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected an error, got nil", name)
	}
	var structural pgperrors.StructuralError
	var unsupported pgperrors.UnsupportedError
	switch c {
	case wantStructural:
		if !errors.As(err, &structural) {
			t.Fatalf("%s: expected StructuralError, got %T: %v", name, err, err)
		}
	case wantUnsupported:
		if !errors.As(err, &unsupported) {
			t.Fatalf("%s: expected UnsupportedError, got %T: %v", name, err, err)
		}
	case wantUnexpectedEOF:
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("%s: expected io.ErrUnexpectedEOF, got %T: %v", name, err, err)
		}
	}
}

// TestMalformedPacketBoundaries checks that minimal malformed packets fail
// with a defined error, consume exactly their declared packet body, and leave
// the following packet readable.
func TestMalformedPacketBoundaries(t *testing.T) {
	salt := bytes.Repeat([]byte{0xaa}, 32)

	cases := []struct {
		name string
		raw  []byte
		// consumed is the exact number of bytes the parser may take.
		consumed int
		want     errClass
		// noSentinel disables the "next packet is still readable" check for
		// samples whose declared length extends past the input on purpose.
		noSentinel bool
		// nextSkips is set when Reader.Next is documented to skip this
		// UnsupportedError packet and return the following packet directly.
		nextSkips bool
	}{
		{
			// User attribute: one valid subpacket, then a subpacket that
			// declares more content than the packet holds.
			name:     "user-attribute-truncated-subpacket",
			raw:      []byte{0xd1, 0x07, 0x02, 0x01, 0x00, 0x05, 0x01, 0x7f, 0xaa},
			consumed: 9,
			want:     wantStructural,
		},
		{
			// User attribute: zero-length subpacket is reserved for future
			// extensions, so parsing stops at the first valid subpacket.
			name:     "user-attribute-zero-length-subpacket",
			raw:      []byte{0xd1, 0x04, 0x02, 0x01, 0x00, 0x00},
			consumed: 6,
			want:     wantStructural,
		},
		{
			// Public key: an MPI declares 64 bits (8 bytes) while the packet
			// body carries only one of them.
			name:     "public-key-mpi-overrun",
			raw:      []byte{0xc6, 0x09, 0x04, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x40, 0x01},
			consumed: 11,
			want:     wantUnexpectedEOF,
		},
		{
			// Public key with an unimplemented algorithm; the whole body is
			// still skipped. Reader.Next treats an unsupported non-message
			// packet as skippable, so the following packet is returned.
			name:      "public-key-unknown-algorithm",
			raw:       []byte{0xc6, 0x08, 0x04, 0x00, 0x00, 0x00, 0x01, 0x63, 0xde, 0xad},
			consumed:  10,
			want:      wantUnsupported,
			nextSkips: true,
		},
		{
			// Integrity-protected data packet with an unknown version octet.
			name:     "seipd-unknown-version",
			raw:      []byte{0xd2, 0x01, 0x03},
			consumed: 3,
			want:     wantUnsupported,
		},
		{
			// SEIPDv2 header cut short before the salt: cipher, mode and
			// chunk size are present, but only 31 of the 32 salt bytes are.
			name:     "seipd-v2-truncated-salt",
			raw:      append([]byte{0xd2, 0x23, 0x02, 0x07, 0x01, 0x01}, bytes.Repeat([]byte{0xaa}, 31)...),
			consumed: 37,
			want:     wantStructural,
		},
		{
			// SEIPDv2 with a complete header but an unimplemented AEAD mode.
			name:     "seipd-v2-unknown-mode",
			raw:      append([]byte{0xd2, 0x23, 0x02, 0x07, 0x09}, salt...),
			consumed: 37,
			want:     wantUnsupported,
		},
		{
			// SEIPDv2 whose cipher has no 16-byte block size.
			name:     "seipd-v2-invalid-cipher",
			raw:      append([]byte{0xd2, 0x23, 0x02, 0x00, 0x01}, salt...),
			consumed: 37,
			want:     wantUnsupported,
		},
		{
			// AEAD encrypted data packet (tag 20) with an unknown AEAD mode.
			name:     "aead-encrypted-unknown-mode",
			raw:      []byte{0xd4, 0x04, 0xd4, 0x01, 0x09, 0x00},
			consumed: 6,
			want:     wantErrAny, // errors.AEADError
		},
		{
			// AEAD encrypted data packet whose nonce is missing.
			name:     "aead-encrypted-missing-nonce",
			raw:      []byte{0xd4, 0x04, 0xd4, 0x01, 0x02, 0x00},
			consumed: 6,
			want:     wantErrAny, // errors.AEADError
		},
		{
			// Compressed packet with an unknown compression algorithm.
			name:     "compressed-unknown-algorithm",
			raw:      []byte{0xc8, 0x01, 0x09},
			consumed: 3,
			want:     wantUnsupported,
		},
		{
			// Compressed packet using zlib, but the stream is not valid zlib.
			name:     "compressed-invalid-zlib-header",
			raw:      []byte{0xc8, 0x03, 0x02, 0xff, 0xff},
			consumed: 5,
			want:     wantErrAny, // zlib: invalid header
		},
		{
			// Literal data packet cut inside its fixed metadata.
			name:     "literal-data-truncated-metadata",
			raw:      []byte{0xcb, 0x04, 0x62, 0x00, 0x00, 0x00},
			consumed: 6,
			want:     wantUnexpectedEOF,
		},
		{
			// Symmetric-key encrypted session key packet cut inside the s2k
			// specifier.
			name:     "skesk-truncated-s2k",
			raw:      []byte{0xc3, 0x03, 0x04, 0x07, 0x00},
			consumed: 5,
			want:     wantUnexpectedEOF,
		},
		{
			// SKESK declaring a 64-byte encrypted session key: the parser
			// refuses sizes at the limit instead of accepting a partial key.
			// Reader.Next skips this unsupported packet as well.
			name:      "skesk-oversized-session-key",
			raw:       append([]byte{0xc3, 0x44, 0x04, 0x07, 0x00, 0x08}, make([]byte, 64)...),
			consumed:  70,
			want:      wantUnsupported,
			nextSkips: true,
		},
		{
			// Padding packet whose declared length (6) exceeds the whole
			// stream (2 padding bytes + 3 sentinel bytes). Padding has no
			// fixed layout, so the sentinel is consumed as padding and no
			// "next packet" check applies.
			name:       "padding-declared-longer-than-stream",
			raw:        []byte{0xd5, 0x06, 0xaa, 0xbb},
			consumed:   7,
			want:       wantUnexpectedEOF,
			noSentinel: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Parse repeatedly: the boundary must be reproducible.
			for attempt := 0; attempt < 3; attempt++ {
				stream := append(append([]byte{}, tc.raw...), sentinelPacket...)
				cr := &countingReader{r: bytes.NewReader(stream)}
				if _, err := Read(cr); err == nil {
					t.Fatalf("attempt %d: expected an error, got nil", attempt)
				} else {
					tc.want.check(t, tc.name, err)
				}
				wantConsumed := tc.consumed
				if tc.noSentinel {
					wantConsumed = len(stream)
				}
				if cr.n != wantConsumed {
					t.Fatalf("attempt %d: consumed %d bytes, want %d", attempt, cr.n, wantConsumed)
				}
			}

			if tc.noSentinel {
				return
			}

			// The malformed packet must not consume the sentinel; a Reader
			// must also recover and return it (or, for unsupported packets
			// that Next is documented to skip, return it on the first call).
			stream := append(append([]byte{}, tc.raw...), sentinelPacket...)
			r := NewReader(bytes.NewReader(stream))
			if !tc.nextSkips {
				if _, err := r.Next(); err == nil {
					t.Fatalf("expected an error from Next, got nil")
				}
			}
			p, err := r.Next()
			if err != nil {
				t.Fatalf("sentinel packet was not readable after the failure: %v", err)
			}
			uid, ok := p.(*UserId)
			if !ok {
				t.Fatalf("sentinel parsed as %T, want *UserId", p)
			}
			if uid.Id != "Z" {
				t.Fatalf("sentinel UserId is %q, want %q", uid.Id, "Z")
			}
		})
	}
}

// TestMalformedPacketNoUsableHalfProduct checks that packets which failed to
// parse cannot be turned into decryption streams. Before the fix these calls
// dereferenced uninitialised state and panicked; now they must return an
// error.
func TestMalformedPacketNoUsableHalfProduct(t *testing.T) {
	t.Run("skesk", func(t *testing.T) {
		// Cipher octet 0 is not supported, so parsing stops before the s2k
		// function exists.
		p, err := Read(bytes.NewReader([]byte{0xc3, 0x02, 0x04, 0x00}))
		if err == nil {
			t.Fatal("expected a parse error")
		}
		ske, ok := p.(*SymmetricKeyEncrypted)
		if !ok {
			t.Fatalf("parsed packet is %T, want *SymmetricKeyEncrypted", p)
		}
		if _, _, derr := ske.Decrypt([]byte("pw")); derr == nil {
			t.Fatal("Decrypt on a partially parsed SKESK returned no error")
		}
	})

	t.Run("seipd-v2", func(t *testing.T) {
		// Chunk size byte 0xaa (> 16) is rejected after the version was read
		// but before Contents was set.
		raw := append([]byte{0xd2, 0x25, 0x02, 0x07, 0x01}, bytes.Repeat([]byte{0xaa}, 32)...)
		p, err := Read(bytes.NewReader(raw))
		if err == nil {
			t.Fatal("expected a parse error")
		}
		se, ok := p.(*SymmetricallyEncrypted)
		if !ok {
			t.Fatalf("parsed packet is %T, want *SymmetricallyEncrypted", p)
		}
		if rc, derr := se.Decrypt(CipherAES128, make([]byte, 16)); derr == nil {
			rc.Close()
			t.Fatal("Decrypt on a partially parsed SEIPD packet returned no error")
		}
	})

	t.Run("aead-encrypted", func(t *testing.T) {
		p, err := Read(bytes.NewReader([]byte{0xd4, 0x04, 0xd4, 0x01, 0x09, 0x00}))
		if err == nil {
			t.Fatal("expected a parse error")
		}
		ae, ok := p.(*AEADEncrypted)
		if !ok {
			t.Fatalf("parsed packet is %T, want *AEADEncrypted", p)
		}
		if rc, derr := ae.Decrypt(CipherAES128, make([]byte, 16)); derr == nil {
			rc.Close()
			t.Fatal("Decrypt on a partially parsed AEAD packet returned no error")
		}
	})
}

// TestIntegrityFailureIsSticky checks that once an integrity-protected stream
// has been closed, it neither reports success on a second Close nor keeps
// returning plaintext. This makes the failure observable to callers that
// stop reading early (or close twice by accident).
func TestIntegrityFailureIsSticky(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i + 1)
	}
	badKey := append([]byte{}, key...)
	badKey[0] ^= 0xff

	buildMdc := func(t *testing.T) []byte {
		t.Helper()
		w := new(bytes.Buffer)
		wc, err := SerializeSymmetricallyEncrypted(&noOpCloser{w: w}, CipherAES128, false, CipherSuite{}, key, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := wc.Write([]byte{0xcb, 0x00}); err != nil {
			t.Fatal(err)
		}
		if err := wc.Close(); err != nil {
			t.Fatal(err)
		}
		return append([]byte{}, w.Bytes()...)
	}

	t.Run("mdc-wrong-key", func(t *testing.T) {
		p, err := Read(bytes.NewReader(buildMdc(t)))
		if err != nil {
			t.Fatal(err)
		}
		rc, err := p.(*SymmetricallyEncrypted).Decrypt(CipherAES128, badKey)
		if err != nil {
			t.Fatal(err)
		}
		// Close without reading: the MDC check must fail.
		if err := rc.Close(); !errors.Is(err, pgperrors.ErrMDCHashMismatch) {
			t.Fatalf("first Close = %v, want MDC hash mismatch", err)
		}
		// Closing again must keep reporting the failure.
		if err := rc.Close(); !errors.Is(err, pgperrors.ErrMDCHashMismatch) {
			t.Fatalf("second Close = %v, want MDC hash mismatch", err)
		}
		// Reading after the failed close must not hand out plaintext.
		buf := make([]byte, 8)
		n, err := rc.Read(buf)
		if n != 0 || err == nil {
			t.Fatalf("Read after failed Close = (%d, %v), want (0, error)", n, err)
		}
	})

	t.Run("mdc-valid-after-read", func(t *testing.T) {
		raw := buildMdc(t)
		p, err := Read(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		rc, err := p.(*SymmetricallyEncrypted).Decrypt(CipherAES128, key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(rc); err != nil {
			t.Fatalf("reading valid stream: %v", err)
		}
		if err := rc.Close(); err != nil {
			t.Fatalf("Close of valid stream: %v", err)
		}
		// A reader that has been fully consumed and closed stays at EOF.
		if n, err := rc.Read(make([]byte, 4)); n != 0 || err != io.EOF {
			t.Fatalf("Read after successful Close = (%d, %v), want (0, io.EOF)", n, err)
		}
	})

	buildAead := func(t *testing.T, aeadV2 bool) []byte {
		t.Helper()
		config := &Config{DefaultCipher: CipherAES128, AEADConfig: &AEADConfig{DefaultMode: AEADModeOCB, ChunkSize: 64}}
		w := new(bytes.Buffer)
		var wc io.WriteCloser
		var err error
		if aeadV2 {
			wc, err = SerializeSymmetricallyEncrypted(&noOpCloser{w: w}, CipherAES128, true, CipherSuite{Cipher: CipherAES128, Mode: AEADModeOCB}, key, config)
		} else {
			wc, err = SerializeAEADEncrypted(w, key, config)
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := wc.Write(bytes.Repeat([]byte{'A'}, 200)); err != nil {
			t.Fatal(err)
		}
		if err := wc.Close(); err != nil {
			t.Fatal(err)
		}
		return append([]byte{}, w.Bytes()...)
	}

	for _, tc := range []struct {
		name string
		v2   bool
	}{
		{"seipd-v2-close-early", true},
		{"aead-encrypted-close-early", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Read(bytes.NewReader(buildAead(t, tc.v2)))
			if err != nil {
				t.Fatal(err)
			}
			var rc io.ReadCloser
			if tc.v2 {
				rc, err = p.(*SymmetricallyEncrypted).Decrypt(CipherAES128, key)
			} else {
				rc, err = p.(*AEADEncrypted).Decrypt(CipherAES128, key)
			}
			if err != nil {
				t.Fatal(err)
			}
			// Read only part of the stream, then close. The final tag has not
			// been verified, so Close must report the truncated stream.
			if _, err := rc.Read(make([]byte, 10)); err != nil {
				t.Fatal(err)
			}
			first := rc.Close()
			if !errors.Is(first, pgperrors.ErrAEADTagVerification) {
				t.Fatalf("first Close = %v, want AEAD tag verification failure", first)
			}
			if second := rc.Close(); !errors.Is(second, pgperrors.ErrAEADTagVerification) {
				t.Fatalf("second Close = %v, want AEAD tag verification failure", second)
			}
			// No further plaintext may be returned once integrity failed.
			if n, err := rc.Read(make([]byte, 10)); n != 0 || err == nil {
				t.Fatalf("Read after failed Close = (%d, %v), want (0, error)", n, err)
			}
		})
	}
}

// TestCompressedReaderConsumesTrailingPacket pins the other side of the
// boundary: a compressed packet that declares a definite length must not read
// into the packet that follows it, even though its body is only decoded
// lazily.
func TestCompressedReaderConsumesTrailingPacket(t *testing.T) {
	w := new(bytes.Buffer)
	wc, err := SerializeCompressed(&noOpCloser{w: w}, CompressionZIP, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wc.Write([]byte{0xcb, 0x00}); err != nil {
		t.Fatal(err)
	}
	if err := wc.Close(); err != nil {
		t.Fatal(err)
	}
	compressed := append([]byte{}, w.Bytes()...)

	stream := append(append([]byte{}, compressed...), sentinelPacket...)
	cr := &countingReader{r: bytes.NewReader(stream)}
	p, err := Read(cr)
	if err != nil {
		t.Fatal(err)
	}
	// Reading the packet header must only take the header; the body is
	// consumed lazily by the decompressor, so the sentinel must still be
	// untouched.
	if cr.n >= len(stream) {
		t.Fatalf("parser consumed %d bytes, past the compressed packet", cr.n)
	}

	c, ok := p.(*Compressed)
	if !ok {
		t.Fatalf("parsed %T, want *Compressed", p)
	}
	body, err := io.ReadAll(c.Body)
	if err != nil {
		t.Fatalf("reading compressed body: %v", err)
	}
	want, _ := hex.DecodeString("cb00")
	if !bytes.Equal(body, want) {
		t.Fatalf("decompressed body = %x, want %x", body, want)
	}
	// The decompressor must have consumed exactly the compressed packet, no
	// more: the sentinel is still readable.
	if cr.n != len(compressed) {
		t.Fatalf("after decoding, consumed %d bytes, want %d", cr.n, len(compressed))
	}
	rest := stream[cr.n:]
	p2, err := Read(bytes.NewReader(rest))
	if err != nil {
		t.Fatalf("sentinel not readable: %v", err)
	}
	if _, ok := p2.(*UserId); !ok {
		t.Fatalf("sentinel parsed as %T, want *UserId", p2)
	}
}

// TestLegalPacketRoundTrips is the "no regression" half of the boundary suite:
// the legal inputs used elsewhere are parsed through the unchanged public API
// and must keep working.
func TestLegalPacketRoundTrips(t *testing.T) {
	t.Run("session-key-and-mdc-message", func(t *testing.T) {
		// A complete SKESK + SEIPDv1 message with a literal packet inside,
		// produced with a deterministic random source so the bytes are stable.
		whole := new(bytes.Buffer)
		sessionKey, err := SerializeSymmetricKeyEncrypted(whole, []byte("pw"), &Config{
			Rand:          &sequenceReader{},
			DefaultCipher: CipherAES128,
		})
		if err != nil {
			t.Fatal(err)
		}
		enc, err := SerializeSymmetricallyEncrypted(&noOpCloser{w: whole}, CipherAES128, false, CipherSuite{}, sessionKey, &Config{Rand: &sequenceReader{}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := enc.Write([]byte{0xcb, 0x06, 'b', 0x00, 0, 0, 0, 0}); err != nil {
			t.Fatal(err)
		}
		if err := enc.Close(); err != nil {
			t.Fatal(err)
		}

		r := NewReader(bytes.NewReader(whole.Bytes()))
		p, err := r.Next()
		if err != nil {
			t.Fatal(err)
		}
		ske, ok := p.(*SymmetricKeyEncrypted)
		if !ok {
			t.Fatalf("first packet is %T, want *SymmetricKeyEncrypted", p)
		}
		key, cipher, err := ske.Decrypt([]byte("pw"))
		if err != nil {
			t.Fatal(err)
		}
		p, err = r.Next()
		if err != nil {
			t.Fatal(err)
		}
		se, ok := p.(*SymmetricallyEncrypted)
		if !ok {
			t.Fatalf("second packet is %T, want *SymmetricallyEncrypted", p)
		}
		rc, err := se.Decrypt(cipher, key)
		if err != nil {
			t.Fatal(err)
		}
		litPacket, err := Read(rc)
		if err != nil {
			t.Fatal(err)
		}
		lit, ok := litPacket.(*LiteralData)
		if !ok {
			t.Fatalf("decrypted packet is %T, want *LiteralData", litPacket)
		}
		body, err := io.ReadAll(lit.Body)
		if err != nil {
			t.Fatal(err)
		}
		if len(body) != 0 {
			t.Fatalf("literal body = %x, want empty", body)
		}
		if err := rc.Close(); err != nil {
			t.Fatalf("Close of valid message: %v", err)
		}
	})

	t.Run("aead-message", func(t *testing.T) {
		key := make([]byte, 16)
		for i := range key {
			key[i] = byte(i + 1)
		}
		config := &Config{DefaultCipher: CipherAES128, AEADConfig: &AEADConfig{DefaultMode: AEADModeOCB, ChunkSize: 64}}
		w := new(bytes.Buffer)
		wc, err := SerializeAEADEncrypted(w, key, config)
		if err != nil {
			t.Fatal(err)
		}
		payload := []byte{0xcb, 0x02, 'b', 0x00}
		if _, err := wc.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err := wc.Close(); err != nil {
			t.Fatal(err)
		}
		p, err := Read(bytes.NewReader(w.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		rc, err := p.(*AEADEncrypted).Decrypt(CipherAES128, key)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("reading AEAD stream: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("decrypted = %x, want %x", got, payload)
		}
		if err := rc.Close(); err != nil {
			t.Fatalf("Close of valid AEAD stream: %v", err)
		}
	})

	t.Run("user-id-and-attribute", func(t *testing.T) {
		uidRaw := []byte{0xcd, 0x0a, 'A', ' ', '(', 'c', ')', ' ', '<', 'e', '>', 'x'}
		p, err := Read(bytes.NewReader(uidRaw))
		if err != nil {
			t.Fatal(err)
		}
		uid := p.(*UserId)
		if uid.Name != "A" || uid.Comment != "c" || uid.Email != "e" {
			t.Fatalf("parsed user id = %q/%q/%q", uid.Name, uid.Comment, uid.Email)
		}
		out := new(bytes.Buffer)
		if err := uid.Serialize(out); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out.Bytes(), uidRaw) {
			t.Fatalf("re-serialized user id = %x, want %x", out.Bytes(), uidRaw)
		}

		// A five-byte length prefix in a user attribute subpacket must be
		// preserved byte for byte when re-serialized.
		uatBody := mustDecodeHex(t, "ff0000000301aabb")
		uatRaw := append([]byte{0xd1, byte(len(uatBody))}, uatBody...)
		p, err = Read(bytes.NewReader(uatRaw))
		if err != nil {
			t.Fatal(err)
		}
		uat := p.(*UserAttribute)
		if len(uat.Contents) != 1 {
			t.Fatalf("parsed %d user attribute subpackets, want 1", len(uat.Contents))
		}
		sp := uat.Contents[0]
		if sp.SubType != 1 || !bytes.Equal(sp.Contents, []byte{0xaa, 0xbb}) {
			t.Fatalf("subpacket = type %d contents %x", sp.SubType, sp.Contents)
		}
		out.Reset()
		if err := sp.Serialize(out); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out.Bytes(), uatBody) {
			t.Fatalf("re-serialized subpacket = %x, want %x", out.Bytes(), uatBody)
		}
	})
}

// TestNestedPacketDepthBoundary pins the recursion limit: 31 nested
// compressed packets parse, the 32nd push is rejected. This is the boundary
// the parser relies on to stop quines.
func TestNestedPacketDepthBoundary(t *testing.T) {
	build := func(depth int) []byte {
		payload := []byte{0xcd, 0x01, 'a'}
		for i := 0; i < depth; i++ {
			body := append([]byte{0x00}, payload...)
			payload = append([]byte{0xc8, byte(len(body))}, body...)
		}
		return payload
	}

	for _, tc := range []struct {
		depth      int
		wantErr    bool
		wantPushes int
	}{
		{1, false, 1},
		{31, false, 31},
		{32, true, 31},
	} {
		r := NewReader(bytes.NewReader(build(tc.depth)))
		pushes := 0
		var err error
		for {
			var p Packet
			p, err = r.Next()
			if err != nil {
				break
			}
			c, ok := p.(*Compressed)
			if !ok {
				break
			}
			if pushErr := r.Push(c.Body); pushErr != nil {
				err = pushErr
				break
			}
			pushes++
		}
		if pushes != tc.wantPushes {
			t.Fatalf("depth %d: %d pushes, want %d", tc.depth, pushes, tc.wantPushes)
		}
		if tc.wantErr {
			var structural pgperrors.StructuralError
			if !errors.As(err, &structural) {
				t.Fatalf("depth %d: error = %T %v, want StructuralError", tc.depth, err, err)
			}
		} else if err != nil && err != io.EOF {
			t.Fatalf("depth %d: unexpected error %v", tc.depth, err)
		}
	}
}

// countingReader counts how many bytes have been read from the underlying
// reader.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// sequenceReader produces a deterministic, non-repeating byte stream so that
// serially encrypted test messages are reproducible.
type sequenceReader struct {
	next byte
}

func (r *sequenceReader) Read(p []byte) (int, error) {
	for i := range p {
		r.next++
		p[i] = r.next
	}
	return len(p), nil
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}
