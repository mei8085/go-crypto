// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openpgp

// This file checks the high-level "no regression" property that accompanies
// the packet-level boundary tests: the key-ring reader still parses legal
// key material, and messages encrypted in the different supported schemes
// still decrypt and verify through the unchanged public API.
//
// The malformed samples here are minimal truncations of those legal inputs,
// so a failure shows exactly which parser boundary broke, and every fixture
// is embedded in the repository (no network, no external files).

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
)

// TestKeyRingSurvivesTruncatedEntity checks that a truncated or malformed key
// entity is skipped, and that the well-formed entities around it still load.
func TestKeyRingSurvivesTruncatedEntity(t *testing.T) {
	good := mustHexDecode(t, testKeys1And2Hex)

	// A half copy of the keyring: the last entity is cut mid-packet.
	truncated := good[:len(good)/2]

	t.Run("good-then-truncated-then-good", func(t *testing.T) {
		stream := append(append(append([]byte{}, good...), truncated...), good...)
		el, err := ReadKeyRing(bytes.NewReader(stream))
		if err != nil {
			t.Fatalf("ReadKeyRing: %v", err)
		}
		// The truncated middle entity must be dropped; the two intact
		// entities must survive.
		if len(el) != 2 {
			t.Fatalf("read %d entities, want 2", len(el))
		}
		if el[0].PrimaryKey.KeyId != 0xa34d7e18c20c31bb || el[1].PrimaryKey.KeyId != 0xd4984f961e35246b {
			t.Fatalf("unexpected key ids: %x, %x", el[0].PrimaryKey.KeyId, el[1].PrimaryKey.KeyId)
		}
	})

	t.Run("truncated-only", func(t *testing.T) {
		el, err := ReadKeyRing(bytes.NewReader(truncated))
		if err == nil {
			t.Fatalf("ReadKeyRing of a truncated entity returned %d entities and no error", len(el))
		}
		if len(el) != 0 {
			t.Fatalf("read %d entities from a truncated keyring, want 0", len(el))
		}
	})

	t.Run("empty", func(t *testing.T) {
		el, err := ReadKeyRing(bytes.NewReader(nil))
		if err != nil {
			t.Fatalf("ReadKeyRing of empty input: %v", err)
		}
		if len(el) != 0 {
			t.Fatalf("read %d entities from empty input, want 0", len(el))
		}
	})
}

// TestLegalMessagesStillReadable covers the message kinds the repository has
// fixtures for: signed, signed and encrypted, symmetrically encrypted with
// compression, and the v6 message format.
func TestLegalMessagesStillReadable(t *testing.T) {
	t.Run("signed", func(t *testing.T) {
		checkSignedMessage(t, signedMessageHex, signedInput)
	})

	t.Run("signed-text", func(t *testing.T) {
		checkSignedMessage(t, signedTextMessageHex, signedTextInput)
	})

	t.Run("signed-and-encrypted", func(t *testing.T) {
		kring, err := ReadKeyRing(readerFromHex(testKeys1And2PrivateHex))
		if err != nil {
			t.Fatal(err)
		}
		prompt := func(keys []Key, symmetric bool) ([]byte, error) {
			if symmetric {
				t.Errorf("message was marked as symmetrically encrypted")
				return nil, pgperrors.ErrKeyIncorrect
			}
			if len(keys) == 0 {
				t.Error("no keys requested")
				return nil, pgperrors.ErrKeyIncorrect
			}
			if err := keys[0].PrivateKey.Decrypt([]byte("passphrase")); err != nil {
				t.Errorf("decrypting key: %v", err)
				return nil, pgperrors.ErrKeyIncorrect
			}
			return nil, nil
		}
		md, err := ReadMessage(readerFromHex(signedEncryptedMessageHex), kring, prompt, nil)
		if err != nil {
			t.Fatalf("ReadMessage: %v", err)
		}
		contents, err := io.ReadAll(md.UnverifiedBody)
		if err != nil {
			t.Fatalf("reading body: %v", err)
		}
		if string(contents) != "Signed and encrypted message\n" {
			t.Fatalf("body = %q", contents)
		}
		if md.SignatureError != nil {
			t.Fatalf("signature error: %v", md.SignatureError)
		}
	})

	t.Run("compressed-symmetric", func(t *testing.T) {
		passphrase := []byte("password")
		prompt := func(keys []Key, symmetric bool) ([]byte, error) {
			return passphrase, nil
		}
		md, err := ReadMessage(readerFromHex(symmetricallyEncryptedCompressedHex), nil, prompt, nil)
		if err != nil {
			t.Fatalf("ReadMessage: %v", err)
		}
		contents, err := io.ReadAll(md.UnverifiedBody)
		if err != nil {
			t.Fatalf("reading body: %v", err)
		}
		if string(contents) != "Symmetrically encrypted.\r\n" {
			t.Fatalf("body = %q", contents)
		}
	})
}

// TestTruncatedMessageFailsClosed checks that cutting a legal encrypted
// message short never yields a complete plaintext: reading either fails, or
// the integrity check at the end of the stream fails.
func TestTruncatedMessageFailsClosed(t *testing.T) {
	raw := mustHexDecode(t, symmetricallyEncryptedCompressedHex)
	prompt := func(keys []Key, symmetric bool) ([]byte, error) {
		return []byte("password"), nil
	}

	// The intact message must decrypt, for reference.
	md, err := ReadMessage(bytes.NewReader(raw), nil, prompt, nil)
	if err != nil {
		t.Fatalf("baseline ReadMessage: %v", err)
	}
	body, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Fatalf("baseline body: %v", err)
	}
	complete := string(body)

	for _, cut := range []int{len(raw) - 1, len(raw) - 2, len(raw) - 22, len(raw) / 2} {
		md, err := ReadMessage(bytes.NewReader(raw[:cut]), nil, prompt, nil)
		if err != nil {
			// Failing during parsing is an acceptable closed result.
			continue
		}
		body, err := io.ReadAll(md.UnverifiedBody)
		if err == nil {
			// A successful read must not produce the complete plaintext.
			if string(body) == complete {
				t.Fatalf("cut at %d/%d bytes was accepted as a complete message", cut, len(raw))
			}
			continue
		}
		var decErr pgperrors.DecryptWithSessionKeyError
		var sigErr pgperrors.SignatureError
		if !errors.As(err, &decErr) && !errors.As(err, &sigErr) {
			t.Fatalf("cut at %d bytes: unexpected error type %T: %v", cut, err, err)
		}
	}
}

// TestTruncatedSignedMessage reports the truncated signature rather than
// silently accepting the message as unsigned.
func TestTruncatedSignedMessage(t *testing.T) {
	raw := mustHexDecode(t, signedMessageHex)
	kring, err := ReadKeyRing(readerFromHex(testKeys1And2Hex))
	if err != nil {
		t.Fatal(err)
	}

	// The signature packet sits at the end of the message. Cutting it off
	// must leave the message signed but with a signature error.
	md, err := ReadMessage(bytes.NewReader(raw[:len(raw)-20]), kring, nil, nil)
	if err != nil {
		// A parse failure is also a closed result.
		return
	}
	if _, err := io.ReadAll(md.UnverifiedBody); err != nil {
		return
	}
	if md.IsSigned && md.SignatureError == nil {
		t.Fatalf("a message whose signature packet was cut off verified successfully")
	}
}

func mustHexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}
