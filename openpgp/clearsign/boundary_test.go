// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package clearsign

// Boundary tests for the Cleartext Signature Framework.
//
// The tests below pin down what DecodeWithError returns for every boundary
// the format has: unsigned data before the cleartext marker, unsigned data
// after the signature armor, one or more signature blocks, truncated armor
// tails, a tampered (unauthenticated) Hash header, and CRLF/LF input.
//
// The contract under test is:
//
//   - A valid message yields the exact signed bytes in Block.Bytes and the
//     exact cleartext in Block.Plaintext, byte for byte, independent of the
//     line ending style of the carrier.
//   - Unsigned prefix data is exposed in Block.Prefix and never leaks into
//     Bytes or Plaintext.
//   - Unsigned trailing data is returned in rest and never leaks into Bytes
//     or Plaintext.
//   - Any malformed or truncated boundary yields nil block plus an error,
//     with the unmodified input returned as rest.
//   - A Hash header altered after signing is detected by VerifySignature,
//     since the header is not covered by the signature.

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// signTestMessage clear-signs body with the test key and returns the encoded
// message together with the parsed keyring.
func signTestMessage(t *testing.T, body string) ([]byte, openpgp.EntityList) {
	t.Helper()
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(signingKey))
	if err != nil {
		t.Fatalf("failed to parse public key: %s", err)
	}
	var buf bytes.Buffer
	w, err := Encode(&buf, keyring[0].PrivateKey, allowAllAlgorithmsConfig)
	if err != nil {
		t.Fatalf("Encode: %s", err)
	}
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatalf("Write: %s", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %s", err)
	}
	return buf.Bytes(), keyring
}

// mustVerify asserts that b verifies and that the signer is reported.
func mustVerify(t *testing.T, b *Block, keyring openpgp.KeyRing) {
	t.Helper()
	if b == nil {
		t.Fatal("nil block")
	}
	signer, err := b.VerifySignature(keyring, allowAllAlgorithmsConfig)
	if err != nil {
		t.Fatalf("VerifySignature: %s", err)
	}
	if signer == nil {
		t.Fatal("VerifySignature returned no signer")
	}
}

// withPrefix puts unsigned data in front of the marker line. The data uses the
// requested line ending, including the line break that introduces the marker.
func withPrefix(prefix, message string, crlf bool) []byte {
	sep := "\n"
	if crlf {
		sep = "\r\n"
	}
	if prefix == "" {
		return []byte(prefix + message)
	}
	return []byte(prefix + sep + message)
}

// TestDecodeBoundaryValid checks that valid messages decode to exactly the
// signed bytes and that surrounding unsigned data stays outside them.
func TestDecodeBoundaryValid(t *testing.T) {
	const body = "Hello world\nline 2\n"
	signed, keyring := signTestMessage(t, body)
	bareBytes := mustSignedBytes(t, signed)

	tests := []struct {
		name       string
		input      []byte
		wantPrefix string
		wantRest   string
	}{
		{
			name:  "bare message",
			input: signed,
		},
		{
			name:       "unsigned prefix without final newline",
			input:      withPrefix("; comment\nsecond line", string(signed), false),
			wantPrefix: "; comment\nsecond line",
		},
		{
			name:       "unsigned prefix ending in CRLF",
			input:      withPrefix("mail header\r\nsecond line", string(signed), true),
			wantPrefix: "mail header\r\nsecond line",
		},
		{
			name:     "unsigned trailing data",
			input:    []byte(string(signed) + "\ntrailing\n"),
			wantRest: "trailing\n",
		},
		{
			name:       "prefix and trailing data",
			input:      withPrefix("indented header", string(signed)+"\nafter signature", false),
			wantPrefix: "indented header",
			wantRest:   "after signature",
		},
		{
			name:     "signature followed directly by data",
			input:    []byte(strings.TrimRight(string(signed), "\r\n") + "\ntail"),
			wantRest: "tail",
		},
		{
			name:     "suffix on the END marker line",
			input:    []byte(strings.Replace(string(signed), string(end), string(end)+"garbage", 1)),
			wantRest: "garbage",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, rest, err := DecodeWithError(tc.input)
			if err != nil {
				t.Fatalf("DecodeWithError: %s", err)
			}
			if got := string(b.Prefix); got != tc.wantPrefix {
				t.Errorf("Prefix = %q, want %q", got, tc.wantPrefix)
			}
			if got := string(rest); got != tc.wantRest {
				t.Errorf("rest = %q, want %q", got, tc.wantRest)
			}
			if got := string(b.Plaintext); got != body {
				t.Errorf("Plaintext = %q, want %q", got, body)
			}
			// Surrounding unsigned data must not change the signed bytes.
			if !bytes.Equal(b.Bytes, bareBytes) {
				t.Errorf("Bytes = %q, want %q (as for the bare message)", b.Bytes, bareBytes)
			}
			mustVerify(t, b, keyring)
		})
	}
}

// mustSignedBytes returns the signed representation of a valid message.
func mustSignedBytes(t *testing.T, message []byte) []byte {
	t.Helper()
	b, _, err := DecodeWithError(message)
	if err != nil {
		t.Fatalf("DecodeWithError(bare): %s", err)
	}
	return b.Bytes
}

// TestDecodeBoundaryLineEndings checks that CRLF and LF carriers yield the same
// signed bytes, and that a CRLF carrier does not leak a stray '\r' into the
// prefix.
func TestDecodeBoundaryLineEndings(t *testing.T) {
	const body = "a\nb\nc\n"
	signed, keyring := signTestMessage(t, body)

	lf := signed
	crlf := bytes.ReplaceAll(signed, []byte("\n"), []byte("\r\n"))

	var lfBytes, crlfBytes []byte
	for name, input := range map[string][]byte{"LF": lf, "CRLF": crlf} {
		b, rest, err := DecodeWithError(input)
		if err != nil {
			t.Fatalf("%s: %s", name, err)
		}
		if len(rest) != 0 {
			t.Errorf("%s: unexpected rest %q", name, rest)
		}
		mustVerify(t, b, keyring)
		if name == "LF" {
			lfBytes = b.Bytes
		} else {
			crlfBytes = b.Bytes
		}
	}
	if !bytes.Equal(lfBytes, crlfBytes) {
		t.Errorf("signed bytes differ between line endings: LF %q, CRLF %q", lfBytes, crlfBytes)
	}
	if bytes.Contains(crlfBytes, []byte("\r\r")) {
		t.Errorf("doubled CR in signed bytes: %q", crlfBytes)
	}

	// A CRLF carrier with a prefix must not leave the prefix's '\r' behind.
	input := []byte("preamble\r\n" + string(crlf))
	b, _, err := DecodeWithError(input)
	if err != nil {
		t.Fatalf("prefixed CRLF: %s", err)
	}
	if got, want := string(b.Prefix), "preamble"; got != want {
		t.Errorf("Prefix = %q, want %q", got, want)
	}
}

// TestDecodeBoundaryFailures checks that every malformed boundary yields a nil
// block, a specific error, and the unmodified input as rest.
func TestDecodeBoundaryFailures(t *testing.T) {
	signed, _ := signTestMessage(t, "signed text\n")

	// cutAfter returns the message truncated just after the first occurrence of
	// needle.
	cutAfter := func(needle string) []byte {
		i := bytes.Index(signed, []byte(needle))
		if i < 0 {
			t.Fatalf("marker %q not found", needle)
		}
		return signed[:i+len(needle)]
	}
	endLine := "-----END PGP SIGNATURE-----"
	endIdx := bytes.Index(signed, []byte(endLine))
	if endIdx < 0 {
		t.Fatal("END line not found")
	}

	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{
			name: "no marker at all",
			in:   []byte("just some text\n"),
			want: ErrNoCleartextMessage,
		},
		{
			name: "marker with trailing suffix",
			in:   []byte("-----BEGIN PGP SIGNED MESSAGE-----garbage\nHash: SHA256\n\nx\n"),
			want: ErrInvalidHeader,
		},
		{
			name: "stopped inside header section",
			in:   []byte("-----BEGIN PGP SIGNED MESSAGE-----\n"),
			want: ErrTruncatedMessage,
		},
		{
			name: "missing header separator",
			in:   []byte("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\nHello\n"),
			want: ErrInvalidHeader,
		},
		{
			name: "non-Hash header",
			in:   []byte("-----BEGIN PGP SIGNED MESSAGE-----\nComment: hi\n\nx\n"),
			want: ErrInvalidHeader,
		},
		{
			name: "Hash header with prose",
			in:   []byte("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256 wire $100k\n\nx\n"),
			want: ErrInvalidHeader,
		},
		{
			name: "Hash header with unknown algorithm",
			in:   []byte("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA999\n\nx\n"),
			want: ErrInvalidHeader,
		},
		{
			name: "Hash header with control character",
			in:   []byte("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA\x0b256\n\nx\n"),
			want: ErrInvalidHeader,
		},
		{
			name: "stopped after cleartext, before armor",
			in:   cutAfter("\n\nsigned text\n"),
			want: ErrTruncatedMessage,
		},
		{
			name: "armor body truncated",
			in:   signed[:endIdx],
			want: ErrTruncatedMessage,
		},
		{
			name: "armor tail truncated mid-line",
			in:   signed[:endIdx+len(endLine)-6],
			want: ErrTruncatedMessage,
		},
		{
			name: "checksum line truncated",
			in:   signed[:len(signed)-2],
			want: ErrTruncatedMessage,
		},
		{
			name: "different END marker",
			in:   []byte(strings.Replace(string(signed), endLine, "-----END PGP MESSAGE-----", 1)),
			want: ErrInvalidArmor,
		},
		{
			name: "garbage line inside armor body",
			in: func() []byte {
				i := bytes.Index(signed, []byte("-----BEGIN PGP SIGNATURE-----"))
				bodyStart := bytes.Index(signed[i:], []byte("\n\n"))
				if bodyStart < 0 {
					t.Fatal("armor body not found")
				}
				at := i + bodyStart + 2
				out := append([]byte{}, signed[:at]...)
				out = append(out, []byte("!!!not base64!!!\n")...)
				return append(out, signed[at:]...)
			}(),
			want: ErrInvalidArmor,
		},
		{
			name: "wrong armor block type",
			in:   []byte(strings.Replace(string(signed), "-----BEGIN PGP SIGNATURE-----", "-----BEGIN PGP MESSAGE-----", 1)),
			want: ErrTruncatedMessage,
		},
		{
			name: "empty armor body",
			in: []byte("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nx\n" +
				"-----BEGIN PGP SIGNATURE-----\n\n-----END PGP SIGNATURE-----\n"),
			want: ErrInvalidArmor,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, rest, err := DecodeWithError(tc.in)
			if b != nil {
				t.Fatal("decoded a message with a broken boundary")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if !bytes.Equal(rest, tc.in) {
				t.Errorf("rest changed: got %q", rest)
			}
			// Decode must agree with DecodeWithError.
			if b2, rest2 := Decode(tc.in); b2 != nil || !bytes.Equal(rest2, tc.in) {
				t.Errorf("Decode disagrees with DecodeWithError")
			}
		})
	}
}

// TestDecodeMultipleSignaturePackets checks that one armor block carrying
// several signature packets still decodes to a single, unambiguous body and
// verifies against a keyring that knows the signer.
func TestDecodeMultipleSignaturePackets(t *testing.T) {
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(signingKey))
	if err != nil {
		t.Fatalf("failed to parse public key: %s", err)
	}
	// Signing twice with the same key yields two signature packets in one
	// armor block without needing to generate extra keys.
	var buf bytes.Buffer
	w, err := EncodeMulti(&buf, []*packet.PrivateKey{keyring[0].PrivateKey, keyring[0].PrivateKey}, allowAllAlgorithmsConfig)
	if err != nil {
		t.Fatalf("EncodeMulti: %s", err)
	}
	const body = "multi-signature body\n"
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatalf("Write: %s", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %s", err)
	}

	input := append(append([]byte{}, buf.Bytes()...), []byte("\nunsigned tail\n")...)
	b, rest, err := DecodeWithError(input)
	if err != nil {
		t.Fatalf("DecodeWithError: %s", err)
	}
	// The body is emitted with a trailing line ending before the armor
	// marker, so Plaintext keeps the final '\n' that Write was given.
	if got := string(b.Plaintext); got != body {
		t.Errorf("Plaintext = %q, want %q", got, body)
	}
	if got := string(rest); got != "unsigned tail\n" {
		t.Errorf("rest = %q, want %q", got, "unsigned tail\n")
	}

	// VerifySignature reports the first signature's signer.
	mustVerify(t, b, keyring)

	// The armor block must contain both signature packets. The armored body is
	// a single-use stream, so decode a fresh copy to count them.
	b2, _, err := DecodeWithError(buf.Bytes())
	if err != nil {
		t.Fatalf("DecodeWithError(again): %s", err)
	}
	packetCount := 0
	for {
		p, err := packet.Read(b2.ArmoredSignature.Body)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("reading signature packet: %s", err)
		}
		if _, ok := p.(*packet.Signature); ok {
			packetCount++
		}
	}
	if packetCount < 2 {
		t.Errorf("armor block has %d signature packets, want at least 2", packetCount)
	}
}

// TestDecodeMultipleSignatureBlocks checks that a second armored signature is
// treated as unsigned trailing data rather than folded into the signed body.
func TestDecodeMultipleSignatureBlocks(t *testing.T) {
	signed, keyring := signTestMessage(t, "two signatures\n")

	begin := bytes.Index(signed, []byte("-----BEGIN PGP SIGNATURE-----"))
	if begin < 0 {
		t.Fatal("no signature block")
	}
	second := append([]byte("\n"), signed[begin:]...)
	input := append(append([]byte{}, signed...), second...)

	b, rest, err := DecodeWithError(input)
	if err != nil {
		t.Fatalf("DecodeWithError: %s", err)
	}
	// The second block is unsigned trailing data. splitArmor consumes the line
	// breaks after the END line of the first block, so rest starts directly at
	// the BEGIN line of the second block.
	if !bytes.HasPrefix(rest, []byte("-----BEGIN PGP SIGNATURE-----")) {
		t.Errorf("rest = %q, want the second armor block", rest)
	}
	if !bytes.HasSuffix(bytes.TrimRight(rest, "\r\n"), []byte("-----END PGP SIGNATURE-----")) {
		t.Errorf("rest = %q, want a complete second armor block", rest)
	}
	if bytes.Contains(b.Bytes, []byte("BEGIN PGP SIGNATURE")) {
		t.Errorf("signature armor leaked into Bytes: %q", b.Bytes)
	}
	mustVerify(t, b, keyring)
}

// TestHashHeaderTamper checks that the unauthenticated Hash header cannot be
// changed without the mismatch being reported, while the signed bytes stay
// untouched and valid.
func TestHashHeaderTamper(t *testing.T) {
	signed, keyring := signTestMessage(t, "important text\n")
	if !bytes.Contains(signed, []byte("Hash: SHA256")) {
		t.Fatalf("test message does not contain the expected header: %q", signed)
	}

	// The pristine message verifies and reports no mismatch.
	b, _, err := DecodeWithError(signed)
	if err != nil {
		t.Fatalf("DecodeWithError: %s", err)
	}
	mustVerify(t, b, keyring)
	pristineBytes := append([]byte{}, b.Bytes...)

	// A tampered but syntactically valid header decodes (the header is not
	// signed) but must be rejected by VerifySignature.
	tampered := bytes.Replace(signed, []byte("Hash: SHA256"), []byte("Hash: SHA512"), 1)
	b, _, err = DecodeWithError(tampered)
	if err != nil {
		t.Fatalf("DecodeWithError(tampered): %s", err)
	}
	if !bytes.Equal(b.Bytes, pristineBytes) {
		t.Fatalf("header change altered the signed bytes")
	}
	if _, err := b.VerifySignature(keyring, allowAllAlgorithmsConfig); !errors.Is(err, ErrHashHeaderMismatch) {
		t.Fatalf("VerifySignature = %v, want ErrHashHeaderMismatch", err)
	}

	// A tampered header naming an algorithm that is not allowed at all must
	// fail to decode.
	for _, bad := range []string{"Hash: SHA999", "Hash: SHA256 with a note", "Comment: hello"} {
		in := bytes.Replace(signed, []byte("Hash: SHA256"), []byte(bad), 1)
		if b, rest, err := DecodeWithError(in); b != nil || !errors.Is(err, ErrInvalidHeader) || !bytes.Equal(rest, in) {
			t.Errorf("%q: b=%v err=%v", bad, b, err)
		}
	}

	// A multi-value header that includes the signature's algorithm is
	// conformant and verifies.
	multi := bytes.Replace(signed, []byte("Hash: SHA256"), []byte("Hash: SHA512,SHA256"), 1)
	b, _, err = DecodeWithError(multi)
	if err != nil {
		t.Fatalf("DecodeWithError(multi): %s", err)
	}
	mustVerify(t, b, keyring)

	// A multi-value header that omits the signature's algorithm is rejected.
	multi = bytes.Replace(signed, []byte("Hash: SHA256"), []byte("Hash: SHA512,SHA384"), 1)
	b, _, err = DecodeWithError(multi)
	if err != nil {
		t.Fatalf("DecodeWithError(multi2): %s", err)
	}
	if _, err := b.VerifySignature(keyring, allowAllAlgorithmsConfig); !errors.Is(err, ErrHashHeaderMismatch) {
		t.Fatalf("VerifySignature = %v, want ErrHashHeaderMismatch", err)
	}
}

// TestHashHeaderMultiSignature verifies that a message carrying several
// signature packets is rejected when the header names none of their
// algorithms, and accepted when it names one.
func TestHashHeaderMultiSignature(t *testing.T) {
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(signingKey))
	if err != nil {
		t.Fatalf("failed to parse public key: %s", err)
	}
	var buf bytes.Buffer
	w, err := EncodeMulti(&buf, []*packet.PrivateKey{keyring[0].PrivateKey, keyring[0].PrivateKey}, allowAllAlgorithmsConfig)
	if err != nil {
		t.Fatalf("EncodeMulti: %s", err)
	}
	if _, err := w.Write([]byte("body\n")); err != nil {
		t.Fatalf("Write: %s", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %s", err)
	}

	good := buf.Bytes()
	b, _, err := DecodeWithError(good)
	if err != nil {
		t.Fatalf("DecodeWithError: %s", err)
	}
	if _, err := b.VerifySignature(keyring, allowAllAlgorithmsConfig); err != nil {
		t.Fatalf("VerifySignature(genuine header): %s", err)
	}

	bad := bytes.Replace(good, []byte("Hash: SHA256"), []byte("Hash: SHA512"), 1)
	if bytes.Equal(bad, good) {
		t.Fatal("header replacement had no effect")
	}
	b, _, err = DecodeWithError(bad)
	if err != nil {
		t.Fatalf("DecodeWithError(tampered): %s", err)
	}
	if _, err := b.VerifySignature(keyring, allowAllAlgorithmsConfig); !errors.Is(err, ErrHashHeaderMismatch) {
		t.Fatalf("VerifySignature(tampered header) = %v, want ErrHashHeaderMismatch", err)
	}
}

// TestTamperedBodyNotSigned checks that changing the cleartext itself makes
// verification fail, so unauthenticated edits can never pass as signed text.
func TestTamperedBodyNotSigned(t *testing.T) {
	signed, keyring := signTestMessage(t, "pay 10 EUR\n")
	tampered := bytes.Replace(signed, []byte("pay 10 EUR"), []byte("pay 10000 EUR"), 1)
	if bytes.Equal(tampered, signed) {
		t.Fatal("failed to tamper with the body")
	}
	b, _, err := DecodeWithError(tampered)
	if err != nil {
		t.Fatalf("DecodeWithError: %s", err)
	}
	if !bytes.Contains(b.Plaintext, []byte("10000")) {
		t.Fatalf("expected tampered plaintext, got %q", b.Plaintext)
	}
	if _, err := b.VerifySignature(keyring, allowAllAlgorithmsConfig); err == nil {
		t.Fatal("a tampered cleartext verified successfully")
	}
}

// TestDecodeAcceptsCommonArmorVariants checks that valid armor variations that
// other implementations emit are still accepted and keep verifying, so the
// stricter boundary checks do not reject interoperable messages.
func TestDecodeAcceptsCommonArmorVariants(t *testing.T) {
	const body = "variant\n"
	signed, keyring := signTestMessage(t, body)

	begin := bytes.Index(signed, []byte("-----BEGIN PGP SIGNATURE-----"))
	if begin < 0 {
		t.Fatal("no signature block")
	}
	beginLineEnd := begin + bytes.IndexByte(signed[begin:], '\n')
	if beginLineEnd < begin {
		t.Fatal("no line break after BEGIN line")
	}

	insertAfterLine := func(at int, line string) []byte {
		out := append([]byte{}, signed[:at+1]...)
		out = append(out, []byte(line+"\n")...)
		return append(out, signed[at+1:]...)
	}
	insertAfterBodyLine := func() []byte {
		bodyStart := begin + bytes.Index(signed[begin:], []byte("\n\n")) + 2
		j := bytes.IndexByte(signed[bodyStart:], '\n')
		if j < 0 {
			t.Fatal("no body line")
		}
		return insertAfterLine(bodyStart+j, "")
	}

	tests := []struct {
		name string
		in   []byte
	}{
		{
			name: "armor header line",
			in:   insertAfterLine(beginLineEnd, "Version: Test 1.0"),
		},
		{
			name: "different armor header name",
			in:   insertAfterLine(beginLineEnd, "Comment: hello"),
		},
		{
			name: "blank line inside base64 body",
			in:   insertAfterBodyLine(),
		},
		{
			name: "END line with trailing spaces",
			in:   bytes.Replace(signed, end, append(append([]byte{}, end...), ' ', ' ', ' '), 1),
		},
		{
			name: "BEGIN marker with trailing spaces",
			in:   []byte(strings.Replace(string(signed), "-----BEGIN PGP SIGNED MESSAGE-----", "-----BEGIN PGP SIGNED MESSAGE-----   ", 1)),
		},
		{
			name: "armor BEGIN line with trailing spaces",
			in:   []byte(strings.Replace(string(signed), "-----BEGIN PGP SIGNATURE-----", "-----BEGIN PGP SIGNATURE-----   ", 1)),
		},
		{
			name: "CRLF line endings",
			in:   bytes.ReplaceAll(signed, []byte("\n"), []byte("\r\n")),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, rest, err := DecodeWithError(tc.in)
			if err != nil {
				t.Fatalf("DecodeWithError: %s", err)
			}
			if len(rest) != 0 {
				t.Errorf("unexpected rest %q", rest)
			}
			if got := string(b.Plaintext); got != body {
				t.Errorf("Plaintext = %q, want %q", got, body)
			}
			mustVerify(t, b, keyring)
		})
	}
}

// TestDecodeEmptyMessage ensures that an empty signed message is not reported
// through a panic or a bogus boundary.
func TestDecodeEmptyMessage(t *testing.T) {
	signed, keyring := signTestMessage(t, "")
	b, rest, err := DecodeWithError(signed)
	if err != nil {
		t.Fatalf("DecodeWithError: %s", err)
	}
	if len(rest) != 0 {
		t.Errorf("unexpected rest %q", rest)
	}
	if len(b.Bytes) != 0 || len(b.Plaintext) != 0 {
		t.Errorf("expected empty body, got Bytes=%q Plaintext=%q", b.Bytes, b.Plaintext)
	}
	mustVerify(t, b, keyring)
}

// TestDecodeNoHashHeaderV6 verifies that a version 6 message without a Hash
// header is accepted (there is nothing to cross-check) while its signature is
// still verified.
func TestDecodeNoHashHeaderV6(t *testing.T) {
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(clearSignV6PublicKey))
	if err != nil {
		t.Fatalf("failed to parse public key: %s", err)
	}
	b, rest, err := DecodeWithError([]byte(clearSignV6))
	if err != nil {
		t.Fatalf("DecodeWithError: %s", err)
	}
	if len(rest) != 0 {
		t.Errorf("unexpected rest %q", rest)
	}
	if len(b.Headers) != 0 {
		t.Errorf("expected no headers, got %v", b.Headers)
	}
	if _, err := b.VerifySignature(keyring, nil); err != nil {
		t.Errorf("VerifySignature: %s", err)
	}
}

// TestDecodeDropsTrailingWhitespaceOnlyAtEndOfLine verifies the exact signed
// representation: trailing spaces and tabs are removed, but leading whitespace
// and interior whitespace survive.
func TestDecodeDropsTrailingWhitespaceOnlyAtEndOfLine(t *testing.T) {
	const body = "  leading and trailing  \n\tindented\t\nplain\n"
	signed, _ := signTestMessage(t, body)
	b, _, err := DecodeWithError(signed)
	if err != nil {
		t.Fatalf("DecodeWithError: %s", err)
	}
	want := "  leading and trailing\r\n\tindented\r\nplain\r\n"
	if got := string(b.Bytes); got != want {
		t.Errorf("Bytes = %q, want %q", got, want)
	}
	if got, want := string(b.Plaintext), strings.ReplaceAll(want, "\r\n", "\n"); got != want {
		t.Errorf("Plaintext = %q, want %q", got, want)
	}
}
