// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package clearsign generates and processes OpenPGP, clear-signed data. See
// RFC 4880, section 7.
//
// Clearsigned messages are cryptographically signed, but the contents of the
// message are kept in plaintext so that it can be read without special tools.
//
// A cleartext signed message has several boundaries that are not covered by
// the signature: the text before the "-----BEGIN PGP SIGNED MESSAGE-----"
// marker, the header section between the marker and the first empty line, and
// the text after the "-----END PGP SIGNATURE-----" line. Decode reports the
// first as Block.Prefix and the last through its rest return value, and
// DecodeWithError additionally rejects inputs whose boundaries are ambiguous
// (truncated armor, non-Hash headers, a signature marker that does not delimit
// an armor block). The signed representation itself is always available in
// Block.Bytes and is what VerifySignature checks; the Hash header is not
// signed, so VerifySignature rejects a header that names a different hash
// algorithm than the signature uses.
package clearsign // import "github.com/ProtonMail/go-crypto/openpgp/clearsign"

import (
	"bufio"
	"bytes"
	"crypto"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"net/textproto"
	"slices"
	"strconv"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// A Block represents a clearsigned message. A signature on a Block can
// be checked by calling Block.VerifySignature.
type Block struct {
	Headers          textproto.MIMEHeader // Optional unverified Hash headers
	Plaintext        []byte               // The original message text
	Bytes            []byte               // The signed message
	ArmoredSignature *armor.Block         // The signature block
	// Prefix holds the unsigned data that preceded the
	// "-----BEGIN PGP SIGNED MESSAGE-----" line. It is never part of Bytes
	// and can therefore never be mistaken for signed text. The line break
	// that introduces the marker line is not included.
	Prefix []byte
}

// The errors returned by DecodeWithError. They distinguish the different
// ways in which a cleartext signed message can fail to have unambiguous
// boundaries, so that callers can tell a missing message, a truncated one,
// a malformed header section, a malformed signature armor block, and a
// tampered Hash header apart.
var (
	// ErrNoCleartextMessage is returned when no cleartext signed message is
	// present in the input.
	ErrNoCleartextMessage = errors.StructuralError("clearsign: no cleartext signed message found")
	// ErrTruncatedMessage is returned when a cleartext signed message is
	// cut off before its signature armor is complete.
	ErrTruncatedMessage = errors.StructuralError("clearsign: truncated cleartext signed message")
	// ErrInvalidHeader is returned when the header section between the
	// cleartext marker and the first empty line is malformed, contains a
	// header other than Hash, or has an illegal Hash value.
	ErrInvalidHeader = errors.StructuralError("clearsign: invalid cleartext header")
	// ErrInvalidArmor is returned when the signature armor block has
	// ambiguous or malformed boundaries: garbage lines, a broken base64 body,
	// an empty signature body, an unexpectedly different END marker, or data
	// after the optional checksum line.
	ErrInvalidArmor = errors.StructuralError("clearsign: invalid signature armor")
	// ErrHashHeaderMismatch is returned by VerifySignature when the Hash
	// header is present but does not list the hash algorithm that the
	// signature actually uses.
	ErrHashHeaderMismatch = errors.StructuralError("clearsign: hash algorithm in cleartext header does not match signature")
)

// start is the marker which denotes the beginning of a clearsigned message.
var start = []byte("\n-----BEGIN PGP SIGNED MESSAGE-----")

// dashEscape is prefixed to any lines that begin with a hyphen so that they
// can't be confused with endText.
var dashEscape = []byte("- ")

// endText is a marker which denotes the end of the message and the start of
// an armored signature.
var endText = []byte("-----BEGIN PGP SIGNATURE-----")

// end is the exact tail line of a PGP SIGNATURE armor block.
var end = []byte("-----END PGP SIGNATURE-----")

var allowedHashHeaderValues = []string{"MD5", "SHA1", "RIPEMD160", "SHA224", "SHA256", "SHA384", "SHA512", "SHA3-256", "SHA3-512"}

var crlf = []byte("\r\n")
var lf = byte('\n')

const hashHeader string = "Hash"

// getLine returns the first \r\n or \n delineated line from the given byte
// array. The line does not include the \r\n or \n. The remainder of the byte
// array (also not including the new line bytes) is also returned and this will
// always be smaller than the original argument.
func getLine(data []byte) (line, rest []byte) {
	i := bytes.Index(data, []byte{'\n'})
	var j int
	if i < 0 {
		i = len(data)
		j = i
	} else {
		j = i + 1
		if i > 0 && data[i-1] == '\r' {
			i--
		}
	}
	return data[0:i], data[j:]
}

// Decode finds the first clearsigned message in data and returns it, as well as
// the suffix of data which remains after the message. Any prefix data is not
// signed; it is returned in Block.Prefix and never included in Block.Bytes or
// Block.Plaintext.
//
// If no message is found, or if the message is invalid, Decode returns nil and
// the whole data slice. The only allowed header type is Hash, and Decode does
// not check it against the signature hash. Callers that need to tell the
// different failure modes apart should use DecodeWithError.
func Decode(data []byte) (b *Block, rest []byte) {
	b, rest, _ = DecodeWithError(data)
	return
}

// DecodeWithError is like Decode, but returns a descriptive error when the
// cleartext signed message has ambiguous or invalid boundaries instead of
// silently reporting that no message was found.
//
// The returned boundary is always unambiguous:
//
//   - Block.Prefix holds the unsigned data that preceded the cleartext marker,
//     without the line break that introduces the marker line.
//   - Block.Plaintext and Block.Bytes hold only the cleartext between the
//     header separator and the signature marker line.
//   - rest holds the unsigned data that followed the signature armor. The line
//     terminator of the "-----END PGP SIGNATURE-----" line and any immediately
//     following empty lines are consumed, so rest always starts at the first
//     byte of trailing data. A non-conformant suffix on the END line itself is
//     reported as trailing data rather than silently dropped.
//
// On any error the returned block is nil and rest is the whole of data, so
// unauthenticated input can never be mistaken for signed content. The error is
// one of ErrNoCleartextMessage, ErrTruncatedMessage, ErrInvalidHeader or
// ErrInvalidArmor.
func DecodeWithError(data []byte) (b *Block, rest []byte, err error) {
	// start begins with a newline. However, at the very beginning of
	// the byte array, we'll accept the start string without it.
	rest = data
	var prefix []byte
	if bytes.HasPrefix(data, start[1:]) {
		rest = rest[len(start)-1:]
	} else if i := bytes.Index(data, start); i >= 0 {
		// Everything before the marker line is unsigned. The newline that
		// introduced the marker line belongs to the preceding line, so it is
		// not part of the prefix. A CRLF line terminator leaves a trailing
		// '\r' behind, which is removed as well.
		prefix = data[:i]
		if len(prefix) > 0 && prefix[len(prefix)-1] == '\r' {
			prefix = prefix[:len(prefix)-1]
		}
		rest = rest[i+len(start):]
	} else {
		return nil, data, ErrNoCleartextMessage
	}

	// Consume the start line and check it does not have a suffix. Trailing
	// spaces and tabs are tolerated, since the marker is a delimiter rather
	// than signed content, but any other trailing character is rejected: it
	// could be used to make a human reader mistake header text for the message.
	suffix, rest := getLine(rest)
	if len(bytes.TrimRight(suffix, " \t\r")) != 0 {
		return nil, data, ErrInvalidHeader
	}

	var line []byte
	b = &Block{
		Headers: make(textproto.MIMEHeader),
		Prefix:  prefix,
	}

	// Next come a series of header lines.
	for {
		// This loop terminates because getLine's second result is
		// always smaller than its argument.
		if len(rest) == 0 {
			// The marker was found but the message stops before the header
			// separator or the signature armor.
			return nil, data, ErrTruncatedMessage
		}
		// An empty (or whitespace-only) line marks the end of the headers.
		if line, rest = getLine(rest); len(strings.TrimSpace(string(line))) == 0 {
			break
		}

		// Reject headers with control or Unicode characters.
		if i := bytes.IndexFunc(line, func(r rune) bool {
			return r < 0x20 || r > 0x7e
		}); i != -1 {
			return nil, data, ErrInvalidHeader
		}

		i := bytes.Index(line, []byte{':'})
		if i == -1 {
			return nil, data, ErrInvalidHeader
		}

		key, val := string(line[0:i]), string(line[i+1:])
		key = strings.TrimSpace(key)
		if key == hashHeader {
			for _, val := range strings.Split(val, ",") {
				val = strings.ToUpper(strings.TrimSpace(val))
				if !slices.Contains(allowedHashHeaderValues, val) {
					return nil, data, ErrInvalidHeader
				}
				b.Headers.Add(key, val)
			}
		} else {
			// Only "Hash" headers are allowed.
			return nil, data, ErrInvalidHeader
		}
	}

	firstLine := true
	for {
		start := rest

		line, rest = getLine(rest)
		if len(line) == 0 && len(rest) == 0 {
			// No armored data was found, so this isn't a complete message.
			return nil, data, ErrTruncatedMessage
		}
		if bytes.Equal(bytes.TrimRight(line, " \t"), endText) {
			// Back up to the start of the line because armor expects to see the
			// header line.
			rest = start
			break
		}

		// The final CRLF isn't included in the hash so we don't write it until
		// we've seen the next line.
		if firstLine {
			firstLine = false
		} else {
			b.Bytes = append(b.Bytes, crlf...)
		}

		if bytes.HasPrefix(line, dashEscape) {
			line = line[2:]
		}
		line = bytes.TrimRight(line, " \t")
		b.Bytes = append(b.Bytes, line...)

		b.Plaintext = append(b.Plaintext, line...)
		b.Plaintext = append(b.Plaintext, lf)
	}
	if len(b.Plaintext) > 0 {
		b.Plaintext = b.Plaintext[:len(b.Plaintext)-1]
	}

	// Find the extent of the armored data (including any newlines at the end)
	// and validate its internal structure before handing it to armor.Decode.
	armored, rest, err := splitArmor(rest)
	if err != nil {
		return nil, data, err
	}

	b.ArmoredSignature, err = armor.Decode(bytes.NewBuffer(armored))
	if err != nil || b.ArmoredSignature == nil {
		return nil, data, ErrInvalidArmor
	}
	if b.ArmoredSignature.Type != "PGP SIGNATURE" {
		return nil, data, ErrInvalidArmor
	}

	return b, rest, nil
}

// splitArmor validates the structure of the armored signature block that
// starts at the "-----BEGIN PGP SIGNATURE-----" line in data and returns its
// extent (including trailing line breaks) together with the data after it.
//
// The armor block must be self-delimiting: the END line must match the marker
// exactly (apart from surrounding whitespace), the body must contain only
// base64 lines and an optional checksum, and the block must not be truncated.
// This makes the boundary between signed text and unsigned trailing data
// unambiguous.
func splitArmor(data []byte) (armored, rest []byte, err error) {
	off := 0
	line, next, _, ok := nextLine(data, off)
	if !ok || !bytes.Equal(bytes.TrimRight(line, " \t"), endText) {
		return nil, nil, ErrInvalidArmor
	}
	off = next

	inBody := false
	var body []byte
	sawBody := false
	sawChecksum := false
	// suffixAt is set when the END marker is followed by extra content on the
	// same line; the armor extent then ends at the marker itself and the rest
	// is unsigned trailing data.
	suffixAt := -1
	for {
		lineStart := off
		line, next, terminated, ok := nextLine(data, off)
		if !ok {
			// The armor started but its END line is missing.
			return nil, nil, ErrTruncatedMessage
		}
		trimmed := bytes.TrimSpace(line)

		if len(trimmed) == 0 {
			// The first blank line separates the armor headers from the base64
			// body. Blank lines inside the body are ignored by armor.Decode, so
			// they are harmless here as well.
			inBody = true
			off = next
			continue
		}

		if bytes.HasPrefix(trimmed, end) {
			if !inBody || !sawBody {
				return nil, nil, ErrInvalidArmor
			}
			if len(bytes.TrimSpace(trimmed[len(end):])) != 0 {
				// Content after the END marker on the same line is not part of
				// the armor. Keep it as unsigned trailing data instead of
				// dropping or signing it.
				suffixAt = lineStart + bytes.Index(line, end) + len(end)
			} else {
				off = next
			}
			break
		}

		if bytes.HasPrefix(trimmed, armorEnd) {
			if bytes.HasPrefix(end, trimmed) {
				// The tail line is a truncated form of the expected marker.
				return nil, nil, ErrTruncatedMessage
			}
			// A different END line leaves the armor extent ambiguous.
			return nil, nil, ErrInvalidArmor
		}

		if !terminated {
			// An unterminated line that is not the END marker means the message
			// was cut off, whatever the line happens to contain.
			return nil, nil, ErrTruncatedMessage
		}

		if sawChecksum {
			// The checksum line is the last line armor.Decode reads; anything
			// after it would not be part of the signature, so it must not be
			// folded into the armor extent.
			return nil, nil, ErrInvalidArmor
		}

		if !inBody {
			// Armor header line or a continuation of the previous header.
			if !isArmorHeaderLine(line, trimmed) {
				return nil, nil, ErrInvalidArmor
			}
			off = next
			continue
		}

		bodyLine, isChecksum, ok := parseArmorBodyLine(trimmed)
		if !ok {
			return nil, nil, ErrInvalidArmor
		}
		if isChecksum {
			sawChecksum = true
		} else {
			body = append(body, bodyLine...)
		}
		sawBody = true
		off = next
	}

	// The base64 body must decode cleanly; otherwise the extent of the signed
	// content would be known but the signature itself unreadable.
	if decoded, err := base64.StdEncoding.DecodeString(string(body)); err != nil || len(decoded) == 0 {
		return nil, nil, ErrInvalidArmor
	}

	if suffixAt >= 0 {
		// The END line carried extra bytes; they start immediately after the
		// marker and are unsigned trailing data.
		return data[:suffixAt], data[suffixAt:], nil
	}

	// The newlines after the END line are not part of the message that
	// follows; consume them so that rest starts at the first byte of trailing
	// data.
	tailEnd := off
	for tailEnd < len(data) && (data[tailEnd] == '\r' || data[tailEnd] == '\n') {
		tailEnd++
	}
	return data[:tailEnd], data[tailEnd:], nil
}

// armorEnd is the prefix that introduces an ASCII armor tail line.
var armorEnd = []byte("-----END ")

// nextLine returns the line starting at off without its line terminator, the
// offset just past the terminator, whether the line was terminated by '\n', and
// whether a line was available. A trailing bare '\r' is removed so that CRLF
// and LF input are treated alike.
func nextLine(data []byte, off int) (line []byte, next int, terminated, ok bool) {
	if off >= len(data) {
		return nil, off, false, false
	}
	i := bytes.IndexByte(data[off:], '\n')
	if i < 0 {
		line = data[off:]
		next = len(data)
	} else {
		line = data[off : off+i]
		next = off + i + 1
		terminated = true
	}
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}
	return line, next, terminated, true
}

// isArmorHeaderLine reports whether line is a valid ASCII armor header line or
// a continuation of one. Armor header values may be UTF-8, so only the shape
// of the line is checked here.
func isArmorHeaderLine(line, trimmed []byte) bool {
	if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
		// Continuation of the previous header.
		return len(trimmed) > 0
	}
	i := bytes.IndexByte(trimmed, ':')
	return i > 0
}

// parseArmorBodyLine validates a single line of the armored signature body and
// returns the base64 characters it contributes. It reports whether the line was
// the optional "=" checksum line.
func parseArmorBodyLine(line []byte) (body []byte, isChecksum bool, ok bool) {
	if len(line) == 0 || len(line) > 96 {
		return nil, false, false
	}
	if line[0] == '=' {
		if len(line) != 5 {
			return nil, false, false
		}
		for _, c := range line[1:] {
			if !isBase64Char(c) {
				return nil, false, false
			}
		}
		return nil, true, true
	}
	for i, c := range line {
		if isBase64Char(c) {
			continue
		}
		// Padding may only appear as the last one or two characters.
		if c == '=' && i >= len(line)-2 {
			continue
		}
		return nil, false, false
	}
	return line, false, true
}

func isBase64Char(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z':
		return true
	case c >= 'a' && c <= 'z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '+' || c == '/':
		return true
	}
	return false
}

// A dashEscaper is an io.WriteCloser which processes the body of a clear-signed
// message. The clear-signed message is written to buffered and a hash, suitable
// for signing, is maintained in h.
//
// When closed, an armored signature is created and written to complete the
// message.
type dashEscaper struct {
	buffered    *bufio.Writer
	hashers     []hash.Hash // one per key in privateKeys
	hashTypes   []crypto.Hash
	toHash      io.Writer         // writes to all the hashes in hashers
	salts       [][]byte          // salts for the signatures if v6
	armorHeader map[string]string // Armor headers

	atBeginningOfLine bool
	isFirstLine       bool

	whitespace []byte
	byteBuf    []byte // a one byte buffer to save allocations

	privateKeys []*packet.PrivateKey
	config      *packet.Config
}

func (d *dashEscaper) Write(data []byte) (n int, err error) {
	for _, b := range data {
		d.byteBuf[0] = b

		if d.atBeginningOfLine {
			// The final CRLF isn't included in the hash so we have to wait
			// until this point (the start of the next line) before writing it.
			if !d.isFirstLine {
				if _, err = d.toHash.Write(crlf); err != nil {
					return
				}
			}
			d.isFirstLine = false
		}

		// Any whitespace at the end of the line has to be removed so we
		// buffer it until we find out whether there's more on this line.
		if b == ' ' || b == '\t' || b == '\r' {
			d.whitespace = append(d.whitespace, b)
			d.atBeginningOfLine = false
			continue
		}

		if d.atBeginningOfLine {
			// At the beginning of a line, hyphens have to be escaped.
			if b == '-' {
				// The signature isn't calculated over the dash-escaped text so
				// the escape is only written to buffered.
				if _, err = d.buffered.Write(dashEscape); err != nil {
					return
				}
				if _, err = d.toHash.Write(d.byteBuf); err != nil {
					return
				}
				d.atBeginningOfLine = false
			} else if b == '\n' {
				// Nothing to do because we delay writing CRLF to the hash.
			} else {
				if _, err = d.toHash.Write(d.byteBuf); err != nil {
					return
				}
				d.atBeginningOfLine = false
			}
			if err = d.buffered.WriteByte(b); err != nil {
				return
			}
		} else {
			if b == '\n' {
				// We got a raw \n. Drop any trailing whitespace and write a
				// CRLF.
				d.whitespace = d.whitespace[:0]
				// We delay writing CRLF to the hash until the start of the
				// next line.
				if err = d.buffered.WriteByte(b); err != nil {
					return
				}
				d.atBeginningOfLine = true
			} else {
				// Any buffered whitespace wasn't at the end of the line so
				// we need to write it out.
				if len(d.whitespace) > 0 {
					if _, err = d.toHash.Write(d.whitespace); err != nil {
						return
					}
					if _, err = d.buffered.Write(d.whitespace); err != nil {
						return
					}
					d.whitespace = d.whitespace[:0]
				}
				if _, err = d.toHash.Write(d.byteBuf); err != nil {
					return
				}
				if err = d.buffered.WriteByte(b); err != nil {
					return
				}
			}
		}
	}

	n = len(data)
	return
}

func (d *dashEscaper) Close() (err error) {
	if d.atBeginningOfLine {
		if !d.isFirstLine {
			if _, err := d.toHash.Write(crlf); err != nil {
				return err
			}
		}
	}
	if err = d.buffered.WriteByte(lf); err != nil {
		return
	}

	out, err := armor.EncodeWithChecksumOption(d.buffered, "PGP SIGNATURE", d.armorHeader, false)
	if err != nil {
		return
	}

	t := d.config.Now()
	indexSalt := 0
	for i, k := range d.privateKeys {
		sig := new(packet.Signature)
		sig.Version = k.Version
		sig.SigType = packet.SigTypeText
		sig.PubKeyAlgo = k.PubKeyAlgo
		sig.Hash = d.hashTypes[i]
		sig.CreationTime = t
		sig.IssuerKeyId = &k.KeyId
		sig.IssuerKeyVersion = uint8(k.Version)
		sig.IssuerFingerprint = k.Fingerprint
		sig.Notations = d.config.Notations()
		sigLifetimeSecs := d.config.SigLifetime()
		sig.SigLifetimeSecs = &sigLifetimeSecs
		if k.Version == 6 {
			if err = sig.SetSalt(d.salts[indexSalt]); err != nil {
				return
			}
			indexSalt++
		}
		if err = sig.Sign(d.hashers[i], k, d.config); err != nil {
			return
		}
		if err = sig.Serialize(out); err != nil {
			return
		}
	}

	if err = out.Close(); err != nil {
		return
	}
	if err = d.buffered.Flush(); err != nil {
		return
	}
	return
}

// Encode returns a WriteCloser which will clear-sign a message with privateKey
// and write it to w. If config is nil, sensible defaults are used.
func Encode(w io.Writer, privateKey *packet.PrivateKey, config *packet.Config) (plaintext io.WriteCloser, err error) {
	return EncodeMulti(w, []*packet.PrivateKey{privateKey}, config)
}

// EncodeWithHeader returns a WriteCloser which will clear-sign a message with privateKey
// and write it to w. If config is nil, sensible defaults are used.
// Additionally provides a headers argument for custom headers.
func EncodeWithHeader(w io.Writer, privateKey *packet.PrivateKey, config *packet.Config, headers map[string]string) (plaintext io.WriteCloser, err error) {
	return EncodeMultiWithHeader(w, []*packet.PrivateKey{privateKey}, config, headers)
}

// EncodeMulti returns a WriteCloser which will clear-sign a message with all the
// private keys indicated and write it to w. If config is nil, sensible defaults
// are used.
func EncodeMulti(w io.Writer, privateKeys []*packet.PrivateKey, config *packet.Config) (plaintext io.WriteCloser, err error) {
	return EncodeMultiWithHeader(w, privateKeys, config, nil)
}

// EncodeMultiWithHeader returns a WriteCloser which will clear-sign a message with all the
// private keys indicated and write it to w. If config is nil, sensible defaults
// are used.
// Additionally provides a headers argument for custom headers.
func EncodeMultiWithHeader(w io.Writer, privateKeys []*packet.PrivateKey, config *packet.Config, headers map[string]string) (plaintext io.WriteCloser, err error) {
	for _, k := range privateKeys {
		if k.Encrypted {
			return nil, errors.InvalidArgumentError(fmt.Sprintf("signing key %s is encrypted", k.KeyIdString()))
		}
	}

	hashType := config.Hash()

	var hashers []hash.Hash
	var hashTypes []crypto.Hash
	var ws []io.Writer
	var salts [][]byte
	for _, sk := range privateKeys {
		acceptedHashes := acceptableHashesToWrite(&sk.PublicKey)
		// acceptedHashes contains at least one hash
		selectedHashType := acceptedHashes[0]
		for _, acceptedHash := range acceptedHashes {
			if hashType == acceptedHash {
				selectedHashType = hashType
				break
			}
		}
		h := selectedHashType.New()
		if sk.Version == 6 {
			// generate salt
			var salt []byte
			salt, err = packet.SignatureSaltForHash(selectedHashType, config.Random())
			if err != nil {
				return
			}
			if _, err = h.Write(salt); err != nil {
				return
			}
			salts = append(salts, salt)
		}
		hashers = append(hashers, h)
		hashTypes = append(hashTypes, selectedHashType)
		ws = append(ws, h)
	}
	toHash := io.MultiWriter(ws...)

	buffered := bufio.NewWriter(w)
	// start has a \n at the beginning that we don't want here.
	if _, err = buffered.Write(start[1:]); err != nil {
		return
	}
	if err = buffered.WriteByte(lf); err != nil {
		return
	}
	// write headers
	nonV6 := len(salts) < len(hashers)
	// Crypto refresh: Headers SHOULD NOT be emitted
	if nonV6 { // Emit header if non v6 signatures are present for compatibility
		if err := writeHashHeader(buffered, hashTypes); err != nil {
			return nil, err
		}
	}
	if err = buffered.WriteByte(lf); err != nil {
		return
	}

	plaintext = &dashEscaper{
		buffered:    buffered,
		hashers:     hashers,
		hashTypes:   hashTypes,
		toHash:      toHash,
		salts:       salts,
		armorHeader: headers,

		atBeginningOfLine: true,
		isFirstLine:       true,

		byteBuf: make([]byte, 1),

		privateKeys: privateKeys,
		config:      config,
	}

	return
}

// VerifySignature checks a clearsigned message signature, and checks that the
// hash algorithm in the header matches the hash algorithm in the signature.
//
// The Hash header is not covered by the signature, so a message whose header
// was changed after signing must not be reported as valid for the algorithm it
// names. If the header names a different algorithm than the signature uses,
// VerifySignature returns ErrHashHeaderMismatch. A message without a Hash
// header (as produced for version 6 signatures) is accepted, since there is
// nothing to cross-check.
func (b *Block) VerifySignature(keyring openpgp.KeyRing, config *packet.Config) (signer *openpgp.Entity, err error) {
	if b == nil || b.ArmoredSignature == nil {
		return nil, errors.StructuralError("clearsign: no signature to verify")
	}
	// The armored body is a single-use stream. Read it once so that the Hash
	// header can be cross-checked against every signature packet it contains
	// before the signature is verified.
	body, err := io.ReadAll(b.ArmoredSignature.Body)
	if err != nil {
		return nil, err
	}
	if err = b.checkHashHeader(body); err != nil {
		return nil, err
	}
	_, signer, err = openpgp.VerifyDetachedSignature(keyring, bytes.NewBuffer(b.Bytes), bytes.NewReader(body), config)
	return signer, err
}

// checkHashHeader verifies that the Hash header, when present, names at least
// one of the hash algorithms actually used by the signatures in body. It
// returns ErrHashHeaderMismatch otherwise.
//
// Reading the header's contents is not a substitute for verifying the
// signature -- the header is not covered by it -- but a header that names a
// different algorithm than every signature in the message is misleading and is
// rejected instead of being presented as if it described the signature.
func (b *Block) checkHashHeader(body []byte) error {
	values := b.Headers[hashHeader]
	if len(values) == 0 {
		return nil
	}
	reader := packet.NewReader(bytes.NewReader(body))
	sawSignature := false
	matched := false
	for {
		p, err := reader.Next()
		if err != nil {
			// A malformed body is reported by the signature verification, not
			// here; the header can only be cross-checked against packets that
			// were parsed.
			break
		}
		sig, ok := p.(*packet.Signature)
		if !ok {
			continue
		}
		sawSignature = true
		used := nameOfHash(sig.Hash)
		if used == "" {
			continue
		}
		for _, val := range values {
			if val == used {
				matched = true
			}
		}
	}
	if sawSignature && !matched {
		return ErrHashHeaderMismatch
	}
	return nil
}

// writeHashHeader writes the legacy cleartext hash header to buffered.
func writeHashHeader(buffered *bufio.Writer, hashTypes []crypto.Hash) error {
	seen := make(map[string]bool, len(hashTypes))
	if _, err := buffered.WriteString(fmt.Sprintf("%s: ", hashHeader)); err != nil {
		return err
	}

	for index, sigHashType := range hashTypes {
		first := index == 0
		name := nameOfHash(sigHashType)
		if len(name) == 0 {
			return errors.UnsupportedError("unknown hash type: " + strconv.Itoa(int(sigHashType)))
		}

		switch {
		case !seen[name] && first:
			if _, err := buffered.WriteString(name); err != nil {
				return err
			}
		case !seen[name]:
			if _, err := buffered.WriteString(fmt.Sprintf(",%s", name)); err != nil {
				return err
			}
		}
		seen[name] = true
	}

	if err := buffered.WriteByte(lf); err != nil {
		return err
	}

	return nil
}

// nameOfHash returns the OpenPGP name for the given hash, or the empty string
// if the name isn't known. See RFC 4880, section 9.4.
func nameOfHash(h crypto.Hash) string {
	switch h {
	case crypto.MD5:
		return "MD5"
	case crypto.SHA1:
		return "SHA1"
	case crypto.RIPEMD160:
		return "RIPEMD160"
	case crypto.SHA224:
		return "SHA224"
	case crypto.SHA256:
		return "SHA256"
	case crypto.SHA384:
		return "SHA384"
	case crypto.SHA512:
		return "SHA512"
	case crypto.SHA3_256:
		return "SHA3-256"
	case crypto.SHA3_512:
		return "SHA3-512"
	}
	return ""
}

func acceptableHashesToWrite(singingKey *packet.PublicKey) []crypto.Hash {
	switch singingKey.PubKeyAlgo {
	case packet.PubKeyAlgoEd448, packet.PubKeyAlgoMldsa87Ed448:
		return []crypto.Hash{
			crypto.SHA512,
			crypto.SHA3_512,
		}
	case packet.PubKeyAlgoECDSA, packet.PubKeyAlgoEdDSA:
		if curve, err := singingKey.Curve(); err == nil {
			if curve == packet.Curve448 ||
				curve == packet.CurveNistP521 ||
				curve == packet.CurveBrainpoolP512 {
				return []crypto.Hash{
					crypto.SHA512,
					crypto.SHA3_512,
				}
			} else if curve == packet.CurveBrainpoolP384 ||
				curve == packet.CurveNistP384 {
				return []crypto.Hash{
					crypto.SHA384,
					crypto.SHA512,
					crypto.SHA3_512,
				}
			}
		}
	}
	return []crypto.Hash{
		crypto.SHA256,
		crypto.SHA384,
		crypto.SHA512,
		crypto.SHA3_256,
		crypto.SHA3_512,
	}
}
