// Copyright 2026 Proton AG. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package v2

// SEIPDv2 (AEAD, RFC 4880bis / crypto-refresh sec. 5.13.2) integration tests.
//
// The tests encrypt a fixed multi-chunk SEIPDv2 message, tamper with the
// ciphertext at precisely computed offsets, and verify that the decrypting
// side rejects the message *before* delivering unauthenticated plaintext and
// without reusing stale state afterwards. Legitimate multi-chunk SEIPDv2
// messages and legacy SEIPDv1 (MDC) messages must still decrypt to the exact
// original bytes.
//
// Test matrix (executed in this order):
//
//  | #  | 篡改位置                     | 返回错误                   | 明文是否交付          |
//  |----|------------------------------|----------------------------|-----------------------|
//  | 1  | 第1块密文翻转                | ErrAEADTagVerification     | 否                    |
//  | 2  | 第1块认证标签翻转            | ErrAEADTagVerification     | 否                    |
//  | 3  | 第2块认证标签翻转            | ErrAEADTagVerification     | 仅认证前缀            |
//  | 4  | 块序号交换 (第1块<->第2块)   | ErrAEADTagVerification     | 否                    |
//  | 5  | 块重放 (第1块复制到第2块)    | ErrAEADTagVerification     | 仅认证前缀            |
//  | 6  | 尾部完整性标签翻转           | ErrAEADTagVerification     | 是 (全部, 伴随错误)   |
//  | 7  | 版本字段 2->3                | UnsupportedError           | 否                    |
//  | 8  | 版本字段 2->1                | UnsupportedError           | 否                    |
//  | 9  | 截断: 删除尾部完整性标签     | ErrAEADTagVerification     | 仅前缀                |
//  | 10 | 截断: 截入最后一块中间       | ErrAEADTagVerification     | 仅前缀                |
//  | 11 | 合法 SEIPDv2 多块消息        | 无                         | 完整原文              |
//  | 12 | 合法 SEIPDv1 (MDC) 兼容路径  | 无                         | 完整原文              |

import (
	"bytes"
	stderrs "errors"
	"fmt"
	"io"
	"strings"
	"testing"

	pgpErrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

const (
	// seipdTamperChunkSize is the AEAD chunk size used to build the test
	// message (chunkSizeByte = 0 -> 1 << 6 = 64 bytes per chunk).
	seipdTamperChunkSize = 64
	// seipdTamperTagLen is the authentication tag length of OCB/EAX/GCM.
	seipdTamperTagLen = 16
	// seipdTamperSaltLen is the SEIPDv2 salt length (32 bytes).
	seipdTamperSaltLen = 32
	// seipdTamperHeaderLen is version + cipher + mode + chunkSizeByte.
	seipdTamperHeaderLen = 4
	// seipdTamperMessageLen yields 4 AEAD chunks with the 64-byte chunk size
	// (literal packet overhead included), i.e. a multi-chunk message.
	seipdTamperMessageLen = 200
)

// seipdPacketSpan locates one packet inside a raw OpenPGP message.
type seipdPacketSpan struct {
	tag       byte
	hdrStart  int // offset of the packet type octet
	bodyStart int // offset of the first body octet
	bodyEnd   int // offset one past the last body octet
}

// scanPacketSpans walks the packets of a raw message. The messages generated
// in this test only use new-format headers with definite lengths; anything
// else fails the test loudly instead of silently miscomputing offsets.
func scanPacketSpans(t *testing.T, data []byte) []seipdPacketSpan {
	t.Helper()
	var spans []seipdPacketSpan
	off := 0
	for off < len(data) {
		hdrStart := off
		b := data[off]
		if b&0x80 == 0 {
			t.Fatalf("scanPacketSpans: invalid packet header octet 0x%02x at offset %d", b, off)
		}
		if b&0x40 == 0 {
			t.Fatalf("scanPacketSpans: unexpected old-format packet at offset %d", off)
		}
		tag := b & 0x3f
		off++
		lb := data[off]
		off++
		var length int
		switch {
		case lb < 192:
			length = int(lb)
		case lb < 224:
			length = (int(lb)-192)<<8 + int(data[off]) + 192
			off++
		case lb == 255:
			length = int(data[off])<<24 | int(data[off+1])<<16 | int(data[off+2])<<8 | int(data[off+3])
			off += 4
		default:
			t.Fatalf("scanPacketSpans: unexpected partial body length at offset %d", off-1)
		}
		if off+length > len(data) {
			t.Fatalf("scanPacketSpans: packet at offset %d overruns message", hdrStart)
		}
		spans = append(spans, seipdPacketSpan{
			tag:       tag,
			hdrStart:  hdrStart,
			bodyStart: off,
			bodyEnd:   off + length,
		})
		off += length
	}
	return spans
}

// seipdv2Layout describes the byte offsets of a SEIPDv2 packet in a raw message.
type seipdv2Layout struct {
	span               seipdPacketSpan
	versionOff         int // offset of the SEIPD version octet
	chunksOff          int // offset of the first chunk record
	finalTagOff        int // offset of the trailing integrity tag
	numChunks          int
	fullChunkRecordLen int // chunkSize + tagLen for non-final chunks
}

// locateSEIPDv2 parses the raw message, finds the SEIPD packet (tag 18) and
// computes the offsets of every tamper target. It asserts the message is a
// multi-chunk SEIPDv2 message so the matrix below stays meaningful.
func locateSEIPDv2(t *testing.T, data []byte) seipdv2Layout {
	t.Helper()
	spans := scanPacketSpans(t, data)
	var span *seipdPacketSpan
	for i := range spans {
		if spans[i].tag == 18 { // Symmetrically Encrypted Integrity Protected Data
			span = &spans[i]
		}
	}
	if span == nil {
		t.Fatal("locateSEIPDv2: no SEIPD packet found in generated message")
	}
	if v := data[span.bodyStart]; v != 2 {
		t.Fatalf("locateSEIPDv2: expected SEIPDv2 packet, got version %d", v)
	}
	chunksOff := span.bodyStart + seipdTamperHeaderLen + seipdTamperSaltLen
	finalTagOff := span.bodyEnd - seipdTamperTagLen
	recordLen := seipdTamperChunkSize + seipdTamperTagLen
	chunkRegion := finalTagOff - chunksOff
	numChunks := chunkRegion / recordLen
	if chunkRegion%recordLen != 0 {
		numChunks++
	}
	if numChunks < 3 {
		t.Fatalf("locateSEIPDv2: expected a multi-chunk message, got %d chunk(s)", numChunks)
	}
	return seipdv2Layout{
		span:               *span,
		versionOff:         span.bodyStart,
		chunksOff:          chunksOff,
		finalTagOff:        finalTagOff,
		numChunks:          numChunks,
		fullChunkRecordLen: recordLen,
	}
}

// generateSEIPDMessage builds a password-encrypted message. With aead=true a
// SEIPDv2 packet with 64-byte chunks is produced, otherwise a legacy SEIPDv1
// (MDC) packet.
func generateSEIPDMessage(t *testing.T, message, password []byte, aead bool) []byte {
	t.Helper()
	config := &packet.Config{DefaultCipher: packet.CipherAES256}
	if aead {
		config.AEADConfig = &packet.AEADConfig{
			DefaultMode: packet.AEADModeOCB,
			ChunkSize:   seipdTamperChunkSize,
		}
	}
	var buf bytes.Buffer
	w, err := openpgp.SymmetricallyEncrypt(&buf, password, nil, config)
	if err != nil {
		t.Fatalf("generateSEIPDMessage: %v", err)
	}
	if _, err := w.Write(message); err != nil {
		t.Fatalf("generateSEIPDMessage: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("generateSEIPDMessage: %v", err)
	}
	return buf.Bytes()
}

// seipdDecryptOutcome captures the full result of one decryption attempt.
type seipdDecryptOutcome struct {
	readMessageErr error
	plaintext      []byte
	readErr        error
	postReadN      int   // bytes delivered by a Read after the first error
	postReadErr    error // error of that Read
}

// decryptSEIPDMessage runs the full openpgp decryption path. If reading the
// body fails, it performs one extra Read to prove no plaintext is delivered
// after the rejection.
func decryptSEIPDMessage(t *testing.T, ciphertext, password []byte) seipdDecryptOutcome {
	t.Helper()
	prompt := func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		return password, nil
	}
	md, err := openpgp.ReadMessage(bytes.NewReader(ciphertext), nil, prompt, &packet.Config{})
	if err != nil {
		return seipdDecryptOutcome{readMessageErr: err}
	}
	outcome := seipdDecryptOutcome{}
	outcome.plaintext, outcome.readErr = io.ReadAll(md.UnverifiedBody)
	if outcome.readErr != nil {
		var one [1]byte
		outcome.postReadN, outcome.postReadErr = md.UnverifiedBody.Read(one[:])
	}
	return outcome
}

// ---------------------------------------------------------------------------
// Error matchers (失败类别)
// ---------------------------------------------------------------------------

func isAEADTagError(err error) bool {
	if err == nil {
		return false
	}
	if err == pgpErrors.ErrAEADTagVerification {
		return true
	}
	var derr pgpErrors.DecryptWithSessionKeyError
	if stderrs.As(err, &derr) {
		return strings.Contains(err.Error(), "AEAD tag verification failed")
	}
	return false
}

func isUnsupportedVersionError(err error) bool {
	if err == nil {
		return false
	}
	var uerr pgpErrors.UnsupportedError
	if stderrs.As(err, &uerr) {
		return true
	}
	return strings.Contains(err.Error(), "unknown SymmetricallyEncrypted version")
}

// isUnsupportedCipherError matches the rejection of a SEIPDv2 -> SEIPDv1
// downgrade: a v6 SKESK returns cipher 0, so the legacy MDC path refuses to
// decrypt with "unsupported cipher" before any plaintext exists.
func isUnsupportedCipherError(err error) bool {
	if err == nil {
		return false
	}
	var uerr pgpErrors.UnsupportedError
	if stderrs.As(err, &uerr) {
		return strings.Contains(err.Error(), "unsupported cipher")
	}
	return false
}

// ---------------------------------------------------------------------------
// Tamper primitives (触发偏移)
// ---------------------------------------------------------------------------

func flipByteAt(data []byte, off int) []byte {
	out := bytes.Clone(data)
	out[off] ^= 0x01
	return out
}

func setByteAt(data []byte, off int, v byte) []byte {
	out := bytes.Clone(data)
	out[off] = v
	return out
}

// truncateSEIPDv2Body drops the last `drop` octets of the SEIPDv2 packet body
// and rewrites the packet's two-octet definite length so the result stays a
// syntactically valid packet stream (truncation must be detected by the AEAD
// integrity checks, not by the packet framing layer).
func truncateSEIPDv2Body(t *testing.T, data []byte, layout seipdv2Layout, drop int) []byte {
	t.Helper()
	span := layout.span
	bodyLen := span.bodyEnd - span.bodyStart
	newBodyLen := bodyLen - drop
	if newBodyLen < 192 || newBodyLen >= 8384 {
		t.Fatalf("truncateSEIPDv2Body: new body length %d does not fit a two-octet length", newBodyLen)
	}
	if hdrLen := span.bodyStart - span.hdrStart; hdrLen != 3 {
		t.Fatalf("truncateSEIPDv2Body: expected 1+2 octet header, got %d octets", hdrLen)
	}
	out := make([]byte, 0, len(data)-drop)
	out = append(out, data[:span.hdrStart+1]...) // packet type octet
	l := newBodyLen - 192
	out = append(out, byte(192+(l>>8)), byte(l&0xff))
	out = append(out, data[span.bodyStart:span.bodyEnd-drop]...)
	out = append(out, data[span.bodyEnd:]...)
	return out
}

// ---------------------------------------------------------------------------
// Test matrix definition
// ---------------------------------------------------------------------------

type deliveryExpectation int

const (
	deliverNone          deliveryExpectation = iota // 拒绝前不得交付任何明文
	deliverPrefix                                   // 仅允许交付已认证的严格前缀
	deliverFullWithError                            // 流式交付全部明文, 但最终必须返回完整性错误
)

func (d deliveryExpectation) column() string {
	switch d {
	case deliverNone:
		return "否"
	case deliverPrefix:
		return "仅认证前缀"
	case deliverFullWithError:
		return "是(全部,伴随错误)"
	}
	return "?"
}

type seipdTamperCase struct {
	name        string // 篡改位置
	errCategory string // 失败类别 (用于断言与矩阵展示)
	delivery    deliveryExpectation
	wantErr     func(err error) bool
	tamper      func(t *testing.T, data []byte, layout seipdv2Layout) (mutated []byte, offsets []int)
}

// chunkTamperCases is matrix group 1: 分块篡改 (chunk ciphertext, chunk tags,
// chunk sequencing).
func chunkTamperCases() []seipdTamperCase {
	return []seipdTamperCase{
		{
			name:        "第1块密文翻转",
			errCategory: "ErrAEADTagVerification",
			delivery:    deliverNone,
			wantErr:     isAEADTagError,
			tamper: func(t *testing.T, data []byte, l seipdv2Layout) ([]byte, []int) {
				off := l.chunksOff + 10 // inside chunk #1 ciphertext
				return flipByteAt(data, off), []int{off}
			},
		},
		{
			name:        "第1块认证标签翻转",
			errCategory: "ErrAEADTagVerification",
			delivery:    deliverNone,
			wantErr:     isAEADTagError,
			tamper: func(t *testing.T, data []byte, l seipdv2Layout) ([]byte, []int) {
				off := l.chunksOff + seipdTamperChunkSize // first tag octet of chunk #1
				return flipByteAt(data, off), []int{off}
			},
		},
		{
			name:        "第2块认证标签翻转",
			errCategory: "ErrAEADTagVerification",
			delivery:    deliverPrefix,
			wantErr:     isAEADTagError,
			tamper: func(t *testing.T, data []byte, l seipdv2Layout) ([]byte, []int) {
				off := l.chunksOff + l.fullChunkRecordLen + seipdTamperChunkSize // tag of chunk #2
				return flipByteAt(data, off), []int{off}
			},
		},
		{
			name:        "块序号交换(第1块<->第2块)",
			errCategory: "ErrAEADTagVerification",
			delivery:    deliverNone,
			wantErr:     isAEADTagError,
			tamper: func(t *testing.T, data []byte, l seipdv2Layout) ([]byte, []int) {
				rec := l.fullChunkRecordLen
				out := bytes.Clone(data)
				c1 := bytes.Clone(out[l.chunksOff : l.chunksOff+rec])
				copy(out[l.chunksOff:l.chunksOff+rec], out[l.chunksOff+rec:l.chunksOff+2*rec])
				copy(out[l.chunksOff+rec:l.chunksOff+2*rec], c1)
				return out, []int{l.chunksOff, l.chunksOff + rec}
			},
		},
		{
			name:        "块重放(第1块复制到第2块)",
			errCategory: "ErrAEADTagVerification",
			delivery:    deliverPrefix,
			wantErr:     isAEADTagError,
			tamper: func(t *testing.T, data []byte, l seipdv2Layout) ([]byte, []int) {
				rec := l.fullChunkRecordLen
				out := bytes.Clone(data)
				copy(out[l.chunksOff+rec:l.chunksOff+2*rec], out[l.chunksOff:l.chunksOff+rec])
				return out, []int{l.chunksOff + rec}
			},
		},
	}
}

// versionTruncationCases is matrix group 2: 尾部完整性, 版本字段与截断位置.
func versionTruncationCases() []seipdTamperCase {
	return []seipdTamperCase{
		{
			name:        "尾部完整性标签翻转",
			errCategory: "ErrAEADTagVerification",
			delivery:    deliverFullWithError,
			wantErr:     isAEADTagError,
			tamper: func(t *testing.T, data []byte, l seipdv2Layout) ([]byte, []int) {
				off := l.finalTagOff + 5 // inside the trailing integrity tag
				return flipByteAt(data, off), []int{off}
			},
		},
		{
			name:        "版本字段2->3",
			errCategory: "UnsupportedError",
			delivery:    deliverNone,
			wantErr:     isUnsupportedVersionError,
			tamper: func(t *testing.T, data []byte, l seipdv2Layout) ([]byte, []int) {
				return setByteAt(data, l.versionOff, 3), []int{l.versionOff}
			},
		},
		{
			name:        "版本字段2->1",
			errCategory: "UnsupportedError(降级拒绝)",
			delivery:    deliverNone,
			wantErr:     isUnsupportedCipherError,
			tamper: func(t *testing.T, data []byte, l seipdv2Layout) ([]byte, []int) {
				return setByteAt(data, l.versionOff, 1), []int{l.versionOff}
			},
		},
		{
			name:        "截断:删除尾部完整性标签",
			errCategory: "ErrAEADTagVerification",
			delivery:    deliverPrefix,
			wantErr:     isAEADTagError,
			tamper: func(t *testing.T, data []byte, l seipdv2Layout) ([]byte, []int) {
				return truncateSEIPDv2Body(t, data, l, seipdTamperTagLen), []int{l.finalTagOff}
			},
		},
		{
			name:        "截断:截入最后一块中间",
			errCategory: "ErrAEADTagVerification",
			delivery:    deliverPrefix,
			wantErr:     isAEADTagError,
			tamper: func(t *testing.T, data []byte, l seipdv2Layout) ([]byte, []int) {
				off := l.span.bodyEnd - 40
				return truncateSEIPDv2Body(t, data, l, 40), []int{off}
			},
		},
	}
}

// check executes one tampered-message case and asserts the full contract:
// correct failure category, no plaintext delivered before rejection, no
// plaintext delivered after rejection, and no stale state reused afterwards.
// It returns the number of delivered plaintext bytes for stability checks.
func (tc seipdTamperCase) check(
	t *testing.T,
	valid []byte,
	layout seipdv2Layout,
	message, password []byte,
) int {
	t.Helper()

	mutated, offsets := tc.tamper(t, valid, layout)
	if bytes.Equal(mutated, valid) {
		t.Fatalf("[%s] 篡改未生效: 触发偏移 %v 处字节未改变", tc.name, offsets)
	}

	outcome := decryptSEIPDMessage(t, mutated, password)

	stage := "ReadMessage"
	gotErr := outcome.readMessageErr
	if gotErr == nil {
		stage = "Read"
		gotErr = outcome.readErr
	}
	if gotErr == nil {
		t.Fatalf("[%s] 篡改未被拒绝: 触发偏移=%v 失败类别期望=%s",
			tc.name, offsets, tc.errCategory)
	}
	if !tc.wantErr(gotErr) {
		t.Fatalf("[%s] 失败类别不符: 触发偏移=%v 阶段=%s 期望=%s 实际错误=%v (类型 %T)",
			tc.name, offsets, stage, tc.errCategory, gotErr, gotErr)
	}

	switch tc.delivery {
	case deliverNone:
		if len(outcome.plaintext) != 0 {
			t.Fatalf("[%s] 拒绝前交付了明文: 触发偏移=%v 交付=%d 字节",
				tc.name, offsets, len(outcome.plaintext))
		}
	case deliverPrefix:
		if outcome.readMessageErr != nil {
			t.Fatalf("[%s] ReadMessage 不应失败: 触发偏移=%v 错误=%v",
				tc.name, offsets, outcome.readMessageErr)
		}
		if len(outcome.plaintext) >= len(message) ||
			!bytes.Equal(outcome.plaintext, message[:len(outcome.plaintext)]) {
			t.Fatalf("[%s] 交付的明文不是已认证前缀: 触发偏移=%v 交付=%d 字节",
				tc.name, offsets, len(outcome.plaintext))
		}
	case deliverFullWithError:
		if !bytes.Equal(outcome.plaintext, message) {
			t.Fatalf("[%s] 流式交付的明文与原文不符: 触发偏移=%v 交付=%d 字节",
				tc.name, offsets, len(outcome.plaintext))
		}
	}

	// 拒绝之后不得再交付任何字节 (无滞后明文泄漏)。
	if outcome.readMessageErr == nil && outcome.readErr != nil {
		if outcome.postReadN != 0 || outcome.postReadErr == nil {
			t.Fatalf("[%s] 拒绝后仍交付明文或读取未报错: 触发偏移=%v postReadN=%d postReadErr=%v",
				tc.name, offsets, outcome.postReadN, outcome.postReadErr)
		}
	}

	// 拒绝篡改消息之后, 解密端不得复用旧状态: 合法消息必须仍能完整解密。
	fresh := decryptSEIPDMessage(t, valid, password)
	if fresh.readMessageErr != nil || fresh.readErr != nil ||
		!bytes.Equal(fresh.plaintext, message) {
		t.Fatalf("[%s] 拒绝后合法消息解密失败 (疑似复用旧状态): 触发偏移=%v readMessageErr=%v readErr=%v",
			tc.name, offsets, fresh.readMessageErr, fresh.readErr)
	}

	t.Logf("矩阵行 | 篡改位置=%s | 触发偏移=%v | 返回错误=%s(%s阶段) | 明文是否交付=%s",
		tc.name, offsets, tc.errCategory, stage, tc.delivery.column())
	return len(outcome.plaintext)
}

// TestSEIPDv2TamperResistance runs matrix groups 1 (分块篡改) and 2
// (版本/尾部完整性/截断). Every case runs against two independently generated
// ciphertexts (different salt/session key) and the delivered plaintext length
// must be identical across runs (重复运行稳定).
func TestSEIPDv2TamperResistance(t *testing.T) {
	password := []byte("seipdv2-t4mper-resistance")
	message := make([]byte, seipdTamperMessageLen)
	for i := range message {
		message[i] = byte(i*31 + 7)
	}

	groups := []struct {
		name  string
		cases []seipdTamperCase
	}{
		{"1-chunk-tampering", chunkTamperCases()},
		{"2-version-integrity-truncation", versionTruncationCases()},
	}

	deliveredByRun := map[string][]int{}
	var matrixRows []string

	for run := 0; run < 2; run++ {
		valid := generateSEIPDMessage(t, message, password, true)
		layout := locateSEIPDv2(t, valid)

		t.Run(fmt.Sprintf("run-%d", run), func(t *testing.T) {
			for _, group := range groups {
				group := group
				t.Run(group.name, func(t *testing.T) {
					for _, tc := range group.cases {
						tc := tc
						t.Run(tc.name, func(t *testing.T) {
							delivered := tc.check(t, valid, layout, message, password)
							deliveredByRun[tc.name] = append(deliveredByRun[tc.name], delivered)
							if run == 0 {
								matrixRows = append(matrixRows, fmt.Sprintf(
									"| 篡改位置=%s | 返回错误=%s | 明文是否交付=%s |",
									tc.name, tc.errCategory, tc.delivery.column()))
							}
						})
					}
				})
			}
		})
	}

	// 重复运行稳定性: 同一篡改位置在不同密文下的交付长度必须一致。
	for name, delivered := range deliveredByRun {
		if len(delivered) == 2 && delivered[0] != delivered[1] {
			t.Errorf("重复运行不稳定: 篡改位置=%s 第一次交付=%d 字节 第二次交付=%d 字节",
				name, delivered[0], delivered[1])
		}
	}

	t.Log("SEIPDv2 篡改测试矩阵:")
	for _, row := range matrixRows {
		t.Log(row)
	}
}

// TestSEIPDv2AndV1Compatibility is matrix group 3: 合法兼容. A legitimate
// multi-chunk SEIPDv2 message and a legacy SEIPDv1 (MDC) message must both
// decrypt to the exact original bytes.
func TestSEIPDv2AndV1Compatibility(t *testing.T) {
	password := []byte("seipdv2-compat-password")
	message := make([]byte, seipdTamperMessageLen)
	for i := range message {
		message[i] = byte(i*17 + 3)
	}

	t.Run("合法SEIPDv2多块消息", func(t *testing.T) {
		valid := generateSEIPDMessage(t, message, password, true)
		layout := locateSEIPDv2(t, valid)
		if layout.numChunks < 3 {
			t.Fatalf("期望多块消息, 实际块数=%d", layout.numChunks)
		}
		outcome := decryptSEIPDMessage(t, valid, password)
		if outcome.readMessageErr != nil || outcome.readErr != nil {
			t.Fatalf("合法 SEIPDv2 消息解密失败: readMessageErr=%v readErr=%v",
				outcome.readMessageErr, outcome.readErr)
		}
		if !bytes.Equal(outcome.plaintext, message) {
			t.Fatalf("合法 SEIPDv2 消息解密结果与原字节不符: 交付=%d 字节, 期望=%d 字节",
				len(outcome.plaintext), len(message))
		}
		t.Logf("矩阵行 | 篡改位置=无(合法SEIPDv2, 块数=%d) | 返回错误=无 | 明文是否交付=完整原文", layout.numChunks)
	})

	t.Run("合法SEIPDv1(MDC)兼容路径", func(t *testing.T) {
		valid := generateSEIPDMessage(t, message, password, false)
		spans := scanPacketSpans(t, valid)
		var seipd *seipdPacketSpan
		for i := range spans {
			if spans[i].tag == 18 {
				seipd = &spans[i]
			}
		}
		if seipd == nil {
			t.Fatal("未找到 SEIPD 包")
		}
		if v := valid[seipd.bodyStart]; v != 1 {
			t.Fatalf("期望 SEIPDv1 (MDC) 包, 实际版本=%d", v)
		}
		outcome := decryptSEIPDMessage(t, valid, password)
		if outcome.readMessageErr != nil || outcome.readErr != nil {
			t.Fatalf("旧版本兼容路径解密失败: readMessageErr=%v readErr=%v",
				outcome.readMessageErr, outcome.readErr)
		}
		if !bytes.Equal(outcome.plaintext, message) {
			t.Fatalf("旧版本兼容路径解密结果与原字节不符: 交付=%d 字节, 期望=%d 字节",
				len(outcome.plaintext), len(message))
		}
		t.Log("矩阵行 | 篡改位置=无(合法SEIPDv1/MDC) | 返回错误=无 | 明文是否交付=完整原文")
	})
}
