package cache

import (
	"strconv"
	"strings"
)

// packedIndexSep marks a packed kind-plus-origin-id in a range-index line.
// It is not the U+001F leftover suffix.
const packedIndexSep = "\x1e"

// Stored is a remediation payload: packed memory word or leftover string.
type Stored struct {
	word uint32
	text string
}

// Packed is kind in the low 8 bits and origin id in the next 16.
func Packed(kind string, originID uint16) Stored {
	if kind == "" {
		return Stored{}
	}
	return Stored{word: uint32(kind[0]) | uint32(originID)<<8}
}

// Leftover is a letter-only or U+001F origin string (Redis, live/none, overflow).
func Leftover(text string) Stored {
	return Stored{text: text}
}

// storedFromWord rebuilds a packed Stored from a ttl_map uint32.
func storedFromWord(word uint32) Stored {
	return Stored{word: word}
}

// PackedWord is the ttl_map value when this Stored interned.
func (s Stored) PackedWord() (uint32, bool) {
	if s.word == 0 {
		return 0, false
	}
	return s.word, true
}

// PackedOriginID is the intern id when this Stored is packed.
func (s Stored) PackedOriginID() (uint16, bool) {
	if s.word == 0 {
		return 0, false
	}
	return uint16((s.word >> 8) & 0xFFFF), true //nolint:gosec // G115: origin id is stored in 16 bits
}

// Kind is the ban/captcha/none letter from the packed word or leftover first letter.
func (s Stored) Kind() string {
	if s.word != 0 {
		return string([]byte{byte(s.word)})
	}
	return RemediationKind(s.text)
}

// LeftoverOrigin is the U+001F suffix when this Stored is not packed.
func (s Stored) LeftoverOrigin() string {
	if s.word != 0 {
		return ""
	}
	return RemediationOrigin(s.text)
}

// IndexForm is the range-index / leftover string encoding of this Stored.
func (s Stored) IndexForm() string {
	if s.word != 0 {
		kind := string([]byte{byte(s.word)})
		id := uint64(s.word >> 8)
		return kind + packedIndexSep + strconv.FormatUint(id, 10)
	}
	return s.text
}

// ParseStored rebuilds a packed or leftover value from an index line or Get string.
func ParseStored(raw string) Stored {
	if raw == "" {
		return Stored{}
	}
	kind, rest, ok := strings.Cut(raw, packedIndexSep)
	if ok && len(kind) == 1 {
		id, err := strconv.ParseUint(rest, 10, 16)
		if err == nil {
			return Packed(kind, uint16(id))
		}
	}
	return Leftover(raw)
}

// ParsePackedOriginID is the intern id encoded in a packed index form, if any.
func ParsePackedOriginID(raw string) (uint16, bool) {
	return ParseStored(raw).PackedOriginID()
}
