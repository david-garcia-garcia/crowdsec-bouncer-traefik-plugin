package bouncer

import (
	"crypto/rand"
	"encoding/hex"
)

// readRandom fills b with cryptographic random bytes. Tests in this package may replace it.
var readRandom = rand.Read

// newRemediationTraceID returns a 16-character lowercase hex ID when the built-in knob is set.
// Rand failure logs a warning and returns empty so the ban or captcha page still writes.
func (b *Bouncer) newRemediationTraceID() string {
	if b.remediationTraceIDHeader == "" {
		return ""
	}
	var buf [8]byte
	if _, err := readRandom(buf[:]); err != nil {
		if b.log != nil {
			b.log.Warn("newRemediationTraceID: " + err.Error())
		}
		return ""
	}
	return hex.EncodeToString(buf[:])
}
