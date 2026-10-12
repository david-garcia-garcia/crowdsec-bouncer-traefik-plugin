package modsecurity

import (
	"bytes"
	"io"
	"net/http"
	"sync"
)

func newBodyBufferPool() *sync.Pool {
	return &sync.Pool{
		New: func() interface{} {
			return new(bytes.Buffer)
		},
	}
}

// readInboundBody copies req.Body for the sidecar and next.
// A positive bodyLimit wraps MaxBytesReader. 0 is unlimited.
func (c *Client) readInboundBody(rw http.ResponseWriter, req *http.Request) (body []byte, err error) {
	if c.bodyLimit > 0 {
		req.Body = http.MaxBytesReader(rw, req.Body, c.bodyLimit)
	}

	if req.ContentLength >= 0 && req.ContentLength > c.poolCap {
		return io.ReadAll(req.Body)
	}

	buf, _ := c.bodyBufferPool.Get().(*bytes.Buffer)
	if buf == nil {
		buf = new(bytes.Buffer)
	}
	buf.Reset()
	defer c.bodyBufferPool.Put(buf)

	limited := io.LimitReader(req.Body, c.poolCap)
	n, readErr := io.Copy(buf, limited)
	if readErr != nil {
		return nil, readErr
	}

	if n == c.poolCap {
		var peek [1]byte
		extra, peekErr := req.Body.Read(peek[:])
		if peekErr != nil && peekErr != io.EOF {
			return nil, peekErr
		}
		if extra > 0 {
			prefix := append([]byte(nil), buf.Bytes()...)
			rest, restErr := io.ReadAll(req.Body)
			if restErr != nil {
				return nil, restErr
			}
			owned := make([]byte, 0, len(prefix)+extra+len(rest))
			owned = append(owned, prefix...)
			owned = append(owned, peek[0])
			owned = append(owned, rest...)
			return owned, nil
		}
	}

	return append([]byte(nil), buf.Bytes()...), nil
}
