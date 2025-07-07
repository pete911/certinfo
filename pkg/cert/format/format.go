package format

import (
	"encoding/hex"
	"strings"
	"time"
)

func HexArray(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	buf := make([]byte, 0, 3*len(b))
	x := buf[1*len(b) : 3*len(b)]
	hex.Encode(x, b)
	for i := 0; i < len(x); i += 2 {
		buf = append(buf, x[i], x[i+1], ':')
	}
	return strings.ToUpper(string(buf[:len(buf)-1]))
}

func Validity(t time.Time) string {
	// format for NotBefore and NotAfter fields to make output similar to openssl
	return t.Format("Jan _2 15:04:05 2006 MST")
}

func SplitString(in, prefix string, size int) []string {
	if len(in) <= size {
		return []string{prefix + in}
	}

	var chunk string
	var out []string
	for {
		in, chunk = in[size:], in[:size]
		out = append(out, prefix+chunk)
		if len(in) <= size {
			out = append(out, prefix+in)
			break
		}
	}
	return out
}
