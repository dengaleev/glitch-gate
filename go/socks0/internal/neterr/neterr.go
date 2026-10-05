// Package neterr classifies errors for socks0 and its server.
package neterr

import (
	"errors"
	"io"

	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// IsTimeout reports whether any error in err's tree has Timeout() true;
// unlike errors.As, a Timeout() false does not stop the search.
func IsTimeout(err error) bool {
	for err != nil {
		if t, ok := err.(interface{ Timeout() bool }); ok && t.Timeout() {
			return true
		}
		switch u := err.(type) {
		case interface{ Unwrap() error }:
			err = u.Unwrap()
		case interface{ Unwrap() []error }:
			for _, e := range u.Unwrap() {
				if IsTimeout(e) {
					return true
				}
			}
			return false
		default:
			return false
		}
	}
	return false
}

// Truncated maps a stream or message that ended mid-message (io.EOF,
// io.ErrUnexpectedEOF, wire.ErrIncomplete) to a *wire.ProtocolError at stage
// wrapping io.ErrUnexpectedEOF; other errors pass through.
func Truncated(stage string, err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, wire.ErrIncomplete) {
		return &wire.ProtocolError{Stage: stage, Err: io.ErrUnexpectedEOF}
	}
	return err
}
