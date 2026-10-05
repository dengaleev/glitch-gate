package wire

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"slices"
	"testing"
	"testing/iotest"
)

var errBoom = errors.New("boom")

// readBytes runs c.read on b a byte at a time and counts the bytes consumed.
func readBytes(c codec, b []byte) (v any, consumed int, err error) {
	br := bytes.NewReader(b)
	v, err = c.read(iotest.OneByteReader(br))
	return v, len(b) - br.Len(), err
}

func TestRead(t *testing.T) {
	for _, v := range valid() {
		if v.c.read == nil {
			continue
		}
		t.Run(v.c.stage+"/"+v.name, func(t *testing.T) {
			got, consumed, err := readBytes(v.c, append(slices.Clip(v.b), 0xAA))
			if err != nil || consumed != len(v.b) || !reflect.DeepEqual(got, v.want) {
				t.Fatalf("read = %v, %d, %v; want %v, %d", got, consumed, err, v.want, len(v.b))
			}
			for i := range len(v.b) {
				trunc := &ProtocolError{Stage: v.c.stage, Err: io.ErrUnexpectedEOF}
				if _, _, err := readBytes(v.c, v.b[:i]); !reflect.DeepEqual(err, trunc) || !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatalf("read(% x) = %v; want %v", v.b[:i], err, trunc)
				}
				// Data and EOF together, then a read error mid-message.
				if _, err := v.c.read(iotest.DataErrReader(bytes.NewReader(v.b[:i]))); !reflect.DeepEqual(err, trunc) {
					t.Fatalf("read(% x) with EOF = %v; want %v", v.b[:i], err, trunc)
				}
				if _, err := v.c.read(io.MultiReader(bytes.NewReader(v.b[:i]), iotest.ErrReader(errBoom))); err != errBoom {
					t.Fatalf("read(% x, boom) = %v; want boom", v.b[:i], err)
				}
			}
		})
	}
}

func TestReadMalformed(t *testing.T) {
	for _, v := range malformed() {
		if v.c.read == nil {
			continue
		}
		t.Run(v.c.stage+"/"+v.name, func(t *testing.T) {
			// Errors in the bytes read come first, even at EOF or on a read error.
			for _, r := range []io.Reader{
				bytes.NewReader(v.b),
				iotest.OneByteReader(bytes.NewReader(v.b)),
				io.MultiReader(bytes.NewReader(v.b), iotest.ErrReader(errBoom)),
				bytes.NewReader(append(slices.Clip(v.b), make([]byte, 600)...)),
			} {
				_, err := v.c.read(r)
				if pe, ok := errors.AsType[*ProtocolError](err); !ok || *pe != v.want {
					t.Errorf("read = %#v; want %#v", err, v.want)
				}
			}
		})
	}
}

func TestReadReplyRep(t *testing.T) {
	for _, tt := range []struct {
		b   []byte
		rep Reply
		err error
	}{
		{msg(5, 4, 0), ReplyHostUnreachable, &ProtocolError{Stage: StageReply, Err: io.ErrUnexpectedEOF}},
		{msg(5, 4, 0, 1, 1, 2), ReplyHostUnreachable, &ProtocolError{Stage: StageReply, Err: io.ErrUnexpectedEOF}},
		{msg(5, 5, 0, 7), ReplyConnectionRefused, &ProtocolError{Stage: StageReply, Field: FieldATYP, Got: 7}},
	} {
		rep, _, err := ReadReply(bytes.NewReader(tt.b), CmdConnect)
		if rep != tt.rep || !reflect.DeepEqual(err, tt.err) {
			t.Errorf("ReadReply(% x) = %v, %v; want %v, %v", tt.b, rep, err, tt.rep, tt.err)
		}
	}
	if rep, _, err := ReadReply(io.MultiReader(bytes.NewReader(msg(5, 4)), iotest.ErrReader(errBoom)), CmdConnect); rep != 4 || err != errBoom {
		t.Errorf("ReadReply(05 04, boom) = %v, %v", rep, err)
	}
}

// ReadReply never reads past the reply: the next bytes are the tunnel's.
func TestReadReplyExact(t *testing.T) {
	for _, b := range [][]byte{msg(5, 0, 0, v4Bin), msg(5, 0, 0, v6Bin), msg(5, 0, 0, domBin)} {
		br := bytes.NewReader(append(slices.Clip(b), "HTTP/1.1 200 OK"...))
		if _, _, err := ReadReply(br, CmdConnect); err != nil || br.Len() != len("HTTP/1.1 200 OK") {
			t.Errorf("ReadReply(% x): %v, left %d", b, err, br.Len())
		}
	}
}
