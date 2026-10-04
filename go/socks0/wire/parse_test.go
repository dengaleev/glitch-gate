package wire

import (
	"errors"
	"reflect"
	"slices"
	"testing"
)

func TestParse(t *testing.T) {
	for _, v := range valid() {
		t.Run(v.c.stage+"/"+v.name, func(t *testing.T) {
			checkParse(t, v.c, v.b, v.want)
		})
	}
}

// checkParse checks the Parse contract on b, its prefixes and b with trailing bytes.
func checkParse(t *testing.T, c codec, b []byte, want any) {
	t.Helper()
	for _, in := range [][]byte{b, append(slices.Clip(b), 0xAA, 0xBB)} {
		got, n, err := c.parse(in)
		if err != nil || n != len(b) || !reflect.DeepEqual(got, want) {
			t.Fatalf("parse(% x) = %v, %d, %v; want %v, %d", in, got, n, err, want, len(b))
		}
	}
	for i := range len(b) {
		if _, n, err := c.parse(b[:i]); err != ErrIncomplete || n <= i || n > len(b) {
			t.Fatalf("parse(% x) = %d, %v; want ErrIncomplete, %d < n ≤ %d", b[:i], n, err, i, len(b))
		}
	}
}

func TestParseMalformed(t *testing.T) {
	for _, v := range malformed() {
		t.Run(v.c.stage+"/"+v.name, func(t *testing.T) {
			for _, in := range [][]byte{v.b, append(slices.Clip(v.b), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)} {
				_, n, err := v.c.parse(in)
				if pe, ok := errors.AsType[*ProtocolError](err); !ok || *pe != v.want || n != 0 {
					t.Errorf("parse(% x) = %d, %#v; want 0, %#v", in, n, err, v.want)
				}
			}
		})
	}
}

func TestParseReplyRep(t *testing.T) {
	for _, tt := range []struct {
		b   []byte
		rep Reply
		n   int
		err error
	}{
		{msg(5, 4), ReplyHostUnreachable, 5, ErrIncomplete},
		{msg(5, 4, 0, 1, 0), ReplyHostUnreachable, 10, ErrIncomplete},
		{msg(5, 5, 0, 9), ReplyConnectionRefused, 0, &ProtocolError{Stage: StageReply, Field: FieldATYP, Got: 9}},
		{msg(5, 0xF6, 0, 3, 0), ReplyTorHSBadAddress, 0, &ProtocolError{Stage: StageReply, Field: FieldADDR}},
	} {
		rep, _, n, err := ParseReply(tt.b, CmdConnect)
		if rep != tt.rep || n != tt.n || !reflect.DeepEqual(err, tt.err) {
			t.Errorf("ParseReply(% x) = %v, %d, %v; want %v, %d, %v", tt.b, rep, n, err, tt.rep, tt.n, tt.err)
		}
	}
}

func TestParseGreetingDst(t *testing.T) {
	dst := make([]Method, 1, 255)
	got, _, err := ParseGreeting(dst, msg(5, 2, 1, 2))
	if want := []Method{0, 1, 2}; err != nil || !slices.Equal(got, want) || &got[0] != &dst[0] {
		t.Errorf("ParseGreeting = %v, %v; want %v appended in place", got, err, want)
	}
}

func TestParseUserPassAliases(t *testing.T) {
	b := msg(1, 1, "u", 1, "p", 0xEE)
	user, pass, _, _ := ParseUserPass(b)
	if &user[0] != &b[2] || &pass[0] != &b[4] || cap(user) != 1 || cap(pass) != 1 {
		t.Error("user and pass must alias b, capped to their length")
	}
}
