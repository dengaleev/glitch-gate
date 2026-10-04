package wire

import (
	"errors"
	"io"
)

const (
	maxGreetingLen = 2 + 255
	maxUserPassLen = 1 + 1 + 255 + 1 + 255
	maxRequest4Len = 8 + 256 + 256 // USERID and name with their NULs
)

func ReadGreeting(r io.Reader) ([]Method, error) {
	var methods []Method
	err := read(r, make([]byte, maxGreetingLen), StageGreeting, func(b []byte) (n int, err error) {
		methods, n, err = ParseGreeting(nil, b)
		return n, err
	})
	return methods, err
}

func ReadUserPass(r io.Reader) (user, pass []byte, err error) {
	err = read(r, make([]byte, maxUserPassLen), StageUserPass, func(b []byte) (n int, err error) {
		user, pass, n, err = ParseUserPass(b)
		return n, err
	})
	return user, pass, err
}

func ReadRequest(r io.Reader) (cmd Command, addr Addr, err error) {
	err = read(r, make([]byte, MaxReplyLen), StageRequest, func(b []byte) (n int, err error) {
		cmd, addr, n, err = ParseRequest(b)
		return n, err
	})
	return cmd, addr, err
}

func ReadMethodSelection(r io.Reader) (Method, error) {
	var m Method
	err := read(r, make([]byte, 2), StageMethodSelection, func(b []byte) (n int, err error) {
		m, n, err = ParseMethodSelection(b)
		return n, err
	})
	return m, err
}

func ReadUserPassStatus(r io.Reader) (status uint8, err error) {
	err = read(r, make([]byte, 2), StageUserPassStatus, func(b []byte) (n int, err error) {
		status, n, err = ParseUserPassStatus(b)
		return n, err
	})
	return status, err
}

// ReadReply sets rep as ParseReply does.
func ReadReply(r io.Reader, cmd Command) (rep Reply, bound Addr, err error) {
	err = read(r, make([]byte, MaxReplyLen), StageReply, func(b []byte) (n int, err error) {
		rep, bound, n, err = ParseReply(b, cmd)
		return n, err
	})
	return rep, bound, err
}

// ReadRequest4 reads a byte at a time while awaiting a NUL; servers should use ParseRequest4.
func ReadRequest4(r io.Reader) (cmd Command, addr Addr, userID []byte, err error) {
	err = read(r, make([]byte, maxRequest4Len), StageRequest4, func(b []byte) (n int, err error) {
		cmd, addr, userID, n, err = ParseRequest4(b)
		return n, err
	})
	return cmd, addr, userID, err
}

// ReadReply4 sets rep as ParseReply4 does.
func ReadReply4(r io.Reader) (rep Reply, bound Addr, err error) {
	err = read(r, make([]byte, reply4Len), StageReply4, func(b []byte) (n int, err error) {
		rep, bound, n, err = ParseReply4(b)
		return n, err
	})
	return rep, bound, err
}

func read(r io.Reader, buf []byte, stage string, parse func([]byte) (int, error)) error {
	have := 0
	for {
		need, err := parse(buf[:have])
		if !errors.Is(err, ErrIncomplete) {
			return err
		}
		got, err := io.ReadFull(r, buf[have:need])
		if err != nil {
			return readFailure(buf[:have+got], err, stage, parse)
		}
		have = need
	}
}

func readFailure(partial []byte, err error, stage string, parse func([]byte) (int, error)) error {
	if _, perr := parse(partial); !errors.Is(perr, ErrIncomplete) {
		return perr
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return &ProtocolError{Stage: stage, Err: io.ErrUnexpectedEOF}
	}
	return err
}
