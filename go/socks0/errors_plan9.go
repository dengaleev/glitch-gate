package socks0

import "errors"

var (
	errMsgSize     = errors.New("message too long")
	errDestAddrReq = errors.New("destination address required")
)

func (e *ReplyError) isErrno(error) bool { return false }

func errnoKind(error) Kind { return "" }
