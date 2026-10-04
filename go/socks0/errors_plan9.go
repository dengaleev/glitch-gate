package socks0

import "errors"

var (
	errMsgSize     = errors.New("message too long")
	errDestAddrReq = errors.New("destination address required")
)

func errnoKind(error) Kind { return "" }
