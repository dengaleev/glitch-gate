package socks0_test

const errnoMapped = false

var eConnRefused, eConnReset, eMsgSize, eNoBufs, eDestAddrReq error // no errno on plan9

func errnoIsTests() []isTest     { return nil }
func errnoKindTests() []kindTest { return nil }
