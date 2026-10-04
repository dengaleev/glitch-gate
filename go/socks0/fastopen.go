package socks0

import (
	"errors"
	"fmt"
)

var errFastOpen = fmt.Errorf("socks0: TCP Fast Open is supported on Linux only: %w", errors.ErrUnsupported)
