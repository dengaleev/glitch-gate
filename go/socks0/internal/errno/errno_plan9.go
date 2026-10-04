// Package errno mirrors SOCKS5 REP codes and errnos; plan9 has no errnos.
package errno

import "github.com/dengaleev/glitch-gate/go/socks0/wire"

// Is is always false: plan9 has no errnos.
func Is(wire.Reply, error) bool { return false }

// Reply is always false: plan9 has no errnos.
func Reply(error) (wire.Reply, bool) { return 0, false }
