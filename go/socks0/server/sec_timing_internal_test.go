package server

// Security review: UserPass.verify user-existence timing, in-process (an attacker's best case).
// Run: go test -run TestSecTimingUserExists -v ./server

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSecTimingUserExists(t *testing.T) {
	if testing.Short() {
		t.Skip("timing")
	}
	users := map[string]string{}
	for i := range 10000 {
		users[fmt.Sprintf("user-%05d-%s", i, strings.Repeat("x", 200))] = "pw"
	}
	a := UserPass{Users: users}
	present := []byte(fmt.Sprintf("user-%05d-%s", 4242, strings.Repeat("x", 200)))
	absent := []byte(fmt.Sprintf("user-%05d-%s", 99999, strings.Repeat("x", 200)))
	pass := []byte("wrong")
	const batches, per = 400, 2000
	var tp, ta []float64
	for range batches {
		s := time.Now()
		for range per {
			a.verify(present, pass)
		}
		tp = append(tp, float64(time.Since(s).Nanoseconds())/per)
		s = time.Now()
		for range per {
			a.verify(absent, pass)
		}
		ta = append(ta, float64(time.Since(s).Nanoseconds())/per)
	}
	slices.Sort(tp)
	slices.Sort(ta)
	mp, ma := tp[len(tp)/2], ta[len(ta)/2]
	t.Logf("verify median: existing user %.1f ns, unknown user %.1f ns, diff %.1f ns (%.1f%%)", mp, ma, mp-ma, 100*(mp-ma)/ma)
}
