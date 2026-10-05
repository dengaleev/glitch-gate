package server

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestUserPassMatching(t *testing.T) {
	long := strings.Repeat("x", 300)
	a := UserPass{Users: map[string]string{"u": "p", "empty": "", "long": long, "max": long[:255]}}
	for _, tt := range []struct {
		user, pass string
		ok         bool
	}{
		{"u", "p", true}, {"u", "P", false}, {"u", "", false}, {"u", "p\x00", false},
		{"nobody", "p", false}, {"nobody", "", false},
		{"empty", "", true}, {"empty", "\x00", false},
		{"long", long[:255], false}, // stored over 255 bytes can never match
		{"max", long[:255], true},
	} {
		if got := a.verify([]byte(tt.user), []byte(tt.pass)); got != tt.ok {
			t.Errorf("%s/%q: %v", tt.user, tt.pass, got)
		}
	}
	if digest("") == digest("\x00") || digest("ab") != digest([]byte("ab")) {
		t.Error("digest")
	}
}

// Wrong password, unknown user and long passwords must cost the same.
func BenchmarkUserPassMatching(b *testing.B) {
	a := UserPass{Users: map[string]string{"u": "p", "long": strings.Repeat("x", 255)}}
	for _, c := range [][2]string{{"u", "wrong"}, {"nobody", "p"}, {"long", strings.Repeat("y", 255)}, {"u", "p"}} {
		b.Run(c[0]+"/"+c[1][:min(len(c[1]), 5)], func(b *testing.B) {
			user, pass := []byte(c[0]), []byte(c[1])
			for b.Loop() {
				a.verify(user, pass)
			}
		})
	}
}

// Reports how much longer a check of an existing user takes than of an unknown one, in-process (an
// attacker's best case); skipped with -short. Run: go test -run TestUserPassTimingUnknownUser -v ./server
func TestUserPassTimingUnknownUser(t *testing.T) {
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
