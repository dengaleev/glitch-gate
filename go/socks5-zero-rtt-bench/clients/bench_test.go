package clients

import "testing"

func BenchmarkClient(b *testing.B) {
	for _, c := range All {
		for _, a := range auths {
			b.Run(c.Name+"/"+a.name, func(b *testing.B) {
				if err := bench(b, c, a.user, a.pass); err != nil {
					b.Fatal(err)
				}
			})
		}
	}
}
