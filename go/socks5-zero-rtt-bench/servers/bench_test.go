package servers

import "testing"

// BenchmarkServer times the Allocs unit (allocCase).
func BenchmarkServer(b *testing.B) {
	for _, s := range All {
		b.Run(s.Name, func(b *testing.B) {
			r, err := allocRig(s)
			if err != nil {
				b.Fatal(err)
			}
			defer r.close()
			b.ReportAllocs()
			for b.Loop() {
				if err := r.run(b.Context(), allocCase); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
