// Command server is the dual-stack HTTP server for the happy-eyeballs demo.
// Listening on ":8080" binds [::]:8080, which on Linux serves both IPv4 and
// IPv6 from one socket; the X-Served-By header reports the local address (and
// thus the family) that handled each request.
package main

import (
	"log"
	"net"
	"net/http"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	log.Print("listening on :8080 (dual-stack)")
	log.Fatal(http.ListenAndServe(":8080", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		local, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
		w.Header().Set("X-Served-By", local.String())
		log.Printf("served %s from %s on %s", r.URL.Path, r.RemoteAddr, local)
	})))
}
