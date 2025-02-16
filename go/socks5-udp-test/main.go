package main

import (
	"encoding/json"
	"flag"
	"log"
	"net"

	"github.com/beevik/ntp"
	"github.com/txthinking/socks5"
)

var (
	socks5Address  = flag.String("socks5", "localhost:1080", "Specify the SOCKS5 proxy server in the format 'host:port'.")
	socks5Username = flag.String("socks5-username", "", "Optional. Username for authentication with the SOCKS5 proxy server.")
	socks5Password = flag.String("socks5-password", "", "Optional. Password for authentication with the SOCKS5 proxy server.")
	ntpAddress     = flag.String("ntp-server", "time-a-g.nist.gov:123", "Specify the NTP server in the format 'host:port'.")
)

const (
	tcpSOCKS5Timeout = 0 // NTP uses UDP, so this value is not applicable for NTP.
	udpSOCKS5Timeout = 1000
)

func main() {
	flag.Parse()

	socks5Cl, err := socks5.NewClient(
		*socks5Address,
		*socks5Username,
		*socks5Password,
		tcpSOCKS5Timeout,
		udpSOCKS5Timeout,
	)
	if err != nil {
		log.Panicf("failed to create SOCKS5 client: %s", err)
	}

	resp, err := ntp.QueryWithOptions(*ntpAddress, ntp.QueryOptions{
		Dialer: func(_, remoteAddress string) (net.Conn, error) {
			return socks5Cl.Dial("udp", remoteAddress)
		},
	})
	if err != nil {
		log.Panicf("request failed: %s", err)
	}

	jsonResp, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		log.Panicf("failed to marshal response: %s", err)
	}

	log.Println(string(jsonResp))
}
