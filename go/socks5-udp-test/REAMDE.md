# SOCKS5 UDP Test

This is a simple Go program that queries an NTP (Network Time Protocol) server through a SOCKS5 proxy.
It retrieves the time from the specified NTP server and prints the response in a formatted JSON.

## Features

- Connect to an NTP server through a SOCKS5 proxy
- Support for SOCKS5 proxy authentication (username and password)
- Retrieve and display NTP responses in JSON format

## Requirements

- Go 1.18 or higher

## Installation

You can directly run the program using the `go run` command with the package path from GitHub.

## Usage

Run the program with the following command-line flags:

```sh
go run github.com/dengaleev/glitch-gate/go/socks5-udp-test -socks5 <socks5_address> -socks5-username <username> -socks5-password <password> -ntp-server <ntp_server>
```

- `-socks5`: Specify the SOCKS5 proxy server in the format 'host:port' (default: `localhost:1080`)
- `-socks5-username`: Optional. Username for authentication with the SOCKS5 proxy server.
- `-socks5-password`: Optional. Password for authentication with the SOCKS5 proxy server.
- `-ntp-server`: Specify the NTP server in the format 'host:port' (default: `time-a-g.nist.gov:123`)

## Example

```sh
go run github.com/dengaleev/glitch-gate/go/socks5-udp-test -socks5 localhost:1080 -ntp-server time-a-g.nist.gov:123
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
