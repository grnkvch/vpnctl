package main

import (
	"flag"
	"net"
	"os"
)

func main() {
	network := flag.String("network", "", "tcp4 or udp4")
	address := flag.String("address", "", "listener address")
	flag.Parse()
	if flag.NArg() != 0 || (*network != "tcp4" && *network != "udp4") || *address == "" {
		os.Exit(2)
	}
	if err := serve(*network, *address); err != nil {
		os.Exit(1)
	}
}

func serve(network, address string) error {
	if network == "tcp4" {
		listener, err := net.Listen(network, address)
		if err != nil {
			return err
		}
		defer listener.Close()
		for {
			connection, err := listener.Accept()
			if err != nil {
				return err
			}
			_ = connection.Close()
		}
	}
	listener, err := net.ListenPacket(network, address)
	if err != nil {
		return err
	}
	defer listener.Close()
	buffer := make([]byte, 1)
	for {
		if _, _, err := listener.ReadFrom(buffer); err != nil {
			return err
		}
	}
}
