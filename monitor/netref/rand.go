package netref

import (
	"crypto/rand"
	"net"
)

func RandHardwareAddr() (net.HardwareAddr, error) {
	buf := make([]byte, 6)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}

	// Set the local bit (second least significant bit of the first octet)
	// This bit is set to 0 in MAC addresses that are globally unique (OUI enforced)
	// Here, since we are generating locally administered addresses, it should be set
	buf[0] |= 2

	return net.HardwareAddr(buf), nil
}
