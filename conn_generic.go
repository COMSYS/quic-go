// +build !darwin,!linux,!freebsd,!windows

package quic

import (
	"net"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

func newConn(c net.PacketConn) (connection, error) {
	return &basicConn{PacketConn: c}, nil
}

func inspectReadBuffer(interface{}) (int, error) {
	return 0, nil
}

func (i *packetInfo) OOB() []byte             { return nil }
func tosOOB(t protocol.TOS, ipv4 bool) []byte { return nil }
func mergeOOB(oob ...[]byte) []byte           { return nil }
