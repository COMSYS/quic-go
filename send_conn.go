package quic

import (
	"net"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// A sendConn allows sending using a simple Write() on a non-connected packet conn.
type sendConn interface {
	Write([]byte, protocol.TOS) error
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

type sconn struct {
	connection

	remoteAddr net.Addr
	info       *packetInfo
	tos        protocol.TOS
	oob        []byte
}

var _ sendConn = &sconn{}

func newSendConn(c connection, remote net.Addr, info *packetInfo) sendConn {
	sc := &sconn{
		connection: c,
		remoteAddr: remote,
		info:       info,
		tos:        protocol.TOSDefault,
	}
	sc.updateOOB()
	return sc
}

func (c *sconn) updateOOB() {
	ipv4 := utils.AddrIsIPv4(c.remoteAddr)
	c.oob = mergeOOB(c.info.OOB(), tosOOB(c.tos, ipv4))
}

func (c *sconn) Write(p []byte, t protocol.TOS) error {
	if t != c.tos {
		c.tos = t
		c.updateOOB()
	}
	_, err := c.WritePacket(p, c.remoteAddr, c.oob)
	return err
}

func (c *sconn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *sconn) LocalAddr() net.Addr {
	addr := c.connection.LocalAddr()
	if c.info != nil {
		if udpAddr, ok := addr.(*net.UDPAddr); ok {
			addrCopy := *udpAddr
			addrCopy.IP = c.info.addr
			addr = &addrCopy
		}
	}
	return addr
}

type spconnConnected struct {
	*net.UDPConn

	tos protocol.TOS
}

func newSendPconnConnected(c net.PacketConn, remote net.Addr) sendConn {
	udpc, ok := c.(*net.UDPConn)
	if ok {
		return &spconnConnected{UDPConn: udpc, tos: protocol.TOSDefault}
	}
	return nil
}

func (c *spconnConnected) Write(p []byte, t protocol.TOS) error {
	if t != c.tos {
		if err := c.setTOS(t); err != nil {
			return err
		}
		c.tos = t
	}
	_, err := c.UDPConn.Write(p)
	return err
}

func (c *spconnConnected) setTOS(t protocol.TOS) error {
	if utils.AddrIsIPv4(c.RemoteAddr()) {
		return ipv4.NewConn(c.UDPConn).SetTOS(int(t))
	} else {
		return ipv6.NewConn(c.UDPConn).SetTrafficClass(int(t))
	}
}
