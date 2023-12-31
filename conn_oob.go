// +build darwin linux freebsd

package quic

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

func inspectReadBuffer(c interface{}) (int, error) {
	conn, ok := c.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return 0, errors.New("doesn't have a SyscallConn")
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("couldn't get syscall.RawConn: %w", err)
	}
	var size int
	var serr error
	if err := rawConn.Control(func(fd uintptr) {
		size, serr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
	}); err != nil {
		return 0, err
	}
	return size, serr
}

type oobConn struct {
	OOBCapablePacketConn
	oobBuffer []byte
}

var _ connection = &oobConn{}

func newConn(c OOBCapablePacketConn) (*oobConn, error) {
	rawConn, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	needsPacketInfo := false
	if udpAddr, ok := c.LocalAddr().(*net.UDPAddr); ok && udpAddr.IP.IsUnspecified() {
		needsPacketInfo = true
	}
	// We don't know if this a IPv4-only, IPv6-only or a IPv4-and-IPv6 connection.
	// Try enabling receiving of ECN and packet info for both IP versions.
	// We expect at least one of those syscalls to succeed.
	var errECNIPv4, errECNIPv6, errPIIPv4, errPIIPv6 error
	if err := rawConn.Control(func(fd uintptr) {
		errECNIPv4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTOS, 1)
		errECNIPv6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVTCLASS, 1)

		if needsPacketInfo {
			errPIIPv4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, ipv4RECVPKTINFO, 1)
			errPIIPv6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, ipv6RECVPKTINFO, 1)
		}
	}); err != nil {
		return nil, err
	}
	switch {
	case errECNIPv4 == nil && errECNIPv6 == nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv4 and IPv6.")
	case errECNIPv4 == nil && errECNIPv6 != nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv4.")
	case errECNIPv4 != nil && errECNIPv6 == nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv6.")
	case errECNIPv4 != nil && errECNIPv6 != nil:
		return nil, errors.New("activating ECN failed for both IPv4 and IPv6")
	}
	if needsPacketInfo {
		switch {
		case errPIIPv4 == nil && errPIIPv6 == nil:
			utils.DefaultLogger.Debugf("Activating reading of packet info for IPv4 and IPv6.")
		case errPIIPv4 == nil && errPIIPv6 != nil:
			utils.DefaultLogger.Debugf("Activating reading of packet info bits for IPv4.")
		case errPIIPv4 != nil && errPIIPv6 == nil:
			utils.DefaultLogger.Debugf("Activating reading of packet info bits for IPv6.")
		case errPIIPv4 != nil && errPIIPv6 != nil:
			return nil, errors.New("activating packet info failed for both IPv4 and IPv6")
		}
	}
	return &oobConn{
		OOBCapablePacketConn: c,
		oobBuffer:            make([]byte, 128),
	}, nil
}

func (c *oobConn) ReadPacket() (*receivedPacket, error) {
	buffer := getPacketBuffer()
	// The packet size should not exceed protocol.MaxPacketBufferSize bytes
	// If it does, we only read a truncated packet, which will then end up undecryptable
	buffer.Data = buffer.Data[:protocol.MaxPacketBufferSize]
	c.oobBuffer = c.oobBuffer[:cap(c.oobBuffer)]
	n, oobn, _, addr, err := c.OOBCapablePacketConn.ReadMsgUDP(buffer.Data, c.oobBuffer)
	if err != nil {
		return nil, err
	}
	ctrlMsgs, err := unix.ParseSocketControlMessage(c.oobBuffer[:oobn])
	if err != nil {
		return nil, err
	}
	var destIP net.IP
	var ifIndex uint32
	for _, ctrlMsg := range ctrlMsgs {
		if ctrlMsg.Header.Level == unix.IPPROTO_IP {
			switch ctrlMsg.Header.Type {
			case msgTypeIPTOS:
				buffer.TOS = protocol.TOS(ctrlMsg.Data[0])
			case msgTypeIPv4PKTINFO:
				// struct in_pktinfo {
				// 	unsigned int   ipi_ifindex;  /* Interface index */
				// 	struct in_addr ipi_spec_dst; /* Local address */
				// 	struct in_addr ipi_addr;     /* Header Destination
				// 									address */
				// };
				if len(ctrlMsg.Data) == 12 {
					ifIndex = binary.LittleEndian.Uint32(ctrlMsg.Data)
					destIP = net.IP(ctrlMsg.Data[8:12])
				} else if len(ctrlMsg.Data) == 4 {
					// FreeBSD
					destIP = net.IP(ctrlMsg.Data)
				}
			}
		}
		if ctrlMsg.Header.Level == unix.IPPROTO_IPV6 {
			switch ctrlMsg.Header.Type {
			case unix.IPV6_TCLASS:
				buffer.TOS = protocol.TOS(ctrlMsg.Data[0])
			case msgTypeIPv6PKTINFO:
				// struct in6_pktinfo {
				// 	struct in6_addr ipi6_addr;    /* src/dst IPv6 address */
				// 	unsigned int    ipi6_ifindex; /* send/recv interface index */
				// };
				if len(ctrlMsg.Data) == 20 {
					destIP = net.IP(ctrlMsg.Data[:16])
					ifIndex = binary.LittleEndian.Uint32(ctrlMsg.Data[16:])
				}
			}
		}
	}
	var info *packetInfo
	if destIP != nil {
		info = &packetInfo{
			addr:    destIP,
			ifIndex: ifIndex,
		}
	}
	return &receivedPacket{
		remoteAddr: addr,
		rcvTime:    time.Now(),
		data:       buffer.Data[:n],
		info:       info,
		buffer:     buffer,
	}, nil
}

func (c *oobConn) WritePacket(b []byte, addr net.Addr, oob []byte) (n int, err error) {
	n, _, err = c.OOBCapablePacketConn.WriteMsgUDP(b, oob, addr.(*net.UDPAddr))
	return n, err
}

func (info *packetInfo) OOB() []byte {
	if info == nil {
		return nil
	}
	if ip4 := info.addr.To4(); ip4 != nil {
		// struct in_pktinfo {
		// 	unsigned int   ipi_ifindex;  /* Interface index */
		// 	struct in_addr ipi_spec_dst; /* Local address */
		// 	struct in_addr ipi_addr;     /* Header Destination address */
		// };
		msgLen := 12
		if runtime.GOOS == "freebsd" {
			msgLen = 4
		}
		cmsglen := unix.CmsgLen(msgLen)
		oob := make([]byte, cmsglen)
		cmsg := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
		cmsg.Level = unix.IPPROTO_IP
		cmsg.Type = msgTypeIPv4PKTINFO
		cmsg.SetLen(cmsglen)
		off := unix.CmsgLen(0)
		if runtime.GOOS != "freebsd" {
			// FreeBSD does not support in_pktinfo, just an in_addr is sent
			binary.LittleEndian.PutUint32(oob[off:], info.ifIndex)
			off += 4
		}
		copy(oob[off:], ip4)
		return oob
	} else if len(info.addr) == 16 {
		// struct in6_pktinfo {
		// 	struct in6_addr ipi6_addr;    /* src/dst IPv6 address */
		// 	unsigned int    ipi6_ifindex; /* send/recv interface index */
		// };
		const msgLen = 20
		cmsglen := unix.CmsgLen(msgLen)
		oob := make([]byte, cmsglen)
		cmsg := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
		cmsg.Level = unix.IPPROTO_IPV6
		cmsg.Type = msgTypeIPv6PKTINFO
		cmsg.SetLen(cmsglen)
		off := unix.CmsgLen(0)
		off += copy(oob[off:], info.addr)
		binary.LittleEndian.PutUint32(oob[off:], info.ifIndex)
		return oob
	}
	return nil
}

// Specifying TOS/traffic class via ancillary data:
// * IPv4 (Linux): https://lore.kernel.org/all/cover.1379944641.git.ffusco@redhat.com/T/#u
// * IPv4 (FreeBSD): https://github.com/freebsd/freebsd-src/blob/release/10.0.0/sys/netinet/udp_usrreq.c#L1021-L1027
// * IPv4 (Darwin): ???
// * IPv6: RFC 3542 section 6.5
// See also https://github.com/quicwg/base-drafts/wiki/ECN-in-QUIC#ecn-support-in-various-os-stacks
func tosOOB(t protocol.TOS, ipv4 bool) []byte {
	if t == protocol.TOSDefault {
		return nil
	}
	useByte := runtime.GOOS == "freebsd" && ipv4
	msgLen := 4
	if useByte {
		msgLen = 1
	}
	cmsglen := unix.CmsgLen(msgLen)
	oob := make([]byte, cmsglen)
	cmsg := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	if ipv4 {
		cmsg.Level = unix.IPPROTO_IP
		cmsg.Type = unix.IP_TOS
	} else {
		cmsg.Level = unix.IPPROTO_IPV6
		cmsg.Type = unix.IPV6_TCLASS
	}
	cmsg.SetLen(cmsglen)
	off := unix.CmsgLen(0)
	if useByte {
		oob[off] = byte(t)
	} else {
		binary.LittleEndian.PutUint32(oob[off:], uint32(t))
	}
	return oob
}

func mergeOOB(oob ...[]byte) []byte {
	off := 0
	for _, buf := range oob {
		if buf == nil {
			continue
		}
		off += unix.CmsgSpace(len(buf) - unix.CmsgLen(0)) // == CMSG_ALIGN(cmsg->cmsg_len)
	}
	if off == 0 {
		return nil
	}

	res := make([]byte, off)
	off = 0
	for _, buf := range oob {
		if buf == nil {
			continue
		}
		copy(res[off:], buf)
		off += unix.CmsgSpace(len(buf) - unix.CmsgLen(0)) // == CMSG_ALIGN(cmsg->cmsg_len)
	}
	return res
}
