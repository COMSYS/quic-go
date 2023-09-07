package handshake

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"sync"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

var (
	retryAEAD27  cipher.AEAD // used for QUIC draft-27
	retryAEAD29  cipher.AEAD // used for QUIC draft versions up to 34
	retryAEAD    cipher.AEAD // used for QUIC draft-34
)

func init() {
	retryAEAD27 = initAEAD([16]byte{0x4d, 0x32, 0xec, 0xdb, 0x2a, 0x21, 0x33, 0xc8, 0x41, 0xe4, 0x04, 0x3d, 0xf2, 0x7d, 0x44, 0x30})
	retryAEAD29 = initAEAD([16]byte{0xcc, 0xce, 0x18, 0x7e, 0xd0, 0x9a, 0x09, 0xd0, 0x57, 0x28, 0x15, 0x5a, 0x6c, 0xb9, 0x6b, 0xe1})
	retryAEAD = initAEAD([16]byte{0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e})
}

func initAEAD(key [16]byte) cipher.AEAD {
	aes, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}
	return aead
}

var (
	retryBuf      bytes.Buffer
	retryMutex    sync.Mutex
	retryNonce27  = [12]byte{0x4d, 0x16, 0x11, 0xd0, 0x55, 0x13, 0xa5, 0x52, 0xc5, 0x87, 0xd5, 0x75}
	retryNonce29  = [12]byte{0xe5, 0x49, 0x30, 0xf9, 0x7f, 0x21, 0x36, 0xf0, 0x53, 0x0a, 0x8c, 0x1c}
	retryNonce    = [12]byte{0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb}
)

// GetRetryIntegrityTag calculates the integrity tag on a Retry packet
func GetRetryIntegrityTag(retry []byte, origDestConnID protocol.ConnectionID, version protocol.VersionNumber) *[16]byte {
	retryMutex.Lock()
	retryBuf.WriteByte(uint8(origDestConnID.Len()))
	retryBuf.Write(origDestConnID.Bytes())
	retryBuf.Write(retry)

	var tag [16]byte
	var sealed []byte
	if version == protocol.VersionDraft34 || version == protocol.Version1 {
		sealed = retryAEAD.Seal(tag[:0], retryNonce[:], nil, retryBuf.Bytes())
	} else if version == protocol.VersionDraft27 {
		sealed = retryAEAD27.Seal(tag[:0], retryNonce27[:], nil, retryBuf.Bytes())
	} else {
		sealed = retryAEAD29.Seal(tag[:0], retryNonce29[:], nil, retryBuf.Bytes())
	}
	if len(sealed) != 16 {
		panic(fmt.Sprintf("unexpected Retry integrity tag length: %d", len(sealed)))
	}
	retryBuf.Reset()
	retryMutex.Unlock()
	return &tag
}
