package handshake

import (
	"crypto"
	"crypto/tls"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qtls"
	"github.com/lucas-clemente/quic-go/logging"
)

var (
	quicSaltDraft27 = []byte{0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7, 0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02}
	quicSaltDraft29 = []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99}
	quicSaltDraft34 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
)

func getSalt(v protocol.VersionNumber) []byte {
	if v == protocol.VersionDraft27 {
		return quicSaltDraft27
	}
	if v == protocol.VersionDraft34 || v == protocol.Version1 {
		return quicSaltDraft34
	}
	return quicSaltDraft29
}

var initialSuite = &qtls.CipherSuiteTLS13{
	ID:     tls.TLS_AES_128_GCM_SHA256,
	KeyLen: 16,
	AEAD:   qtls.AEADAESGCMTLS13,
	Hash:   crypto.SHA256,
}

// NewInitialAEAD creates a new AEAD for Initial encryption / decryption.
func NewInitialAEAD(connID protocol.ConnectionID, pers protocol.Perspective, v protocol.VersionNumber, tracer logging.ConnectionTracer) (LongHeaderSealer, LongHeaderOpener) {
	clientSecret, serverSecret := computeSecrets(connID, v)
	var mySecret, otherSecret []byte
	if pers == protocol.PerspectiveClient {
		mySecret = clientSecret
		otherSecret = serverSecret
	} else {
		mySecret = serverSecret
		otherSecret = clientSecret
	}
	myKey, myIV := computeInitialKeyAndIV(mySecret)
	otherKey, otherIV := computeInitialKeyAndIV(otherSecret)

	encrypter := qtls.AEADAESGCMTLS13(myKey, myIV)
	decrypter := qtls.AEADAESGCMTLS13(otherKey, otherIV)

	if tracer != nil {
		tracer.UpdatedKeyFromTLS(protocol.EncryptionInitial, protocol.PerspectiveClient, clientSecret)
		tracer.UpdatedKeyFromTLS(protocol.EncryptionInitial, protocol.PerspectiveServer, serverSecret)
	}
	return newLongHeaderSealer(encrypter, newHeaderProtector(initialSuite, mySecret, true)),
		newLongHeaderOpener(decrypter, newAESHeaderProtector(initialSuite, otherSecret, true))
}

func computeSecrets(connID protocol.ConnectionID, v protocol.VersionNumber) (clientSecret, serverSecret []byte) {
	initialSecret := qtls.HkdfExtract(crypto.SHA256, connID, getSalt(v))
	clientSecret = hkdfExpandLabel(crypto.SHA256, initialSecret, []byte{}, "client in", crypto.SHA256.Size())
	serverSecret = hkdfExpandLabel(crypto.SHA256, initialSecret, []byte{}, "server in", crypto.SHA256.Size())
	return
}

func computeInitialKeyAndIV(secret []byte) (key, iv []byte) {
	key = hkdfExpandLabel(crypto.SHA256, secret, []byte{}, "quic key", 16)
	iv = hkdfExpandLabel(crypto.SHA256, secret, []byte{}, "quic iv", 12)
	return
}
