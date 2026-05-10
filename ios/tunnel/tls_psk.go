package tunnel

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
)

const (
	tlsRecordChangeCipherSpec = 20
	tlsRecordAlert            = 21
	tlsRecordHandshake        = 22
	tlsRecordApplicationData  = 23

	tlsHandshakeClientHello       = 1
	tlsHandshakeServerHello       = 2
	tlsHandshakeServerKeyExchange = 12
	tlsHandshakeServerHelloDone   = 14
	tlsHandshakeClientKeyExchange = 16
	tlsHandshakeFinished          = 20

	tlsCipherPSKWithAES128GCM       = 0x00a8
	tlsMaxPlaintext                 = 16 * 1024
	tlsFinishedVerifyDataLength     = 12
	tlsAES128GCMKeyLength           = 16
	tlsAESGCMFixedNonceLength       = 4
	tlsAESGCMExplicitNonceLength    = 8
	tlsAESGCMTagLength              = 16
	tlsAES128GCMKeyBlockLength      = 2*tlsAES128GCMKeyLength + 2*tlsAESGCMFixedNonceLength
	tlsPSKIdentityLength            = 0
	tlsClientHandshakeRecordVersion = 0x0301
	tls12Version                    = 0x0303
)

var tls12VersionBytes = []byte{0x03, 0x03}

type tlsPSKConn struct {
	conn net.Conn

	clientAEAD cipher.AEAD
	serverAEAD cipher.AEAD
	clientIV   []byte
	serverIV   []byte

	readSeq  uint64
	writeSeq uint64

	handshake bytes.Buffer
	hsBuf     []byte
	readBuf   []byte

	readCipherActive  bool
	writeCipherActive bool
	readMu            sync.Mutex
	writeMu           sync.Mutex
}

func newTLSPSKClient(conn net.Conn, psk []byte) (io.ReadWriteCloser, error) {
	c := &tlsPSKConn{conn: conn}
	if err := c.handshakeClient(psk); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *tlsPSKConn) handshakeClient(psk []byte) error {
	clientRandom := make([]byte, 32)
	if _, err := rand.Read(clientRandom); err != nil {
		return fmt.Errorf("client random: %w", err)
	}

	clientHello := buildTLSClientHello(clientRandom)
	if err := c.writeHandshakePlain(tlsHandshakeClientHello, clientHello, tlsClientHandshakeRecordVersion); err != nil {
		return fmt.Errorf("client hello: %w", err)
	}

	msgType, serverHello, err := c.readHandshake()
	if err != nil {
		return fmt.Errorf("server hello: %w", err)
	}
	if msgType != tlsHandshakeServerHello {
		return fmt.Errorf("expected ServerHello, got handshake type %d", msgType)
	}
	serverRandom, err := parseTLSServerHello(serverHello)
	if err != nil {
		return err
	}

	msgType, _, err = c.readHandshake()
	if err != nil {
		return fmt.Errorf("server key exchange/server hello done: %w", err)
	}
	if msgType == tlsHandshakeServerKeyExchange {
		msgType, _, err = c.readHandshake()
		if err != nil {
			return fmt.Errorf("server hello done: %w", err)
		}
	}
	if msgType != tlsHandshakeServerHelloDone {
		return fmt.Errorf("expected ServerHelloDone, got handshake type %d", msgType)
	}

	clientKeyExchange := make([]byte, 2+tlsPSKIdentityLength)
	if err := c.writeHandshakePlain(tlsHandshakeClientKeyExchange, clientKeyExchange, tls12Version); err != nil {
		return fmt.Errorf("client key exchange: %w", err)
	}

	masterSecret := tls12PRF(tlsPSKPremasterSecret(psk), "master secret", concatBytes(clientRandom, serverRandom), 48)
	keyBlock := tls12PRF(masterSecret, "key expansion", concatBytes(serverRandom, clientRandom), tlsAES128GCMKeyBlockLength)
	if err := c.initAES128GCMKeys(keyBlock); err != nil {
		return err
	}

	if err := c.writePlainRecord(tlsRecordChangeCipherSpec, tls12Version, []byte{1}); err != nil {
		return fmt.Errorf("client change cipher spec: %w", err)
	}
	c.writeCipherActive = true

	clientVerifyData := tls12PRF(masterSecret, "client finished", tlsHandshakeHash(c.handshake.Bytes()), tlsFinishedVerifyDataLength)
	clientFinished := buildTLSHandshake(tlsHandshakeFinished, clientVerifyData)
	c.handshake.Write(clientFinished)
	if err := c.writeEncryptedRecord(tlsRecordHandshake, clientFinished); err != nil {
		return fmt.Errorf("client finished: %w", err)
	}

	if err := c.readServerChangeCipherSpec(); err != nil {
		return err
	}
	c.readCipherActive = true

	msgType, serverFinished, err := c.readHandshake()
	if err != nil {
		return fmt.Errorf("server finished: %w", err)
	}
	if msgType != tlsHandshakeFinished {
		return fmt.Errorf("expected Finished, got handshake type %d", msgType)
	}
	expected := tls12PRF(masterSecret, "server finished", tlsHandshakeHash(c.handshake.Bytes()), tlsFinishedVerifyDataLength)
	if !hmac.Equal(serverFinished, expected) {
		return fmt.Errorf("server finished verify data mismatch")
	}
	return nil
}

func buildTLSClientHello(clientRandom []byte) []byte {
	var body bytes.Buffer
	body.Write(tls12VersionBytes)
	body.Write(clientRandom)
	body.WriteByte(0)
	_ = binary.Write(&body, binary.BigEndian, uint16(2))
	_ = binary.Write(&body, binary.BigEndian, uint16(tlsCipherPSKWithAES128GCM))
	body.WriteByte(1)
	body.WriteByte(0)
	_ = binary.Write(&body, binary.BigEndian, uint16(0))
	return body.Bytes()
}

func parseTLSServerHello(body []byte) ([]byte, error) {
	if len(body) < 38 {
		return nil, fmt.Errorf("server hello too short: %d", len(body))
	}
	version := binary.BigEndian.Uint16(body[:2])
	if version != tls12Version {
		return nil, fmt.Errorf("server selected unsupported TLS version 0x%04x", version)
	}
	serverRandom := append([]byte(nil), body[2:34]...)
	sessionIDLen := int(body[34])
	offset := 35 + sessionIDLen
	if len(body) < offset+3 {
		return nil, fmt.Errorf("server hello truncated")
	}
	cipherSuite := binary.BigEndian.Uint16(body[offset : offset+2])
	if cipherSuite != tlsCipherPSKWithAES128GCM {
		return nil, fmt.Errorf("server selected unsupported cipher suite 0x%04x", cipherSuite)
	}
	if body[offset+2] != 0 {
		return nil, fmt.Errorf("server selected unsupported compression method %d", body[offset+2])
	}
	return serverRandom, nil
}

func (c *tlsPSKConn) initAES128GCMKeys(keyBlock []byte) error {
	if len(keyBlock) != tlsAES128GCMKeyBlockLength {
		return fmt.Errorf("unexpected key block length %d", len(keyBlock))
	}
	clientKey := keyBlock[:tlsAES128GCMKeyLength]
	serverKey := keyBlock[tlsAES128GCMKeyLength : 2*tlsAES128GCMKeyLength]
	c.clientIV = append([]byte(nil), keyBlock[2*tlsAES128GCMKeyLength:2*tlsAES128GCMKeyLength+tlsAESGCMFixedNonceLength]...)
	c.serverIV = append([]byte(nil), keyBlock[2*tlsAES128GCMKeyLength+tlsAESGCMFixedNonceLength:]...)

	clientBlock, err := aes.NewCipher(clientKey)
	if err != nil {
		return err
	}
	c.clientAEAD, err = cipher.NewGCMWithNonceSize(clientBlock, tlsAESGCMFixedNonceLength+tlsAESGCMExplicitNonceLength)
	if err != nil {
		return err
	}
	serverBlock, err := aes.NewCipher(serverKey)
	if err != nil {
		return err
	}
	c.serverAEAD, err = cipher.NewGCMWithNonceSize(serverBlock, tlsAESGCMFixedNonceLength+tlsAESGCMExplicitNonceLength)
	return err
}

func tlsPSKPremasterSecret(psk []byte) []byte {
	premaster := make([]byte, 2+len(psk)+2+len(psk))
	binary.BigEndian.PutUint16(premaster[:2], uint16(len(psk)))
	offset := 2 + len(psk)
	binary.BigEndian.PutUint16(premaster[offset:offset+2], uint16(len(psk)))
	copy(premaster[offset+2:], psk)
	return premaster
}

func tls12PRF(secret []byte, label string, seed []byte, length int) []byte {
	return pHash(secret, append([]byte(label), seed...), length)
}

func tlsHandshakeHash(messages []byte) []byte {
	sum := sha256.Sum256(messages)
	return sum[:]
}

func concatBytes(a, b []byte) []byte {
	out := make([]byte, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	return out
}

func pHash(secret, seed []byte, length int) []byte {
	out := make([]byte, 0, length)
	a := seed
	for len(out) < length {
		mac := hmac.New(sha256.New, secret)
		mac.Write(a)
		a = mac.Sum(nil)

		mac = hmac.New(sha256.New, secret)
		mac.Write(a)
		mac.Write(seed)
		out = append(out, mac.Sum(nil)...)
	}
	return out[:length]
}

func buildTLSHandshake(msgType byte, body []byte) []byte {
	msg := make([]byte, 4+len(body))
	msg[0] = msgType
	msg[1] = byte(len(body) >> 16)
	msg[2] = byte(len(body) >> 8)
	msg[3] = byte(len(body))
	copy(msg[4:], body)
	return msg
}

func (c *tlsPSKConn) writeHandshakePlain(msgType byte, body []byte, recordVersion uint16) error {
	msg := buildTLSHandshake(msgType, body)
	c.handshake.Write(msg)
	return c.writePlainRecord(tlsRecordHandshake, recordVersion, msg)
}

func (c *tlsPSKConn) readHandshake() (byte, []byte, error) {
	for {
		if len(c.hsBuf) >= 4 {
			bodyLen := int(c.hsBuf[1])<<16 | int(c.hsBuf[2])<<8 | int(c.hsBuf[3])
			if len(c.hsBuf) >= 4+bodyLen {
				msg := c.hsBuf[:4+bodyLen]
				c.hsBuf = c.hsBuf[4+bodyLen:]
				if msg[0] != tlsHandshakeFinished || !c.readCipherActive {
					c.handshake.Write(msg)
				}
				return msg[0], msg[4:], nil
			}
		}

		recordType, payload, err := c.readRecord()
		if err != nil {
			return 0, nil, err
		}
		switch recordType {
		case tlsRecordHandshake:
			c.hsBuf = append(c.hsBuf, payload...)
		case tlsRecordAlert:
			return 0, nil, parseTLSAlert(payload)
		default:
			return 0, nil, fmt.Errorf("expected handshake record, got record type %d", recordType)
		}
	}
}

func (c *tlsPSKConn) readServerChangeCipherSpec() error {
	recordType, payload, err := c.readRecord()
	if err != nil {
		return fmt.Errorf("server change cipher spec: %w", err)
	}
	if recordType == tlsRecordAlert {
		return parseTLSAlert(payload)
	}
	if recordType != tlsRecordChangeCipherSpec || len(payload) != 1 || payload[0] != 1 {
		return fmt.Errorf("expected ChangeCipherSpec, got record type %d payload %x", recordType, payload)
	}
	return nil
}

func (c *tlsPSKConn) writePlainRecord(recordType byte, version uint16, payload []byte) error {
	header := make([]byte, 5)
	header[0] = recordType
	binary.BigEndian.PutUint16(header[1:3], version)
	binary.BigEndian.PutUint16(header[3:5], uint16(len(payload)))
	if _, err := c.conn.Write(header); err != nil {
		return err
	}
	_, err := c.conn.Write(payload)
	return err
}

func (c *tlsPSKConn) writeEncryptedRecord(recordType byte, payload []byte) error {
	seq := c.writeSeq
	explicit := make([]byte, tlsAESGCMExplicitNonceLength)
	binary.BigEndian.PutUint64(explicit, seq)
	nonce := append(append([]byte(nil), c.clientIV...), explicit...)
	aad := tlsRecordAAD(seq, recordType, len(payload))
	ciphertext := c.clientAEAD.Seal(nil, nonce, payload, aad)
	fragment := append(explicit, ciphertext...)
	if err := c.writePlainRecord(recordType, tls12Version, fragment); err != nil {
		return err
	}
	c.writeSeq++
	return nil
}

func (c *tlsPSKConn) readRecord() (byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(c.conn, header); err != nil {
		return 0, nil, err
	}
	recordType := header[0]
	recordLen := int(binary.BigEndian.Uint16(header[3:5]))
	fragment := make([]byte, recordLen)
	if _, err := io.ReadFull(c.conn, fragment); err != nil {
		return 0, nil, err
	}
	if !c.readCipherActive {
		return recordType, fragment, nil
	}
	if len(fragment) < tlsAESGCMExplicitNonceLength+tlsAESGCMTagLength {
		return 0, nil, fmt.Errorf("encrypted TLS record too short: %d", len(fragment))
	}
	explicit := fragment[:tlsAESGCMExplicitNonceLength]
	ciphertext := fragment[tlsAESGCMExplicitNonceLength:]
	plainLen := len(ciphertext) - tlsAESGCMTagLength
	nonce := append(append([]byte(nil), c.serverIV...), explicit...)
	aad := tlsRecordAAD(c.readSeq, recordType, plainLen)
	plaintext, err := c.serverAEAD.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return 0, nil, fmt.Errorf("decrypt TLS record: %w", err)
	}
	c.readSeq++
	return recordType, plaintext, nil
}

func tlsRecordAAD(seq uint64, recordType byte, plainLen int) []byte {
	aad := make([]byte, 13)
	binary.BigEndian.PutUint64(aad[:8], seq)
	aad[8] = recordType
	copy(aad[9:11], tls12VersionBytes)
	binary.BigEndian.PutUint16(aad[11:13], uint16(plainLen))
	return aad
}

func parseTLSAlert(payload []byte) error {
	if len(payload) < 2 {
		return fmt.Errorf("TLS alert: %x", payload)
	}
	return fmt.Errorf("TLS alert level=%d description=%d", payload[0], payload[1])
}

func (c *tlsPSKConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for len(c.readBuf) == 0 {
		recordType, payload, err := c.readRecord()
		if err != nil {
			return 0, err
		}
		switch recordType {
		case tlsRecordApplicationData:
			c.readBuf = append(c.readBuf, payload...)
		case tlsRecordAlert:
			return 0, parseTLSAlert(payload)
		default:
			return 0, fmt.Errorf("unexpected TLS record type %d while reading application data", recordType)
		}
	}

	n := copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *tlsPSKConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	written := 0
	for len(b) > 0 {
		n := len(b)
		if n > tlsMaxPlaintext {
			n = tlsMaxPlaintext
		}
		if err := c.writeEncryptedRecord(tlsRecordApplicationData, b[:n]); err != nil {
			return written, err
		}
		written += n
		b = b[n:]
	}
	return written, nil
}

func (c *tlsPSKConn) Close() error {
	return c.conn.Close()
}
