package tunnel

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	ios "github.com/danielpaulus/go-ios/ios"
)

var (
	// ErrRemotePairingCompleted indicates that the device accepted a first-time
	// remote pairing request and the caller must open a fresh control channel.
	ErrRemotePairingCompleted      = errors.New("remote pairing completed; reconnect required")
	ErrRemotePairingRequired       = errors.New("remote pairing required; repair over USB before WiFi verify")
	ErrRemotePairingRejected       = errors.New("remote pairing rejected")
	ErrRemotePairingReset          = errors.New("remote pairing connection reset")
	ErrRemotePairingListenerFailed = errors.New("remote pairing TCP listener failed")
	ErrRemotePairingTLSFailed      = errors.New("remote pairing TLS-PSK failed")
	ErrRemotePairingCDTunnelFailed = errors.New("remote pairing CDTunnel failed")
)

// ManualPairWithAddr establishes a TCP userspace tunnel to an iOS 17.4+ device without mDNS.
//
// It connects directly to ip:port (the _remotepairing._tcp service, default 49152)
// using the RPPairing wire protocol - the same protocol as pymobiledevice3's
// RemotePairingTunnelService. This bypasses Bonjour/mDNS discovery, which is
// blocked on many enterprise networks. ip may be either IPv4 or IPv6.
func ManualPairWithAddr(
	ctx context.Context,
	ip string,
	port int,
	device ios.DeviceEntry,
	pm PairRecordManager,
) (Tunnel, error) {
	conn, ts, err := verifyPairWithAddrControlChannel(ctx, ip, port, pm)
	if err != nil {
		return Tunnel{}, err
	}

	info, err := ts.createTCPTunnelListener()
	if err != nil {
		conn.Close()
		return Tunnel{}, fmt.Errorf("ManualPairWithAddr: %w: %v", ErrRemotePairingListenerFailed, err)
	}

	return connectToUserspaceTCPTunnel(ctx, info, ts.encryptionKey, ip, device, 0)
}

func verifyPairWithAddrControlChannel(ctx context.Context, ip string, port int, pm PairRecordManager) (*net.TCPConn, *tunnelService, error) {
	conn, ts, err := newManualPairTunnelService(ctx, ip, port, pm)
	if err != nil {
		return nil, nil, err
	}

	if err := ts.VerifyPairDirect(); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("ManualPairWithAddr: pairing: %w", err)
	}

	return conn, ts, nil
}

func manualPairWithAddrControlChannel(ctx context.Context, ip string, port int, pm PairRecordManager) (*net.TCPConn, *tunnelService, error) {
	var resetErr error
	for attempt := 0; attempt < 3; attempt++ {
		conn, ts, err := newManualPairTunnelService(ctx, ip, port, pm)
		if err != nil {
			if resetErr != nil {
				return nil, nil, fmt.Errorf("ManualPairWithAddr: reconnect after pairing reset: %w: %v", ErrRemotePairingReset, resetErr)
			}
			return nil, nil, err
		}

		err = ts.ManualPairDirect()
		if err == nil {
			return conn, ts, nil
		}
		conn.Close()

		if isRemotePairingConnectionReset(err) {
			resetErr = err
			continue
		}
		if errors.Is(err, ErrRemotePairingCompleted) {
			continue
		}
		return nil, nil, fmt.Errorf("ManualPairWithAddr: pairing: %w", err)
	}

	if resetErr != nil {
		return nil, nil, fmt.Errorf("ManualPairWithAddr: pair verify after reset failed: %w: %v", ErrRemotePairingReset, resetErr)
	}
	return nil, nil, fmt.Errorf("ManualPairWithAddr: pairing after reconnect: %w", ErrRemotePairingCompleted)
}

func newManualPairTunnelService(ctx context.Context, ip string, port int, pm PairRecordManager) (*net.TCPConn, *tunnelService, error) {
	conn, err := dialManualPair(ctx, ip, port)
	if err != nil {
		return nil, nil, fmt.Errorf("ManualPairWithAddr: dial %s:%d: %w", ip, port, err)
	}

	ch := newRPPairingChannel(conn)
	return conn, &tunnelService{
		c:              conn,
		controlChannel: ch,
		pairRecords:    pm,
	}, nil
}

// ManualPairDirect follows pymobiledevice3's RemotePairing state machine for direct
// _remotepairing._tcp connections. A first-time pairing closes the control channel,
// so callers must reconnect and verify before creating a trusted TCP tunnel listener.
func (t *tunnelService) ManualPairDirect() error {
	if err := t.attemptPairVerifyHandshake(); err != nil {
		return err
	}

	if err := t.verifyPair(); err == nil {
		return nil
	}

	if err := t.setupManualPairingSession(); err != nil {
		if isRemotePairingConnectionReset(err) {
			return fmt.Errorf("%w: %v", ErrRemotePairingReset, err)
		}
		if strings.Contains(strings.ToLower(err.Error()), "pairing rejected") {
			return fmt.Errorf("%w: %v", ErrRemotePairingRejected, err)
		}
		return err
	}

	return ErrRemotePairingCompleted
}

// VerifyPairDirect validates that the current host identity is already trusted
// by the device over a direct _remotepairing._tcp connection. It intentionally
// does not start first-time pairing; use RepairRemotePairingOverUSB to rebuild
// RemotePairing trust from a USB connection.
func (t *tunnelService) VerifyPairDirect() error {
	if err := t.attemptPairVerifyHandshake(); err != nil {
		return err
	}

	if err := t.verifyPair(); err == nil {
		return nil
	} else if isRemotePairingConnectionReset(err) {
		return fmt.Errorf("%w: %v", ErrRemotePairingReset, err)
	} else if strings.Contains(strings.ToLower(err.Error()), "pairing rejected") {
		return fmt.Errorf("%w: %v", ErrRemotePairingRejected, err)
	} else {
		return fmt.Errorf("%w: %v", ErrRemotePairingRequired, err)
	}
}

func isRemotePairingConnectionReset(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "connection reset") ||
		strings.Contains(s, "forcibly closed") ||
		strings.Contains(s, "wsarecv") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "eof")
}

// rpPairingPacketMagic is the 9-byte magic prefix for every RemotePairing TCP frame.
const rpPairingPacketMagic = "RPPairing"

// rpPairingChannel implements controlChannelIO over a plain TCP connection using
// the RPPairing wire protocol (magic + uint16-BE length + JSON body).
// This is the protocol spoken by _remotepairing._tcp (port 49152) on iOS 17+ devices.
type rpPairingChannel struct {
	conn  net.Conn
	seqNr uint64
}

func newRPPairingChannel(conn net.Conn) *rpPairingChannel {
	return &rpPairingChannel{conn: conn}
}

// write sends a full ControlChannelMessageEnvelope over RPPairing framing.
// message is the inner "message" value (e.g. {"plain":...} or {"streamEncrypted":...}).
func (r *rpPairingChannel) write(message map[string]interface{}) error {
	envelope := map[string]interface{}{
		"message":        message,
		"originatedBy":   "host",
		"sequenceNumber": r.seqNr,
	}
	r.seqNr++

	body, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("rpPairingChannel.write: marshal: %w", err)
	}
	if len(body) > 0xFFFF {
		return fmt.Errorf("rpPairingChannel.write: payload too large (%d bytes)", len(body))
	}

	frame := make([]byte, len(rpPairingPacketMagic)+2+len(body))
	copy(frame, rpPairingPacketMagic)
	binary.BigEndian.PutUint16(frame[len(rpPairingPacketMagic):], uint16(len(body)))
	copy(frame[len(rpPairingPacketMagic)+2:], body)

	_, err = r.conn.Write(frame)
	return err
}

// read reads one RPPairing frame and returns the "message" field from the envelope.
func (r *rpPairingChannel) read() (map[string]interface{}, error) {
	magic := make([]byte, len(rpPairingPacketMagic))
	if _, err := io.ReadFull(r.conn, magic); err != nil {
		return nil, fmt.Errorf("rpPairingChannel.read: magic: %w", err)
	}
	if string(magic) != rpPairingPacketMagic {
		return nil, fmt.Errorf("rpPairingChannel.read: bad magic %x", magic)
	}

	sizeBuf := make([]byte, 2)
	if _, err := io.ReadFull(r.conn, sizeBuf); err != nil {
		return nil, fmt.Errorf("rpPairingChannel.read: size: %w", err)
	}
	size := binary.BigEndian.Uint16(sizeBuf)

	body := make([]byte, size)
	if _, err := io.ReadFull(r.conn, body); err != nil {
		return nil, fmt.Errorf("rpPairingChannel.read: body: %w", err)
	}

	var envelope map[string]interface{}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("rpPairingChannel.read: parse: %w", err)
	}

	return getChildMap(envelope, "message")
}

// writeRequest wraps req into {"plain":{"_0":{"request":{"_0":req}}}} and sends it.
func (r *rpPairingChannel) writeRequest(req map[string]interface{}) error {
	return r.write(map[string]interface{}{
		"plain": map[string]interface{}{
			"_0": map[string]interface{}{
				"request": map[string]interface{}{
					"_0": req,
				},
			},
		},
	})
}

// writeEvent encodes e and sends it as an event.
func (r *rpPairingChannel) writeEvent(e eventCodec) error {
	return r.write(map[string]interface{}{
		"plain": map[string]interface{}{
			"_0": map[string]interface{}{
				"event": map[string]interface{}{
					"_0": e.Encode(),
				},
			},
		},
	})
}

// readEvent reads one frame and decodes its event payload into e.
func (r *rpPairingChannel) readEvent(e eventCodec) error {
	m, err := r.read()
	if err != nil {
		return fmt.Errorf("readEvent: failed to read message: %w", err)
	}
	event, err := getChildMap(m, "plain", "_0", "event", "_0")
	if err != nil {
		return fmt.Errorf("readEvent: failed to get event payload: %w", err)
	}
	return e.Decode(event)
}

// dialManualPair opens a TCP connection to ip:port, using tcp4 for IPv4 addresses
// and tcp6 for IPv6 addresses. ctx controls the connection timeout.
func dialManualPair(ctx context.Context, ip string, port int) (*net.TCPConn, error) {
	parsed := net.ParseIP(ip)
	var network, addr string
	if parsed != nil && parsed.To4() != nil {
		network = "tcp4"
		addr = fmt.Sprintf("%s:%d", ip, port)
	} else {
		network = "tcp6"
		addr = fmt.Sprintf("[%s]:%d", ip, port)
	}

	c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	conn := c.(*net.TCPConn)
	if err := conn.SetKeepAlive(true); err != nil {
		conn.Close()
		return nil, fmt.Errorf("keepalive: %w", err)
	}
	if err := conn.SetKeepAlivePeriod(1 * time.Second); err != nil {
		conn.Close()
		return nil, fmt.Errorf("keepalive period: %w", err)
	}
	return conn, nil
}
