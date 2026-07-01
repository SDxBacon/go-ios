package tunnel

import (
	"errors"
	"io"
	"strings"
	"testing"
)

type fakeControlChannel struct {
	reads  []map[string]interface{}
	events []string
}

func (f *fakeControlChannel) writeRequest(_ map[string]interface{}) error { return nil }
func (f *fakeControlChannel) writeEvent(e eventCodec) error {
	if p, ok := e.(*pairingData); ok {
		f.events = append(f.events, p.kind)
	}
	return nil
}
func (f *fakeControlChannel) write(_ map[string]interface{}) error { return nil }

func (f *fakeControlChannel) read() (map[string]interface{}, error) {
	if len(f.reads) == 0 {
		return nil, io.EOF
	}
	m := f.reads[0]
	f.reads = f.reads[1:]
	return m, nil
}

func (f *fakeControlChannel) readEvent(e eventCodec) error {
	m, err := f.read()
	if err != nil {
		return err
	}
	event, err := getChildMap(m, "plain", "_0", "event", "_0")
	if err != nil {
		return err
	}
	return e.Decode(event)
}

func TestSetupManualPairingMapsUserRejected(t *testing.T) {
	ts := &tunnelService{controlChannel: &fakeControlChannel{reads: []map[string]interface{}{
		plainEvent(map[string]interface{}{
			"pairingRejectedWithError": map[string]interface{}{
				"wrappedError": map[string]interface{}{
					"userInfo": map[string]interface{}{
						"NSLocalizedDescription": "User denied pairing",
					},
				},
			},
		}),
	}}}

	err := ts.setupManualPairing()
	if err == nil || !strings.Contains(err.Error(), "User denied pairing") {
		t.Fatalf("expected rejected pairing error, got %v", err)
	}
}

func TestSetupManualPairingKeepsInlinePairingData(t *testing.T) {
	publicKey := []byte{1, 2, 3}
	salt := []byte{4, 5, 6}
	tlv := newTlvBuffer()
	tlv.writeData(typePublicKey, publicKey)
	tlv.writeData(typeSalt, salt)

	ts := &tunnelService{controlChannel: &fakeControlChannel{reads: []map[string]interface{}{
		plainEvent((&pairingData{data: tlv.bytes(), kind: "setupManualPairing"}).Encode()),
	}}}

	if err := ts.setupManualPairing(); err != nil {
		t.Fatalf("setupManualPairing returned error: %v", err)
	}
	gotPublicKey, gotSalt, err := ts.readDeviceKey()
	if err != nil {
		t.Fatalf("readDeviceKey returned error: %v", err)
	}
	if string(gotPublicKey) != string(publicKey) || string(gotSalt) != string(salt) {
		t.Fatalf("unexpected pairing data: public=%v salt=%v", gotPublicKey, gotSalt)
	}
}

func TestRemotePairingConnectionResetDetection(t *testing.T) {
	if !isRemotePairingConnectionReset(errors.New("wsarecv: An existing connection was forcibly closed by the remote host")) {
		t.Fatal("expected Windows reset to be detected")
	}
	if !isRemotePairingConnectionReset(io.EOF) {
		t.Fatal("expected EOF to be detected")
	}
	if isRemotePairingConnectionReset(errors.New("pairing rejected")) {
		t.Fatal("rejected pairing should not be classified as reset")
	}
}

func TestCheckPairingDoesNotStartManualPairing(t *testing.T) {
	ch := &fakeControlChannel{reads: []map[string]interface{}{
		{},
		{},
	}}
	ts := &tunnelService{controlChannel: ch}

	trusted, err := ts.CheckPairing()
	if err != nil {
		t.Fatalf("CheckPairing returned error: %v", err)
	}
	if trusted {
		t.Fatal("expected untrusted result")
	}
	for _, kind := range ch.events {
		if kind == "setupManualPairing" {
			t.Fatalf("CheckPairing must not start manual pairing, events=%v", ch.events)
		}
	}
}

func TestCheckPairingMapsConnectionReset(t *testing.T) {
	ts := &tunnelService{controlChannel: &fakeControlChannel{reads: []map[string]interface{}{
		{},
	}}}

	trusted, err := ts.CheckPairing()
	if trusted {
		t.Fatal("expected untrusted result")
	}
	if !errors.Is(err, ErrRemotePairingReset) {
		t.Fatalf("expected ErrRemotePairingReset, got %v", err)
	}
}

func plainEvent(event map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"plain": map[string]interface{}{
			"_0": map[string]interface{}{
				"event": map[string]interface{}{
					"_0": event,
				},
			},
		},
	}
}
