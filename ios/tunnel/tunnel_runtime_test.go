package tunnel

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/danielpaulus/go-ios/ios"
)

func TestTunnelDoneClosesOnClose(t *testing.T) {
	_, runtime := newTunnelRuntime(context.Background(), nil)
	tun := Tunnel{closer: runtime.close, done: runtime.done}

	select {
	case <-tun.Done():
		t.Fatal("Done closed before Close")
	default:
	}

	if err := tun.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	select {
	case <-tun.Done():
	case <-time.After(time.Second):
		t.Fatal("Done did not close after Close")
	}
}

func TestTunnelRuntimeCloseIsIdempotent(t *testing.T) {
	calls := 0
	_, runtime := newTunnelRuntime(context.Background(), func() error {
		calls++
		return nil
	})

	if err := runtime.close(); err != nil {
		t.Fatalf("first close returned error: %v", err)
	}
	if err := runtime.close(); err != nil {
		t.Fatalf("second close returned error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("closeFn calls = %d, want 1", calls)
	}
}

func TestZeroValueTunnelCloseAndDoneAreSafe(t *testing.T) {
	var tun Tunnel
	if err := tun.Close(); err != nil {
		t.Fatalf("zero-value Close returned error: %v", err)
	}

	select {
	case <-tun.Done():
	default:
		t.Fatal("zero-value Done returned an open channel")
	}
}

func TestTunnelRuntimeRunForwardClosesDone(t *testing.T) {
	_, runtime := newTunnelRuntime(context.Background(), nil)
	runtime.runForward(context.Background(), "test forward", iosTestDevice(), func() error {
		return io.ErrUnexpectedEOF
	})

	select {
	case <-runtime.done:
	case <-time.After(time.Second):
		t.Fatal("runtime Done did not close after forward error")
	}
}

func TestTunnelRuntimeCloseReturnsStoredError(t *testing.T) {
	closeErr := errors.New("close failed")
	_, runtime := newTunnelRuntime(context.Background(), func() error {
		return closeErr
	})

	if err := runtime.close(); !errors.Is(err, closeErr) {
		t.Fatalf("first close error = %v, want %v", err, closeErr)
	}
	if err := runtime.close(); !errors.Is(err, closeErr) {
		t.Fatalf("second close error = %v, want %v", err, closeErr)
	}
}

func iosTestDevice() ios.DeviceEntry {
	return ios.DeviceEntry{}
}
