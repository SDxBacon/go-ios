package tunnel

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
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

func TestTunnelDoneReadWriteCloserNotifiesOnReadError(t *testing.T) {
	notified := make(chan struct{})
	rw := newTunnelDoneReadWriteCloser(errorReadWriteCloser{}, func() {
		close(notified)
	})

	if _, err := rw.Read(make([]byte, 1)); err == nil {
		t.Fatal("Read returned nil error")
	}

	select {
	case <-notified:
	case <-time.After(time.Second):
		t.Fatal("Read error did not notify")
	}
}

type errorReadWriteCloser struct{}

func (errorReadWriteCloser) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func (errorReadWriteCloser) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func (errorReadWriteCloser) Close() error {
	return nil
}
