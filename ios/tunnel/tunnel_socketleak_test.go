package tunnel

import (
	"context"
	"testing"
	"time"

	"github.com/danielpaulus/go-ios/ios"
)

type stubDeviceLister struct{ list ios.DeviceList }

func (s stubDeviceLister) ListDevices() (ios.DeviceList, error) { return s.list, nil }

func devEntry(udid, connType string) ios.DeviceEntry {
	return ios.DeviceEntry{Properties: ios.DeviceProperties{SerialNumber: udid, ConnectionType: connType}}
}

func leakTestManager(entries ...ios.DeviceEntry) *TunnelManager {
	return &TunnelManager{
		dl:                 stubDeviceLister{list: ios.DeviceList{DeviceList: entries}},
		tunnels:            map[string]Tunnel{},
		failedDevices:      map[string]failedDevice{},
		startTunnelTimeout: time.Second,
	}
}

func TestFailedDeviceBackoff(t *testing.T) {
	cases := []struct {
		failCount int
		want      time.Duration
	}{
		{1, 30 * time.Second},
		{2, 60 * time.Second},
		{3, 120 * time.Second},
		{4, 240 * time.Second},
		{5, 300 * time.Second},
		{10, 300 * time.Second},
	}
	for _, c := range cases {
		if got := failedDeviceBackoff(c.failCount); got != c.want {
			t.Errorf("failedDeviceBackoff(%d) = %v, want %v", c.failCount, got, c.want)
		}
	}
}

func TestShouldSkipDevice(t *testing.T) {
	now := time.Now()
	failed := map[string]failedDevice{
		"recent": {lastAttempt: now.Add(-10 * time.Second), failCount: 1},
		"stale":  {lastAttempt: now.Add(-31 * time.Second), failCount: 1},
	}
	cases := []struct {
		name, udid, conn string
		want             bool
	}{
		{"network always skipped", "net", "Network", true},
		{"fresh usb attempted", "fresh", "USB", false},
		{"recent failure backed off", "recent", "USB", true},
		{"stale failure retried", "stale", "USB", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := shouldSkipDevice(devEntry(c.udid, c.conn), failed, now); got != c.want {
				t.Fatalf("shouldSkipDevice = %v, want %v", got, c.want)
			}
		})
	}
}

func TestUpdateTunnelsSkipsNetworkDevices(t *testing.T) {
	tm := leakTestManager(devEntry("net-1", "Network"))
	if err := tm.UpdateTunnels(context.Background()); err != nil {
		t.Fatalf("UpdateTunnels: %v", err)
	}
	if len(tm.failedDevices) != 0 {
		t.Fatalf("network device must not be attempted; failedDevices=%v", tm.failedDevices)
	}
	if len(tm.tunnels) != 0 {
		t.Fatalf("no tunnel expected for network device; tunnels=%v", tm.tunnels)
	}
}

func TestUpdateTunnelsRespectsBackoff(t *testing.T) {
	tm := leakTestManager(devEntry("usb-1", "USB"))
	seeded := time.Now()
	tm.failedDevices["usb-1"] = failedDevice{lastAttempt: seeded, failCount: 5}
	if err := tm.UpdateTunnels(context.Background()); err != nil {
		t.Fatalf("UpdateTunnels: %v", err)
	}
	got, ok := tm.failedDevices["usb-1"]
	if !ok {
		t.Fatal("usb-1 should remain in failedDevices")
	}
	if !got.lastAttempt.Equal(seeded) || got.failCount != 5 {
		t.Fatalf("backed-off device must not be retried; entry changed: %+v", got)
	}
}

func TestUpdateTunnelsPrunesDisconnectedFailedDevices(t *testing.T) {
	tm := leakTestManager(devEntry("net-1", "Network"))
	tm.failedDevices["gone"] = failedDevice{lastAttempt: time.Now(), failCount: 2}
	if err := tm.UpdateTunnels(context.Background()); err != nil {
		t.Fatalf("UpdateTunnels: %v", err)
	}
	if _, ok := tm.failedDevices["gone"]; ok {
		t.Fatal("disconnected device should be pruned from failedDevices")
	}
}

func TestUpdateTunnelsRecordsFailure(t *testing.T) {
	tm := leakTestManager(devEntry("usb-1", "USB"))
	if err := tm.UpdateTunnels(context.Background()); err != nil {
		t.Fatalf("UpdateTunnels: %v", err)
	}
	got, ok := tm.failedDevices["usb-1"]
	if !ok || got.failCount != 1 {
		t.Fatalf("failed USB device should be recorded with failCount=1, got ok=%v entry=%+v", ok, got)
	}
}
