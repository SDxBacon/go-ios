package tunnel

import (
	"context"
	"errors"
	"fmt"

	ios "github.com/danielpaulus/go-ios/ios"
	ioshttp "github.com/danielpaulus/go-ios/ios/http"
	"github.com/danielpaulus/go-ios/ios/xpc"
)

// CheckRemotePairingTrustOverUSB checks whether the current host identity is
// already trusted for RemotePairing using a USB-attached device. It uses the same
// reliable USB-RSD route as RepairRemotePairingOverUSB but never starts manual
// pairing and never prompts the user for RemotePairing consent.
func CheckRemotePairingTrustOverUSB(ctx context.Context, device ios.DeviceEntry, pm PairRecordManager) (string, bool, error) {
	udid, ts, closeFn, err := openRemotePairingTunnelServiceOverUSB(ctx, device, pm)
	if err != nil {
		return "", false, err
	}
	defer closeFn()

	trusted, err := ts.CheckPairing()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return udid, false, fmt.Errorf("CheckRemotePairingTrustOverUSB: check pairing timed out or cancelled: %w", ctxErr)
		}
		if errors.Is(err, ErrRemotePairingReset) || errors.Is(err, ErrRemotePairingRejected) {
			return udid, false, nil
		}
		return udid, false, fmt.Errorf("CheckRemotePairingTrustOverUSB: check pairing: %w", err)
	}
	return udid, trusted, nil
}

// RepairRemotePairingOverUSB rebuilds RemotePairing trust using a USB-attached
// device. It mirrors pymobiledevice3's reliable repair path:
//
//	USB lockdown -> CoreDeviceProxy TCP tunnel -> RSD -> untrusted tunnelservice
//	-> manual RemotePairing consent
//
// The same PairRecordManager used by ManualPairWithAddr must be supplied so the
// repaired host identity is the one later used for WiFi pair verification.
func RepairRemotePairingOverUSB(ctx context.Context, device ios.DeviceEntry, pm PairRecordManager) (string, error) {
	udid, ts, closeFn, err := openRemotePairingTunnelServiceOverUSB(ctx, device, pm)
	if err != nil {
		return "", err
	}
	defer closeFn()

	_ = pm.DeleteDeviceInfo(udid)

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = ts.Close()
		case <-done:
		}
	}()

	err = ts.RepairPairing()
	close(done)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", fmt.Errorf("RepairRemotePairingOverUSB: repair pairing timed out or cancelled: %w", ctxErr)
		}
		return "", fmt.Errorf("RepairRemotePairingOverUSB: repair pairing: %w", err)
	}

	return udid, nil
}

func openRemotePairingTunnelServiceOverUSB(ctx context.Context, device ios.DeviceEntry, pm PairRecordManager) (string, *tunnelService, func(), error) {
	if device.Properties.SerialNumber == "" {
		return "", nil, nil, fmt.Errorf("RepairRemotePairingOverUSB: missing USB device UDID")
	}

	conn, err := ios.ConnectToService(device, coreDeviceProxy)
	if err != nil {
		return "", nil, nil, fmt.Errorf("RepairRemotePairingOverUSB: connect CoreDeviceProxy over USB: %w", err)
	}

	usbTunnel, err := connectToUserspaceTunnelLockdown(ctx, device, conn, 0)
	if err != nil {
		_ = conn.Close()
		return "", nil, nil, fmt.Errorf("RepairRemotePairingOverUSB: start USB CoreDeviceProxy tunnel: %w", err)
	}
	usbTunnelDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = usbTunnel.Close()
		case <-usbTunnelDone:
		}
	}()

	rsdDevice := ios.DeviceEntry{
		UserspaceTUN:     true,
		UserspaceTUNHost: ios.HttpApiHost(),
		UserspaceTUNPort: usbTunnel.UserspaceTUNPort,
	}

	rsdSvc, err := ios.NewWithAddrPortDevice(usbTunnel.Address, usbTunnel.RsdPort, rsdDevice)
	if err != nil {
		close(usbTunnelDone)
		_ = usbTunnel.Close()
		return "", nil, nil, fmt.Errorf("RepairRemotePairingOverUSB: connect RSD over USB tunnel: %w", err)
	}
	provider, err := rsdSvc.Handshake()
	rsdSvc.Close()
	if err != nil {
		close(usbTunnelDone)
		_ = usbTunnel.Close()
		return "", nil, nil, fmt.Errorf("RepairRemotePairingOverUSB: RSD handshake over USB tunnel: %w", err)
	}
	if provider.Udid == "" {
		close(usbTunnelDone)
		_ = usbTunnel.Close()
		return "", nil, nil, fmt.Errorf("RepairRemotePairingOverUSB: RSD handshake returned empty UDID")
	}

	rsdDevice.Address = usbTunnel.Address
	rsdDevice.Rsd = provider
	rsdDevice.Properties.SerialNumber = provider.Udid

	xpcConn, err := connectRemoteXPCServiceTunnelIface(rsdDevice, untrustedTunnelServiceName)
	if err != nil {
		close(usbTunnelDone)
		_ = usbTunnel.Close()
		return "", nil, nil, fmt.Errorf("RepairRemotePairingOverUSB: connect untrusted tunnelservice over RSD: %w", err)
	}
	if _, err := waitForUntrustedTunnelServiceVersion(xpcConn); err != nil {
		xpcConn.Close()
		close(usbTunnelDone)
		_ = usbTunnel.Close()
		return "", nil, nil, fmt.Errorf("RepairRemotePairingOverUSB: read untrusted tunnelservice version: %w", err)
	}
	ts := newTunnelServiceWithXpc(xpcConn, xpcConn, pm)

	closeFn := func() {
		_ = ts.Close()
		close(usbTunnelDone)
		_ = usbTunnel.Close()
	}
	return provider.Udid, ts, closeFn, nil
}

func waitForUntrustedTunnelServiceVersion(xpcConn *xpc.Connection) (interface{}, error) {
	for {
		msg, err := xpcConn.ReceiveOnClientServerStream()
		if err != nil {
			return nil, err
		}
		if version, ok := msg["ServiceVersion"]; ok {
			return version, nil
		}
	}
}

func connectRemoteXPCServiceTunnelIface(device ios.DeviceEntry, serviceName string) (*xpc.Connection, error) {
	if !device.SupportsRsd() {
		return nil, fmt.Errorf("connectRemoteXPCServiceTunnelIface: cannot connect to %s, missing RSD provider", serviceName)
	}
	port := device.Rsd.GetPort(serviceName)
	if port == 0 {
		return nil, fmt.Errorf("connectRemoteXPCServiceTunnelIface: service %s not found in RSD", serviceName)
	}

	conn, err := ios.ConnectTUNDevice(device.Address, port, device)
	if err != nil {
		return nil, fmt.Errorf("connectRemoteXPCServiceTunnelIface: failed to dial: %w", err)
	}

	h, err := ioshttp.NewHttpConnection(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("connectRemoteXPCServiceTunnelIface: failed to connect to http2: %w", err)
	}
	return createRemoteXPCConnection(h)
}

func createRemoteXPCConnection(h *ioshttp.HttpConnection) (*xpc.Connection, error) {
	clientServer := ioshttp.NewStreamReadWriter(h, ioshttp.ClientServer)
	serverClient := ioshttp.NewStreamReadWriter(h, ioshttp.ServerClient)

	if err := xpc.EncodeMessage(clientServer, xpc.Message{
		Flags: xpc.AlwaysSetFlag,
		Body:  map[string]interface{}{},
		Id:    0,
	}); err != nil {
		h.Close()
		return nil, fmt.Errorf("createRemoteXPCConnection: failed to encode root message: %w", err)
	}
	if err := xpc.EncodeMessage(clientServer, xpc.Message{
		Flags: 0x201,
		Body:  nil,
		Id:    0,
	}); err != nil {
		h.Close()
		return nil, fmt.Errorf("createRemoteXPCConnection: failed to encode root terminator: %w", err)
	}
	if err := xpc.EncodeMessage(serverClient, xpc.Message{
		Flags: xpc.InitHandshakeFlag | xpc.AlwaysSetFlag,
		Body:  nil,
		Id:    0,
	}); err != nil {
		h.Close()
		return nil, fmt.Errorf("createRemoteXPCConnection: failed to encode reply channel init: %w", err)
	}

	return xpc.New(clientServer, serverClient, h)
}
