package ios

import "fmt"

const (
	RemoteLockdownTrustedService   = "com.apple.mobile.lockdown.remote.trusted"
	RemoteLockdownUntrustedService = "com.apple.mobile.lockdown.remote.untrusted"
)

// ConnectRemoteLockdown opens the RSD remote lockdown service on iOS 17+ devices.
// Remote lockdown connections are already authorized by RemotePairing and do not
// use usbmux StartSession.
func ConnectRemoteLockdown(device DeviceEntry) (*LockDownConnection, error) {
	if !device.SupportsRsd() {
		return nil, fmt.Errorf("ConnectRemoteLockdown: device does not support RSD")
	}

	conn, err := ConnectToShimService(device, RemoteLockdownTrustedService)
	if err == nil {
		return NewLockDownConnection(conn), nil
	}

	untrustedConn, untrustedErr := ConnectToShimService(device, RemoteLockdownUntrustedService)
	if untrustedErr != nil {
		return nil, fmt.Errorf("ConnectRemoteLockdown: trusted service failed: %w; untrusted service failed: %w", err, untrustedErr)
	}
	return NewLockDownConnection(untrustedConn), nil
}

// GetRemoteValuesPlist returns all lockdown values through RSD remote lockdown.
func GetRemoteValuesPlist(device DeviceEntry) (map[string]interface{}, error) {
	lockdownConnection, err := ConnectRemoteLockdown(device)
	if err != nil {
		return map[string]interface{}{}, err
	}
	defer lockdownConnection.Close()

	err = lockdownConnection.Send(newGetValue(""))
	if err != nil {
		return map[string]interface{}{}, err
	}
	resp, err := lockdownConnection.ReadMessage()
	if err != nil {
		return map[string]interface{}{}, err
	}
	plist, err := ParsePlist(resp)
	if err != nil {
		return map[string]interface{}{}, err
	}
	plist, ok := plist["Value"].(map[string]interface{})
	if !ok {
		return plist, fmt.Errorf("Failed converting remote lockdown response:%+v", plist)
	}
	return plist, err
}

// GetRemoteValues returns all lockdown values through RSD remote lockdown.
func GetRemoteValues(device DeviceEntry) (GetAllValuesResponse, error) {
	lockdownConnection, err := ConnectRemoteLockdown(device)
	if err != nil {
		return GetAllValuesResponse{}, err
	}
	defer lockdownConnection.Close()

	allValues, err := lockdownConnection.GetValues()
	if err != nil {
		return GetAllValuesResponse{}, err
	}
	return allValues, nil
}

// GetRemoteValueForDomain gets a remote lockdown value through RSD.
func GetRemoteValueForDomain(device DeviceEntry, key string, domain string) (interface{}, error) {
	lockdownConnection, err := ConnectRemoteLockdown(device)
	if err != nil {
		return nil, err
	}
	defer lockdownConnection.Close()

	return lockdownConnection.GetValueForDomain(key, domain)
}

// GetRemoteDeveloperModeStatus reads DeveloperModeStatus through RSD remote lockdown.
func GetRemoteDeveloperModeStatus(device DeviceEntry) (bool, error) {
	value, err := GetRemoteValueForDomain(device, "DeveloperModeStatus", "com.apple.security.mac.amfi")
	if err != nil {
		return false, err
	}
	return parseRemoteDeveloperModeStatus(value)
}

func parseRemoteDeveloperModeStatus(value interface{}) (bool, error) {
	enabled, ok := value.(bool)
	if !ok {
		return false, fmt.Errorf("GetRemoteDeveloperModeStatus: expected bool, got %T", value)
	}
	return enabled, nil
}
