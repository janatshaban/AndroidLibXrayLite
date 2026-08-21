//go:build android

package libv2ray

import (
	"errors"
	"sync"
	"syscall"

	corenet "github.com/xtls/xray-core/transport/internet"
)

// V2RayVPNService is implemented by the Android VpnService.
//
// Protect must call Android's VpnService.protect(socketFd)
// and return true when the socket has successfully been
// excluded from the VPN tunnel.
type V2RayVPNService interface {
	Protect(int) bool
}

var (
	protectMu      sync.Mutex
	protectService V2RayVPNService
	protectInstalled bool
)

// RegisterVPNService registers the Android VPN socket protection
// callback with Xray's system dialer.
//
// This must be called before starting the Xray core.
func (x *CoreController) RegisterVPNService(service V2RayVPNService) error {
	if service == nil {
		return errors.New("V2RayVPNService is nil")
	}

	protectMu.Lock()
	defer protectMu.Unlock()

	// Do not install the controller repeatedly in the same process.
	if protectInstalled {
		protectService = service
		return nil
	}

	protectService = service

	err := corenet.RegisterDialerController(
		func(network, address string, rawConn syscall.RawConn) error {
			var protectErr error

			err := rawConn.Control(func(fd uintptr) {
				svc := protectService
				if svc == nil {
					protectErr = errors.New("V2RayVPNService is nil")
					return
				}

				if !svc.Protect(int(fd)) {
					protectErr = errors.New("VpnService.protect() failed")
				}
			})

			if err != nil {
				return err
			}

			return protectErr
		},
	)

	if err != nil {
		protectService = nil
		return err
	}

	protectInstalled = true
	return nil
}

// UnregisterVPNService releases the Java/Kotlin callback reference.
//
// The Xray controller itself is process-global, so this does not remove
// an already-installed controller; it simply prevents future callbacks
// from retaining the old Android service.
func (x *CoreController) UnregisterVPNService() {
	protectMu.Lock()
	defer protectMu.Unlock()

	protectService = nil
}
