// Package libxray is a minimal gomobile wrapper around Xray-core for the
// Smart Ad Shield VPN Android app. Xray runs in-process; the Android TUN file
// descriptor is handed over through XRAY_TUN_FD (see proxy/tun/tun_android.go).
package libxray

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
)

var (
	mu       sync.Mutex
	instance *core.Instance
)

// Start launches Xray with the given JSON configuration. tunFd is the
// VpnService TUN descriptor (>= 0) or -1 when no tun inbound is used.
func Start(configJSON string, tunFd int) error {
	mu.Lock()
	defer mu.Unlock()
	if instance != nil {
		_ = instance.Close()
		instance = nil
	}
	if tunFd >= 0 {
		if err := os.Setenv("XRAY_TUN_FD", strconv.Itoa(tunFd)); err != nil {
			return err
		}
	}
	cfg, err := core.LoadConfig("json", bytes.NewReader([]byte(configJSON)))
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	inst, err := core.New(cfg)
	if err != nil {
		return fmt.Errorf("init: %w", err)
	}
	if err := inst.Start(); err != nil {
		_ = inst.Close()
		return fmt.Errorf("start: %w", err)
	}
	instance = inst
	return nil
}

// Stop shuts Xray down. Safe to call when not running.
func Stop() error {
	mu.Lock()
	defer mu.Unlock()
	if instance == nil {
		return nil
	}
	err := instance.Close()
	instance = nil
	return err
}

// IsRunning reports whether an instance is active.
func IsRunning() bool {
	mu.Lock()
	defer mu.Unlock()
	return instance != nil
}

// Version returns the embedded Xray-core version.
func Version() string { return core.Version() }
