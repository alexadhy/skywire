package vpn

import (
	"fmt"
	"io"
	"runtime"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// TUNDevice is a wrapper for TUN interface.
type TUNDevice interface {
	io.ReadWriteCloser
	Name() string
}

func ifTunName() string {
	switch runtime.GOOS {
	case "darwin":
		return "utun" // default name for darwin
	default:
		return "skytun"
	}
}

type tunDevice struct {
	tun tun.Device
	// read buffers
	rmu  sync.Mutex
	rbuf []byte
	// write buffers
	wmu  sync.Mutex
	wbuf []byte
	// name of the interface
	name string
}

func newTUNDevice() (TUNDevice, error) {
	tunName := ifTunName()

	dev, err := tun.CreateTUN(tunName, TUNMTU)
	if err != nil {
		return nil, fmt.Errorf("error allocating TUN interface: %w", err)
	}

	name, err := dev.Name()
	if err != nil {
		return nil, fmt.Errorf("error getting interface name: %w", err)
	}

	return &tunDevice{
		tun:  dev,
		name: name,
	}, nil
}

func (t *tunDevice) Close() error {
	return t.tun.Close()
}

func (t *tunDevice) Name() string {
	return t.name
}
