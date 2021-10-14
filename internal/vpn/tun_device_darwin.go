//go:build darwin
// +build darwin

package vpn

import (
	"errors"
	"syscall"
)

func (t *tunDevice) Read(to []byte) (int, error) {
	t.rmu.Lock()
	defer t.rmu.Unlock()

	if cap(t.rbuf) < len(to)+4 {
		t.rbuf = make([]byte, len(to)+4)
	}
	t.rbuf = t.rbuf[:len(to)+4]

	copy(to, t.rbuf[4:])
	return t.tun.Read(t.rbuf, 4)
}

func (t *tunDevice) Write(from []byte) (int, error) {
	if len(from) == 0 {
		return 0, syscall.EIO
	}

	t.wmu.Lock()
	defer t.wmu.Unlock()

	if cap(t.wbuf) < len(from)+4 {
		t.wbuf = make([]byte, len(from)+4)
	}
	t.wbuf = t.wbuf[:len(from)+4]

	// Determine the IP Family for the NULL L2 Header
	ipVer := from[0] >> 4
	if ipVer == 4 {
		t.wbuf[3] = syscall.AF_INET
	} else if ipVer == 6 {
		t.wbuf[3] = syscall.AF_INET6
	} else {
		return 0, errors.New("unable to determine IP version from packet")
	}
	copy(t.wbuf[4:], from)

	return t.tun.Write(t.wbuf, 4)
}
