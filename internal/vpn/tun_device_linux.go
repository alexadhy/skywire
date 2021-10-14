package vpn

func (t *tunDevice) Read(buf []byte) (int, error) {
	return t.tun.Read(buf, 0)
}

func (t *tunDevice) Write(buf []byte) (int, error) {
	return t.tun.Write(buf, 0)
}

