// Package probe provides hop-by-hop latency measurements used by the admin API.
package probe

import (
	"context"
	"fmt"
	"net"
	"time"
)

// DialTCP connects to addr (host:port) and returns the time-to-connect.
// The connection is closed immediately after the handshake.
func DialTCP(ctx context.Context, addr string) (time.Duration, error) {
	d := &net.Dialer{}
	t0 := time.Now()
	conn, err := d.DialContext(ctx, "tcp", addr)
	elapsed := time.Since(t0)
	if err != nil {
		return 0, fmt.Errorf("probe: TCP dial %s: %w", addr, err)
	}
	_ = conn.Close()
	return elapsed, nil
}

// DialSOCKS5 connects to targetAddr through a SOCKS5 proxy at socksAddr and
// returns the time from dial start until the proxy reports a successful connection.
// It performs only the SOCKS5 handshake — no application data is sent.
func DialSOCKS5(ctx context.Context, socksAddr, targetAddr string) (time.Duration, error) {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return 0, fmt.Errorf("probe: bad target address %q: %w", targetAddr, err)
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return 0, fmt.Errorf("probe: bad target port %q: %w", portStr, err)
	}

	d := &net.Dialer{}
	t0 := time.Now()
	conn, err := d.DialContext(ctx, "tcp", socksAddr)
	if err != nil {
		return 0, fmt.Errorf("probe: SOCKS5 dial %s: %w", socksAddr, err)
	}
	defer conn.Close() //nolint:errcheck

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if err := socks5Connect(conn, host, uint16(port)); err != nil {
		return 0, fmt.Errorf("probe: SOCKS5 handshake to %s: %w", targetAddr, err)
	}

	return time.Since(t0), nil
}

// socks5Connect performs a SOCKS5 no-auth connect request.
// See RFC 1928 §§ 3–6.
func socks5Connect(conn net.Conn, host string, port uint16) error {
	// Greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	// Server choice
	buf := make([]byte, 2)
	if _, err := readFull(conn, buf); err != nil {
		return err
	}
	if buf[0] != 5 || buf[1] != 0 {
		return fmt.Errorf("unexpected auth reply: %v", buf)
	}
	// Request: VER=5, CMD=CONNECT, RSV=0, ATYP=3 (domain), len, host, port (big-endian)
	req := make([]byte, 0, 7+len(host))
	req = append(req, 5, 1, 0, 3, byte(len(host)))
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}
	// Response: VER, REP, RSV, ATYP, …
	hdr := make([]byte, 4)
	if _, err := readFull(conn, hdr); err != nil {
		return err
	}
	if hdr[1] != 0 {
		return fmt.Errorf("SOCKS5 error reply: 0x%02x", hdr[1])
	}
	// Consume the bound address (ATYP determines length).
	switch hdr[3] {
	case 1: // IPv4
		tmp := make([]byte, 6)
		_, err := readFull(conn, tmp)
		return err
	case 3: // domain
		lenBuf := make([]byte, 1)
		if _, err := readFull(conn, lenBuf); err != nil {
			return err
		}
		tmp := make([]byte, int(lenBuf[0])+2)
		_, err := readFull(conn, tmp)
		return err
	case 4: // IPv6
		tmp := make([]byte, 18)
		_, err := readFull(conn, tmp)
		return err
	}
	return nil
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		nn, err := conn.Read(buf[n:])
		n += nn
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
