//go:build linux

package tun

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type redirectListenerTestHandler struct{ destination chan M.Socksaddr }

func (h *redirectListenerTestHandler) NewConnectionEx(_ context.Context, conn net.Conn, _ M.Socksaddr, destination M.Socksaddr, _ N.CloseHandlerFunc) {
	defer conn.Close()
	h.destination <- destination
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.CopyN(conn, conn, 4)
}

func TestRedirectServerExternalListener(t *testing.T) {
	listener, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	handler := &redirectListenerTestHandler{destination: make(chan M.Socksaddr, 1)}
	server := NewRedirectServer(context.Background(), handler, logger.NOP(), netip.IPv6Unspecified())
	// The transparent IPv6 path reports the accepted socket's local address.
	server.SetExternalTransparent()
	server.StartWithListener(listener)
	t.Cleanup(func() { _ = server.Close() })
	if server.Port() != uint16(listener.Addr().(*net.TCPAddr).Port) {
		t.Fatal("listener port changed")
	}
	conn, err := net.DialTimeout("tcp6", listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var payload [4]byte
	if _, err = io.ReadFull(conn, payload[:]); err != nil {
		t.Fatal(err)
	}
	if string(payload[:]) != "ping" {
		t.Fatalf("unexpected echo: %q", payload)
	}
	select {
	case destination := <-handler.destination:
		if destination != M.SocksaddrFromNet(listener.Addr()) {
			t.Fatalf("destination = %v", destination)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler was not called")
	}
	if err = server.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = listener.AcceptTCP(); err == nil {
		t.Fatal("external listener is still open")
	}
}
