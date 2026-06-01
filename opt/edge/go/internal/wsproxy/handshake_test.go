package wsproxy

import (
	"bufio"
	"io"
	"net"
	"testing"
	"time"
)

func TestPathAllowed(t *testing.T) {
	if !PathAllowed("/foo/bar", "/foo") {
		t.Fatal("expected prefix path to be allowed")
	}
	if PathAllowed("/bar", "/foo") {
		t.Fatal("expected mismatched path to be rejected")
	}
}

func TestFirstForwardedIP(t *testing.T) {
	if got := firstForwardedIP(" 203.0.113.10, 127.0.0.1 "); got != "203.0.113.10" {
		t.Fatalf("unexpected forwarded ip: %q", got)
	}
	if got := firstForwardedIP("garbage, ::1"); got != "::1" {
		t.Fatalf("unexpected fallback forwarded ip: %q", got)
	}
}

func TestReadHandshakePreservesBufferedPayload(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	payload := []byte("SSH-2.0-test-client\r\n")
	go func() {
		req := "GET / HTTP/1.1\r\n" +
			"Host: example.test\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"\r\n"
		_, _ = client.Write(append([]byte(req), payload...))
	}()

	reader := bufio.NewReader(server)
	if _, _, _, err := ReadHandshake(reader, server, time.Second, "/"); err != nil {
		t.Fatalf("ReadHandshake failed: %v", err)
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatalf("payload was not preserved in shared reader: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
}
