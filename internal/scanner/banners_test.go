package scanner

import (
	"net"
	"strings"
	"testing"
	"time"
)

type sshBannerTestCase struct {
	name         string
	serverAction func(t *testing.T, s net.Conn)
	wantBanner   string
	wantErr      bool
	errSubstr    string
}

type httpBannerTestCase struct {
	name         string
	serverAction func(t *testing.T, s net.Conn)
	wantBanner   string
	wantErr      bool
	errSubstr    string
}

func getSSHTestCases() []sshBannerTestCase {
	return []sshBannerTestCase{
		{
			name: "SSH-T01: Canonical RFC 4253 banner string",
			serverAction: func(t *testing.T, s net.Conn) {
				_, _ = s.Write([]byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"))
			},
			wantBanner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
			wantErr:    false,
		},
		{
			name: "SSH-T02: Endlessh tarpit buffer exhaustion",
			serverAction: func(t *testing.T, s net.Conn) {
				// Stream infinite garbage bytes to trigger io.LimitReader ceiling
				for i := 0; i < 100; i++ {
					if _, err := s.Write([]byte("SSH-Tarpit-Payload-Stream-Garbage-Garbage")); err != nil {
						return
					}
				}
			},
			wantErr:   true,
			errSubstr: "banner exceeded max limit",
		},
		{
			name: "SSH-T03: Premature socket termination",
			serverAction: func(t *testing.T, s net.Conn) {
				_ = s.Close()
			},
			wantErr:   true,
			errSubstr: "EOF",
		},
		{
			name: "SSH-T04: Stalling socket",
			serverAction: func(t *testing.T, s net.Conn) {
				time.Sleep(200 * time.Millisecond)
			},
			wantErr:   true,
			errSubstr: "i/o timeout",
		},
		{
			name: "SSH-T05: Non-SSH service",
			serverAction: func(t *testing.T, s net.Conn) {
				_, _ = s.Write([]byte("220 Welcome to FTP server\r\n"))
			},
			wantErr:   true,
			errSubstr: "invalid protocol",
		},
	}
}

func getHTTPTestCases() []httpBannerTestCase {
	return []httpBannerTestCase{
		{
			name: "HTTP-T01: Standard Server Header Extraction",
			serverAction: func(t *testing.T, s net.Conn) {
				buf := make([]byte, 1024)
				n, err := s.Read(buf)
				if err != nil || n == 0 {
					return
				}
				_, _ = s.Write([]byte("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n"))
			},
			wantBanner: "nginx/1.24.0",
			wantErr:    false,
		},
		{
			name: "HTTP-T02: Case-Insensitive Header",
			serverAction: func(t *testing.T, s net.Conn) {
				buf := make([]byte, 1024)
				n, err := s.Read(buf)
				if err != nil || n == 0 {
					return
				}
				_, _ = s.Write([]byte("HTTP/1.1 200 OK\r\nserver: Apache/2.4.52\r\n\r\n"))
			},
			wantBanner: "Apache/2.4.52",
			wantErr:    false,
		},
		{
			name: "HTTP-T03: Missing Server Header Fallback",
			serverAction: func(t *testing.T, s net.Conn) {
				buf := make([]byte, 1024)
				n, err := s.Read(buf)
				if err != nil || n == 0 {
					return
				}
				_, _ = s.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
			},
			wantBanner: "HTTP/1.1 403 Forbidden",
			wantErr:    false,
		},
		{
			name: "HTTP-T04: Header Flood / Slowloris Tarpit",
			serverAction: func(t *testing.T, s net.Conn) {
				buf := make([]byte, 1024)
				n, err := s.Read(buf)
				if err != nil || n == 0 {
					return
				}
				for i := 0; i < 100; i++ {
					if _, err := s.Write([]byte("X-Flood-Header: AAAAAAAAAAAAAAAAAAAAAAAA\r\n")); err != nil {
						return
					}
				}
			},
			wantBanner: "",
			wantErr:    true,
			errSubstr:  "exceeded max limit",
		},
		{
			name: "HTTP-T05: Premature Socket Termination",
			serverAction: func(t *testing.T, s net.Conn) {
				buf := make([]byte, 1024)
				_, _ = s.Read(buf)
				_ = s.Close()
			},
			wantBanner: "",
			wantErr:    true,
			errSubstr:  "EOF",
		},
		{
			name: "HTTP-T06: Stalling Socket Read Deadline",
			serverAction: func(t *testing.T, s net.Conn) {
				buf := make([]byte, 1024)
				_, _ = s.Read(buf)
				time.Sleep(100 * time.Millisecond)
			},
			wantBanner: "",
			wantErr:    true,
			errSubstr:  "i/o timeout",
		},
	}
}

func TestParseHTTP(t *testing.T) {
	for _, tc := range getHTTPTestCases() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()

			done := make(chan struct{})

			go func() {
				defer serverConn.Close()
				defer close(done)
				tc.serverAction(t, serverConn)
			}()

			gotBanner, err := ParseHTTP(clientConn, 50*time.Millisecond)

			_ = clientConn.Close()

			select {
			case <-done:
			case <-time.After(250 * time.Millisecond):
				t.Fatalf("test case %q deadlocked mock server goroutine", tc.name)
			}

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (banner: %q)", gotBanner)
				}
				if tc.errSubstr != "" && !strings.Contains(err.Error(), tc.errSubstr) {
					t.Errorf("error %q does not contain expected substring %q", err.Error(), tc.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexcepted error: %v", err)
			}
			if gotBanner != tc.wantBanner {
				t.Errorf("got banner %q, want %q", gotBanner, tc.wantBanner)
			}
		})
	}
}

func TestParseSSH(t *testing.T) {
	for _, tc := range getSSHTestCases() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()

			done := make(chan struct{})

			go func() {
				defer serverConn.Close()
				defer close(done)
				tc.serverAction(t, serverConn)
			}()

			gotBanner, err := ParseSSH(clientConn, 50*time.Millisecond)

			_ = clientConn.Close()

			select {
			case <-done:
			case <-time.After(250 * time.Millisecond):
				t.Fatalf("test case %q deadlocked mock server goroutine", tc.name)
			}

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (banner: %q)", gotBanner)
				}
				if tc.errSubstr != "" && !strings.Contains(err.Error(), tc.errSubstr) {
					t.Errorf("error %q does not contain expected substring %q", err.Error(), tc.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotBanner != tc.wantBanner {
				t.Errorf("got banner %q, want %q", gotBanner, tc.wantBanner)
			}
		})
	}
}
