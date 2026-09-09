package scanner

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/CryToSky1324/TcpRecon/internal/models"
)

// KeyType distinguishes between ECDSA and RSA private key generation.
type KeyType int

const (
	KeyTypeECDSA KeyType = iota
	KeyTypeRSA
)

// generateKeyPair generates either an ECDSA P-256 or RSA-2048 key pair.
func generateKeyPair(t testing.TB, keyType KeyType) (crypto.PrivateKey, crypto.PublicKey) {
	t.Helper()
	switch keyType {
	case KeyTypeRSA:
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey failed: %v", err)
		}
		return priv, &priv.PublicKey
	case KeyTypeECDSA:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey failed: %v", err)
		}
		return priv, &priv.PublicKey
	default:
		t.Fatalf("unsupported key type: %v", keyType)
		return nil, nil
	}
}

// generateTestCA creates a self-signed root CA certificate, private key, and cert pool.
func generateTestCA(t testing.TB) (*x509.Certificate, crypto.PrivateKey, *x509.CertPool) {
	t.Helper()

	privKey, pubKey := generateKeyPair(t, KeyTypeECDSA)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		t.Fatalf("rand.Int serial number failed: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "TcpRecon Test CA",
			Organization: []string{"TcpRecon Test Org"},
		},
		NotBefore:             time.Now().UTC().Add(-1 * time.Hour),
		NotAfter:              time.Now().UTC().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, pubKey, privKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate failed for CA: %v", err)
	}

	caCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("x509.ParseCertificate failed for CA: %v", err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)

	return caCert, privKey, certPool
}

// supplyFixtureCAPool configures both CustomRootCAPool and SSL_CERT_FILE so the scanner
// can verify test certificates issued by the fixture CA.
func supplyFixtureCAPool(t testing.TB, caCert *x509.Certificate, caPool *x509.CertPool) {
	t.Helper()
	customRootCAPool = caPool
	t.Cleanup(func() {
		customRootCAPool = nil
	})

	caPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.Raw,
	})
	tmpFile, err := os.CreateTemp("", "tcprecon-test-ca-*.crt")
	if err != nil {
		t.Fatalf("failed to create temp CA file: %v", err)
	}
	if _, err := tmpFile.Write(caPEM); err != nil {
		t.Fatalf("failed to write temp CA file: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("failed to close temp CA file: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(tmpFile.Name())
	})
	t.Setenv("SSL_CERT_FILE", tmpFile.Name())
}

// generateTestLeafWithKeyType creates a leaf certificate signed by parent (or self-signed if parent is nil).
func generateTestLeafWithKeyType(
	t testing.TB,
	keyType KeyType,
	cn string,
	parent *x509.Certificate,
	parentKey crypto.PrivateKey,
	notBefore, notAfter time.Time,
	dnsNames []string,
	ips []net.IP,
) tls.Certificate {
	t.Helper()

	privKey, pubKey := generateKeyPair(t, keyType)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		t.Fatalf("rand.Int serial number failed: %v", err)
	}

	// Bind 'localhost' to DNSNames by default
	hasLocalhost := false
	for _, name := range dnsNames {
		if name == "localhost" {
			hasLocalhost = true
			break
		}
	}
	mergedDNS := dnsNames
	if !hasLocalhost {
		mergedDNS = append([]string{"localhost"}, dnsNames...)
	}
	if cn != "" && cn != "localhost" {
		mergedDNS = append(mergedDNS, cn)
	}

	// Bind 127.0.0.1 to IPAddresses by default
	loopbackIP := net.ParseIP("127.0.0.1")
	hasLoopback := false
	for _, ip := range ips {
		if ip.Equal(loopbackIP) {
			hasLoopback = true
			break
		}
	}
	mergedIPs := ips
	if !hasLoopback {
		mergedIPs = append([]net.IP{loopbackIP}, ips...)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"TcpRecon Test TLS"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              mergedDNS,
		IPAddresses:           mergedIPs,
	}

	signerCert := template
	signerKey := privKey
	if parent != nil && parentKey != nil {
		signerCert = parent
		signerKey = parentKey
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, signerCert, pubKey, signerKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate failed for leaf: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  privKey,
	}
}

// generateTestLeaf creates an ECDSA P-256 leaf certificate signed by parent (or self-signed if parent is nil).
func generateTestLeaf(
	t testing.TB,
	cn string,
	parent *x509.Certificate,
	parentKey crypto.PrivateKey,
	notBefore, notAfter time.Time,
	dnsNames []string,
	ips []net.IP,
) tls.Certificate {
	t.Helper()
	return generateTestLeafWithKeyType(t, KeyTypeECDSA, cn, parent, parentKey, notBefore, notAfter, dnsNames, ips)
}

// generateTestLeafRSA creates an RSA-2048 leaf certificate signed by parent (or self-signed if parent is nil).
func generateTestLeafRSA(
	t testing.TB,
	cn string,
	parent *x509.Certificate,
	parentKey crypto.PrivateKey,
	notBefore, notAfter time.Time,
	dnsNames []string,
	ips []net.IP,
) tls.Certificate {
	t.Helper()
	return generateTestLeafWithKeyType(t, KeyTypeRSA, cn, parent, parentKey, notBefore, notAfter, dnsNames, ips)
}

// startTLSServer spins up an in-memory TLS listener using the provided tls.Config.
func startTLSServer(t testing.TB, tlsConfig *tls.Config) (string, int, func()) {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("tls.Listen failed: %v", err)
	}

	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected listener addr type: %T", ln.Addr())
	}
	host := tcpAddr.IP.String()
	port := tcpAddr.Port

	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}

			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))

				if tlsConn, ok := c.(*tls.Conn); ok {
					if err := tlsConn.Handshake(); err != nil {
						return
					}
				}

				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				if n > 0 {
					_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
				}
			}(conn)
		}
	}()

	cleanup := func() {
		close(done)
		_ = ln.Close()
	}
	t.Cleanup(cleanup)

	return host, port, cleanup
}

// Helper: TC-C1-01 Valid TLS 1.3 server with CA-signed certificate trusted by fixture pool.
func startValidTLS13Server(t testing.TB) (string, int, *x509.Certificate, func()) {
	t.Helper()

	caCert, caKey, caPool := generateTestCA(t)
	supplyFixtureCAPool(t, caCert, caPool)

	now := time.Now().UTC()
	notBefore := now.Add(-1 * time.Hour)
	notAfter := now.Add(24 * time.Hour)

	tlsCert := generateTestLeaf(
		t,
		"localhost",
		caCert,
		caKey,
		notBefore,
		notAfter,
		[]string{"localhost"},
		[]net.IP{net.ParseIP("127.0.0.1")},
	)

	parsedCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("x509.ParseCertificate failed: %v", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_AES_128_GCM_SHA256},
	}

	host, port, cleanup := startTLSServer(t, cfg)
	return host, port, parsedCert, cleanup
}

// Helper: Deprecated TLS 1.0 / TLS 1.1 server.
func startDeprecatedTLSServer(t testing.TB, version uint16) (string, int, *x509.Certificate, func()) {
	t.Helper()

	now := time.Now().UTC()
	notBefore := now.Add(-1 * time.Hour)
	notAfter := now.Add(24 * time.Hour)

	// RSA-2048 key allows legacy TLS 1.0/1.1 suites to negotiate RSA ciphers
	tlsCert := generateTestLeafRSA(
		t,
		"localhost",
		nil,
		nil,
		notBefore,
		notAfter,
		[]string{"localhost"},
		[]net.IP{net.ParseIP("127.0.0.1")},
	)

	parsedCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("x509.ParseCertificate failed: %v", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   version,
		MaxVersion:   version,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
	}

	host, port, cleanup := startTLSServer(t, cfg)
	return host, port, parsedCert, cleanup
}

// Helper: Expired certificate (NotAfter in the past).
func startExpiredCertServer(t testing.TB) (string, int, *x509.Certificate, func()) {
	t.Helper()

	now := time.Now().UTC()
	notBefore := now.Add(-48 * time.Hour)
	notAfter := now.Add(-24 * time.Hour)

	tlsCert := generateTestLeaf(
		t,
		"localhost",
		nil,
		nil,
		notBefore,
		notAfter,
		[]string{"localhost"},
		[]net.IP{net.ParseIP("127.0.0.1")},
	)

	parsedCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("x509.ParseCertificate failed: %v", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}

	host, port, cleanup := startTLSServer(t, cfg)
	return host, port, parsedCert, cleanup
}

// Helper: Untrusted/self-signed certificate with verification error.
func startUntrustedCertServer(t testing.TB) (string, int, *x509.Certificate, func()) {
	t.Helper()

	now := time.Now().UTC()
	notBefore := now.Add(-1 * time.Hour)
	notAfter := now.Add(24 * time.Hour)

	untrustedCA, untrustedKey, _ := generateTestCA(t)
	tlsCert := generateTestLeaf(
		t,
		"untrusted.local",
		untrustedCA,
		untrustedKey,
		notBefore,
		notAfter,
		[]string{"untrusted.local"},
		nil,
	)

	parsedCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("x509.ParseCertificate failed: %v", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}

	host, port, cleanup := startTLSServer(t, cfg)
	return host, port, parsedCert, cleanup
}

// Helper: TC-C1-05 Plaintext TCP echo server.
func startPlaintextTCPServer(t testing.TB) (string, int, *x509.Certificate, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}

	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected listener addr type: %T", ln.Addr())
	}
	host := tcpAddr.IP.String()
	port := tcpAddr.Port

	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}

			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						_, _ = c.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	cleanup := func() {
		close(done)
		_ = ln.Close()
	}
	t.Cleanup(cleanup)

	return host, port, nil, cleanup
}

// Helper: TC-C1-06 Stalling TCP listener (tarpit).
func startStallingTCPServer(t testing.TB) (string, int, *x509.Certificate, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}

	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected listener addr type: %T", ln.Addr())
	}
	host := tcpAddr.IP.String()
	port := tcpAddr.Port

	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}

			go func(c net.Conn) {
				defer c.Close()
				// Stall indefinitely until closed or test teardown
				select {
				case <-done:
					return
				case <-time.After(30 * time.Second):
					return
				}
			}(conn)
		}
	}()

	cleanup := func() {
		close(done)
		_ = ln.Close()
	}
	t.Cleanup(cleanup)

	return host, port, nil, cleanup
}

// TestTLSInspection scaffolds the table-driven test runner asserting that models.ScanResult captures:
// - Non-Fatal Probe Invariant: res.State == 'open' and res.Port == port
// - TLSVersion (string)
// - CipherSuite (string or uint16) matching exact IANA cipher suite string
// - CertVerified (bool)
// - CertNotBefore / CertNotAfter (strict RFC3339 timestamps in UTC ending in 'Z')
func TestTLSInspection(t *testing.T) {
	testCases := []struct {
		name             string
		serverSetup      func(t testing.TB) (string, int, *x509.Certificate, func())
		wantTLS          bool
		wantTLSVersion   string
		wantCipherSuite  string
		wantCertVerified bool
		wantExpired      bool
	}{
		{
			name:             "TC-C1-01: Valid TLS 1.3 server with verified certificate",
			serverSetup:      startValidTLS13Server,
			wantTLS:          true,
			wantTLSVersion:   "TLS 1.3",
			wantCipherSuite:  "TLS_AES_128_GCM_SHA256",
			wantCertVerified: true,
			wantExpired:      false,
		},
		{
			name: "TC-C1-02: Deprecated TLS 1.0 server",
			serverSetup: func(t testing.TB) (string, int, *x509.Certificate, func()) {
				return startDeprecatedTLSServer(t, tls.VersionTLS10)
			},
			wantTLS:          true,
			wantTLSVersion:   "TLS 1.0",
			wantCipherSuite:  "TLS_RSA_WITH_AES_128_CBC_SHA",
			wantCertVerified: false,
			wantExpired:      false,
		},
		{
			name: "TC-C1-03: Deprecated TLS 1.1 server",
			serverSetup: func(t testing.TB) (string, int, *x509.Certificate, func()) {
				return startDeprecatedTLSServer(t, tls.VersionTLS11)
			},
			wantTLS:          true,
			wantTLSVersion:   "TLS 1.1",
			wantCipherSuite:  "TLS_RSA_WITH_AES_128_CBC_SHA",
			wantCertVerified: false,
			wantExpired:      false,
		},
		{
			name:             "TC-C1-04: Expired certificate (NotAfter in the past)",
			serverSetup:      startExpiredCertServer,
			wantTLS:          true,
			wantTLSVersion:   "TLS 1.2",
			wantCipherSuite:  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			wantCertVerified: false,
			wantExpired:      true,
		},
		{
			name:             "TC-C1-05: Plaintext TCP echo server",
			serverSetup:      startPlaintextTCPServer,
			wantTLS:          false,
			wantTLSVersion:   "",
			wantCipherSuite:  "",
			wantCertVerified: false,
			wantExpired:      false,
		},
		{
			name:             "TC-C1-06: Stalling TCP listener",
			serverSetup:      startStallingTCPServer,
			wantTLS:          false,
			wantTLSVersion:   "",
			wantCipherSuite:  "",
			wantCertVerified: false,
			wantExpired:      false,
		},
		{
			name:             "TC-C1-07: Untrusted certificate with verification error",
			serverSetup:      startUntrustedCertServer,
			wantTLS:          true,
			wantTLSVersion:   "TLS 1.2",
			wantCipherSuite:  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			wantCertVerified: false,
			wantExpired:      false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			host, port, cert, _ := tc.serverSetup(t)

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			jobs := make(chan models.ScanJob, 1)
			results := make(chan models.ScanResult, 1)
			limiter := rate.NewLimiter(rate.Inf, 1)

			jobs <- models.ScanJob{
				TargetIP:   host,
				TargetName: "localhost",
				Port:       port,
				Protocol:   "tcp",
			}
			close(jobs)

			// Concurrency bug fix: Worker runs in a goroutine so select block functions as an active watchdog
			go Worker(ctx, jobs, results, 500*time.Millisecond, false, limiter)

			var res models.ScanResult
			select {
			case res = <-results:
			case <-ctx.Done():
				t.Fatalf("worker watchdog triggered: timed out waiting for results on port %d", port)
			}

			// Non-Fatal Probe Invariant: L4 success must always yield State == "open" and correct Port
			if res.State != "open" {
				t.Errorf("res.State = %q, want %q", res.State, "open")
			}
			if res.Port != port {
				t.Errorf("res.Port = %d, want %d", res.Port, port)
			}

			if !tc.wantTLS {
				// Assert empty TLS metadata for plaintext or stalled services
				if res.TLSVersion != "" {
					t.Errorf("TLSVersion = %q, want empty for non-TLS", res.TLSVersion)
				}
				if res.CipherSuite != "" {
					t.Errorf("CipherSuite = %q, want empty for non-TLS", res.CipherSuite)
				}
				if res.CertVerified {
					t.Errorf("CertVerified = true, want false for non-TLS")
				}
				if res.CertNotBefore != "" {
					t.Errorf("CertNotBefore = %q, want empty for non-TLS", res.CertNotBefore)
				}
				if res.CertNotAfter != "" {
					t.Errorf("CertNotAfter = %q, want empty for non-TLS", res.CertNotAfter)
				}
				if res.CertSubject != "" {
					t.Errorf("CertSubject = %q, want empty for non-TLS", res.CertSubject)
				}
				if res.CertIssuer != "" {
					t.Errorf("CertIssuer = %q, want empty for non-TLS", res.CertIssuer)
				}
				if len(res.SANs) != 0 {
					t.Errorf("SANs = %v, want empty for non-TLS", res.SANs)
				}
				return
			}

			// 1. Assert TLSVersion (string)
			normGotVersion := strings.ReplaceAll(res.TLSVersion, " ", "")
			normWantVersion := strings.ReplaceAll(tc.wantTLSVersion, " ", "")
			if normGotVersion != normWantVersion {
				t.Errorf("TLSVersion = %q, want %q", res.TLSVersion, tc.wantTLSVersion)
			}

			// 2. Assert CipherSuite matching exact expected IANA cipher suite string
			if res.CipherSuite != tc.wantCipherSuite {
				t.Errorf("CipherSuite = %q, want %q", res.CipherSuite, tc.wantCipherSuite)
			}

			// 3. Assert CertVerified (bool)
			if res.CertVerified != tc.wantCertVerified {
				t.Errorf("CertVerified = %v, want %v", res.CertVerified, tc.wantCertVerified)
			}

			// 4. Assert CertNotBefore / CertNotAfter (RFC3339 timestamps in UTC ending in 'Z')
			if res.CertNotBefore == "" {
				t.Errorf("CertNotBefore is empty, want RFC3339 timestamp")
			} else {
				if !strings.HasSuffix(res.CertNotBefore, "Z") {
					t.Errorf("CertNotBefore = %q does not end in 'Z' (strict UTC RFC3339 required)", res.CertNotBefore)
				}
				parsedNB, err := time.Parse(time.RFC3339, res.CertNotBefore)
				if err != nil {
					t.Errorf("CertNotBefore = %q is not valid RFC3339: %v", res.CertNotBefore, err)
				} else if cert != nil && !parsedNB.Equal(cert.NotBefore.Truncate(time.Second)) {
					t.Errorf("CertNotBefore = %v, want %v", parsedNB, cert.NotBefore.Truncate(time.Second))
				}
			}

			if res.CertNotAfter == "" {
				t.Errorf("CertNotAfter is empty, want RFC3339 timestamp")
			} else {
				if !strings.HasSuffix(res.CertNotAfter, "Z") {
					t.Errorf("CertNotAfter = %q does not end in 'Z' (strict UTC RFC3339 required)", res.CertNotAfter)
				}
				parsedNA, err := time.Parse(time.RFC3339, res.CertNotAfter)
				if err != nil {
					t.Errorf("CertNotAfter = %q is not valid RFC3339: %v", res.CertNotAfter, err)
				} else if cert != nil && !parsedNA.Equal(cert.NotAfter.Truncate(time.Second)) {
					t.Errorf("CertNotAfter = %v, want %v", parsedNA, cert.NotAfter.Truncate(time.Second))
				}
				if tc.wantExpired {
					if cert != nil && !cert.NotAfter.Before(time.Now()) {
						t.Errorf("fixture certificate NotAfter = %v is not in the past", cert.NotAfter)
					}
					if res.CertVerified {
						t.Errorf("CertVerified = true for expired certificate, want false")
					}
					if parsedNA.After(time.Now()) {
						t.Errorf("CertNotAfter = %v is not expired, want timestamp in the past", parsedNA)
					}
				}
			}
		})
	}
}
