package scanner

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"
)

type tlsMetaData struct {
	Version      string
	CipherSuite  string
	NotBefore    string
	NotAfter     string
	CertVerified bool
}

var allSupportedCipherSuites = func() []uint16 {
	var ids []uint16
	for _, cs := range tls.CipherSuites() {
		ids = append(ids, cs.ID)
	}
	for _, cs := range tls.InsecureCipherSuites() {
		ids = append(ids, cs.ID)
	}
	return ids
}()

// customRootCAPool allows unit tests to inject mock root CAs without touching host trust stores.
var customRootCAPool *x509.CertPool

// probeTLS wraps an open TCP connection, attempts a handshake with InsecureSkipVerify: true,
// and extracts negotiated parameters and certificate metadata.
func probeTLS(conn net.Conn, targetName string, timeout time.Duration) tlsMetaData {

	// Step 4: Enforce socket deadline and execute non-fatal handshake
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return tlsMetaData{}
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         targetName,
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       allSupportedCipherSuites,
	}

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		// Non-Fatal Invariant: Plaintext or stalled ports return empty metadata
		return tlsMetaData{}
	}

	// Step 5: Extract connection state and canonical IANA names
	state := tlsConn.ConnectionState()
	versionStr := tls.VersionName(state.Version)
	cipherSuiteStr := tls.CipherSuiteName(state.CipherSuite)

	// Step 6: Out-of-band X.509 verification and timestamp extraction
	if len(state.PeerCertificates) <= 0 {
		return tlsMetaData{
			Version:      versionStr,
			CipherSuite:  cipherSuiteStr,
			NotBefore:    "",
			NotAfter:     "",
			CertVerified: false,
		}
	}

	leaf := state.PeerCertificates[0]

	notBefore := leaf.NotBefore.UTC().Format(time.RFC3339)
	notAfter := leaf.NotAfter.UTC().Format(time.RFC3339)

	opts := x509.VerifyOptions{
		DNSName:     targetName,
		Roots:       customRootCAPool,
		CurrentTime: time.Now(),
	}

	_, verifyErr := leaf.Verify(opts)
	verified := (verifyErr == nil)

	return tlsMetaData{
		Version:      versionStr,
		CipherSuite:  cipherSuiteStr,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		CertVerified: verified,
	}
}
