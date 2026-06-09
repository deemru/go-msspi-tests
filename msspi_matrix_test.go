//go:build msspi
// +build msspi

// Package msspitests exercises the CryptoPro Go fork's built-in go-msspi TLS
// stack (GOST cipher suites via CryptoPro CSP) end to end.
//
// Most tests are hermetic: they stand up a TLS echo server and connect to it
// over loopback, using the two certificates issued into the CSP store by the
// base image (a server certificate, CN=127.0.0.1, serverAuth, and a client
// certificate, CN=msspi-client, clientAuth). The certificate paths come from
// the environment (see certPath); the private keys live in CSP key containers,
// so a certificate is loaded by passing the same file as both cert and key,
// which is what triggers the fork's msspi X509KeyPair path.
//
// The external interop test against gost.cryptopro.ru is opt-in (MSSPI_EXTERNAL).
package msspitests

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	serverCN = "127.0.0.1"
	clientCN = "msspi-client"
)

// certPath resolves a certificate file path from the first set environment
// variable, falling back to a default. The base image exports CSP_SERVER_CERT
// and CSP_CLIENT_CERT; the test image additionally exports MSSPI_SERVER_CERT.
func certPath(fallback string, envs ...string) string {
	for _, env := range envs {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	return fallback
}

func serverGostCert() string { return certPath("server_gost.cer", "CSP_SERVER_GOST_CERT") }
func clientGostCert() string { return certPath("client_gost.cer", "CSP_CLIENT_GOST_CERT") }
func serverRsaCert() string  { return certPath("server_rsa.cer", "CSP_SERVER_RSA_CERT") }
func clientRsaCert() string  { return certPath("client_rsa.cer", "CSP_CLIENT_RSA_CERT") }

// loadCert loads a certificate whose private key lives in a CSP container.
// Passing the same path as cert and key makes the bytes identical, which is the
// signal the fork uses to take the msspi key-pair path instead of parsing a PEM
// private key.
func loadCert(t testing.TB, path string) tls.Certificate {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Skipf("certificate %q is not available; run this matrix with CSP test certificates", path)
		}
		t.Fatalf("stat %q: %v", path, err)
	}
	cert, err := tls.LoadX509KeyPair(path, path)
	if err != nil {
		t.Fatalf("LoadX509KeyPair(%q): %v", path, err)
	}
	return cert
}

func serverConfig(t testing.TB, clientAuth tls.ClientAuthType) *tls.Config {
	t.Helper()
	return &tls.Config{
		Certificates: []tls.Certificate{loadCert(t, serverGostCert())},
		ClientAuth:   clientAuth,
	}
}

// clientConfig builds a client config. withCert presents the client certificate
// (mutual TLS); verify enables peer verification (otherwise InsecureSkipVerify).
func clientConfig(t testing.TB, withCert, verify bool) *tls.Config {
	t.Helper()
	cfg := &tls.Config{
		ServerName:         serverCN,
		InsecureSkipVerify: !verify,
	}
	if withCert {
		cfg.Certificates = []tls.Certificate{loadCert(t, clientGostCert())}
	}
	return cfg
}

// connInfo carries a server-side accepted connection's handshake outcome.
type connInfo struct {
	state tls.ConnectionState
	err   error
}

// echoServer starts a TLS echo server on loopback. It returns the listen
// address and a channel that yields, per accepted connection, the server-side
// handshake result. After a successful handshake the connection echoes bytes
// until closed. The listener is closed via t.Cleanup.
func echoServer(t testing.TB, cfg *tls.Config) (string, <-chan connInfo) {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	infos := make(chan connInfo, 64)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go func() {
				defer conn.Close()
				tc := conn.(*tls.Conn)
				if err := tc.Handshake(); err != nil {
					infos <- connInfo{err: err}
					return
				}
				infos <- connInfo{state: tc.ConnectionState()}
				io.Copy(tc, tc)
			}()
		}
	}()
	return ln.Addr().String(), infos
}

// dial establishes a TLS connection and completes the handshake.
func dial(t testing.TB, addr string, cfg *tls.Config) *tls.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	tc := tls.Client(conn, cfg)
	if err := tc.Handshake(); err != nil {
		tc.Close()
		t.Fatalf("client handshake: %v", err)
	}
	t.Cleanup(func() { tc.Close() })
	return tc
}

// roundtrip writes payload and reads exactly len(payload) bytes back. A write
// error is left to surface as a read failure, so the writer goroutine never
// touches t (which would panic once the test has returned).
func roundtrip(t testing.TB, conn net.Conn, payload []byte) []byte {
	t.Helper()
	go func() { _, _ = conn.Write(payload) }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	return got
}

func peerCN(state tls.ConnectionState) string {
	if len(state.PeerCertificates) == 0 {
		return ""
	}
	return state.PeerCertificates[0].Subject.CommonName
}

func awaitServer(t testing.TB, infos <-chan connInfo) connInfo {
	t.Helper()
	select {
	case info := <-infos:
		return info
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for server-side handshake")
		return connInfo{}
	}
}

// TestOneWayTLS is the basic case: the server presents a certificate, the client
// presents none and skips verification.
func TestOneWayTLS(t *testing.T) {
	addr, infos := echoServer(t, serverConfig(t, tls.NoClientCert))
	conn := dial(t, addr, clientConfig(t, false, false))

	if got := string(roundtrip(t, conn, []byte("ping"))); got != "ping" {
		t.Fatalf("echo mismatch: %q", got)
	}
	if cn := peerCN(conn.ConnectionState()); cn != serverCN {
		t.Fatalf("client saw server CN %q, want %q", cn, serverCN)
	}
	if info := awaitServer(t, infos); info.err != nil {
		t.Fatalf("server handshake: %v", info.err)
	} else if len(info.state.PeerCertificates) != 0 {
		t.Fatalf("server unexpectedly received a client certificate")
	}
}

// TestMutualTLS exercises mutual TLS: both peers present a certificate. The
// server requires (but does not chain-verify) a client certificate; each side
// must observe the other's certificate.
func TestMutualTLS(t *testing.T) {
	addr, infos := echoServer(t, serverConfig(t, tls.RequireAnyClientCert))
	conn := dial(t, addr, clientConfig(t, true, false))

	if got := string(roundtrip(t, conn, []byte("mtls"))); got != "mtls" {
		t.Fatalf("echo mismatch: %q", got)
	}
	if cn := peerCN(conn.ConnectionState()); cn != serverCN {
		t.Fatalf("client saw server CN %q, want %q", cn, serverCN)
	}

	info := awaitServer(t, infos)
	if info.err != nil {
		t.Fatalf("server handshake: %v", info.err)
	}
	if cn := peerCN(info.state); cn != clientCN {
		t.Fatalf("server saw client CN %q, want %q", cn, clientCN)
	}
}

// TestMutualTLSVerified additionally verifies the peer certificate chains on
// both sides (RequireAndVerifyClientCert + client-side verification), which
// relies on the issuing CA being trusted in the CSP store.
func TestMutualTLSVerified(t *testing.T) {
	addr, infos := echoServer(t, serverConfig(t, tls.RequireAndVerifyClientCert))
	conn := dial(t, addr, clientConfig(t, true, true))

	if got := string(roundtrip(t, conn, []byte("verified"))); got != "verified" {
		t.Fatalf("echo mismatch: %q", got)
	}
	if info := awaitServer(t, infos); info.err != nil {
		t.Fatalf("server handshake (verified): %v", info.err)
	}
}

// TestClientCertRequiredMissing checks that a server requiring a client
// certificate rejects a client that presents none. Unlike stdlib TLS (which
// fails the handshake with an alert), msspi completes the SChannel handshake and
// enforces the requirement server-side afterwards, so the client may observe a
// successful handshake; the invariant is therefore asserted on the server.
func TestClientCertRequiredMissing(t *testing.T) {
	addr, infos := echoServer(t, serverConfig(t, tls.RequireAnyClientCert))

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	tc := tls.Client(conn, clientConfig(t, false, false))
	defer tc.Close()
	_ = tc.Handshake() // client may succeed; the server enforces the requirement

	if info := awaitServer(t, infos); info.err == nil {
		t.Fatal("server accepted a connection without the required client certificate")
	}
}

// TestVerifyPeerCertificateHonored confirms the msspi path actually invokes the
// configured VerifyPeerCertificate hook with the server certificate.
func TestVerifyPeerCertificateHonored(t *testing.T) {
	addr, _ := echoServer(t, serverConfig(t, tls.NoClientCert))

	var gotCN string
	cfg := clientConfig(t, false, false)
	cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("no server certificate")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		gotCN = cert.Subject.CommonName
		return nil
	}

	dial(t, addr, cfg)
	if gotCN != serverCN {
		t.Fatalf("VerifyPeerCertificate saw CN %q, want %q (or was not called)", gotCN, serverCN)
	}
}

// TestClientCertNotSentToRejectedServer is the privacy-critical case: a client
// with a certificate connects to a server it rejects (the rejection is injected
// via VerifyPeerCertificate). The handshake must abort before the client
// certificate is presented, so the client identity is never revealed to the
// untrusted server.
func TestClientCertNotSentToRejectedServer(t *testing.T) {
	addr, infos := echoServer(t, serverConfig(t, tls.RequireAnyClientCert))

	cfg := clientConfig(t, true, false) // present client cert, skip CSP verification
	cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("no server certificate")
		}
		return errors.New("test: reject server")
	}

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	tc := tls.Client(conn, cfg)
	defer tc.Close()

	err = tc.Handshake()
	if err == nil {
		t.Fatal("handshake succeeded despite a rejected server certificate")
	}
	if !strings.Contains(err.Error(), "reject server") {
		t.Fatalf("handshake error %q does not carry the rejection reason", err)
	}

	// The server must not have completed a handshake that received the client
	// certificate: the client aborted before presenting it.
	select {
	case info := <-infos:
		if info.err == nil && len(info.state.PeerCertificates) != 0 {
			t.Fatal("client certificate leaked to a server the client rejected")
		}
	case <-time.After(2 * time.Second):
		// no server-side handshake completed — also acceptable
	}
}

// TestMsspiIgnoredVerifyStatus checks that a CSP verification failure surfaces as
// a typed *tls.MsspiVerifyError carrying the specific status code, and that
// listing that code in Config.MsspiIgnoredVerifyStatuses accepts the peer.
func TestMsspiIgnoredVerifyStatus(t *testing.T) {
	addr, _ := echoServer(t, serverConfig(t, tls.NoClientCert))

	// Verification on, but with a server name the certificate cannot match, so
	// the CSP rejects it. Capture the specific status.
	bad := clientConfig(t, false, true)
	bad.ServerName = "wrong.invalid"
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	tc := tls.Client(conn, bad)
	err = tc.Handshake()
	tc.Close()
	conn.Close()

	var ve *tls.MsspiVerifyError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *tls.MsspiVerifyError, got %v", err)
	}
	t.Logf("verification rejected: %v", ve)

	// Ignoring that exact status lets the same connection through.
	ok := clientConfig(t, false, true)
	ok.ServerName = "wrong.invalid"
	ok.MsspiIgnoredVerifyStatuses = []uint32{ve.Status}
	dial(t, addr, ok)
}

// generateRSACert builds a self-signed RSA certificate in process (no CSP, no
// openssl), for exercising the standard Go TLS stack.
func generateRSACert(t testing.TB) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: serverCN},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP(serverCN)},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestStandardTLSFallback checks that MsspiByCertOnly makes a connection with an
// ordinary (non-CSP) certificate fall back to the standard Go TLS stack,
// negotiating a non-GOST cipher suite.
func TestStandardTLSFallback(t *testing.T) {
	serverCfg := &tls.Config{
		Certificates:    []tls.Certificate{generateRSACert(t)},
		MsspiByCertOnly: true,
	}
	addr, _ := echoServer(t, serverCfg)

	clientCfg := &tls.Config{
		ServerName:         serverCN,
		InsecureSkipVerify: true,
		MsspiByCertOnly:    true,
	}
	conn := dial(t, addr, clientCfg)

	if got := string(roundtrip(t, conn, []byte("std"))); got != "std" {
		t.Fatalf("echo mismatch: %q", got)
	}

	state := conn.ConnectionState()
	name := tls.CipherSuiteName(state.CipherSuite)
	t.Logf("standard TLS: version=0x%04x cipher=%s", state.Version, name)
	// A GOST suite is unknown to crypto/tls and renders as "0x....".
	if name == "" || strings.HasPrefix(name, "0x") {
		t.Fatalf("expected a standard (named) cipher suite, got %q", name)
	}
}

// assertNonGOST checks a connection state reports a standard (non-GOST) cipher
// suite — one crypto/tls names. GOST suites render as "0x....".
func assertNonGOST(t *testing.T, state tls.ConnectionState) {
	t.Helper()
	name := tls.CipherSuiteName(state.CipherSuite)
	t.Logf("negotiated version=0x%04x cipher=%s", state.Version, name)
	if name == "" || strings.HasPrefix(name, "0x") {
		t.Fatalf("expected a standard (non-GOST) cipher suite, got %q", name)
	}
}

// TestCrossMsspiServerGoClient: an msspi server presenting an RSA certificate
// (the CSP RSA provider, provtype 24) interoperates with a standard Go client.
func TestCrossMsspiServerGoClient(t *testing.T) {
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{loadCert(t, serverRsaCert())}, // msspi, RSA in CSP
	}
	addr, _ := echoServer(t, serverCfg)

	clientCfg := &tls.Config{
		ServerName:         serverCN,
		InsecureSkipVerify: true,
		MsspiByCertOnly:    true, // standard Go client
	}
	conn := dial(t, addr, clientCfg)
	if got := string(roundtrip(t, conn, []byte("msspi->go"))); got != "msspi->go" {
		t.Fatalf("echo mismatch: %q", got)
	}
	assertNonGOST(t, conn.ConnectionState())
}

// TestCrossGoServerMsspiClient: a standard Go server interoperates with an msspi
// client, which offers RSA suites alongside GOST.
func TestCrossGoServerMsspiClient(t *testing.T) {
	serverCfg := &tls.Config{
		Certificates:    []tls.Certificate{generateRSACert(t)},
		MsspiByCertOnly: true, // standard Go server
	}
	addr, infos := echoServer(t, serverCfg)

	clientCfg := &tls.Config{
		ServerName:         serverCN,
		InsecureSkipVerify: true, // msspi client (default); Go cert isn't in the CSP store
	}
	conn := dial(t, addr, clientCfg)
	if got := string(roundtrip(t, conn, []byte("go->msspi"))); got != "go->msspi" {
		t.Fatalf("echo mismatch: %q", got)
	}
	info := awaitServer(t, infos)
	if info.err != nil {
		t.Fatalf("server handshake: %v", info.err)
	}
	assertNonGOST(t, info.state) // server side is standard Go: reliable state
}

// TestMsspiRSA: both peers run msspi over the CSP RSA provider (foreign crypto
// through the same stack), confirming msspi is not GOST-only.
func TestMsspiRSA(t *testing.T) {
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{loadCert(t, serverRsaCert())},
	}
	addr, _ := echoServer(t, serverCfg)

	clientCfg := &tls.Config{
		ServerName:         serverCN,
		InsecureSkipVerify: true,
	}
	conn := dial(t, addr, clientCfg)
	if got := string(roundtrip(t, conn, []byte("rsa"))); got != "rsa" {
		t.Fatalf("echo mismatch: %q", got)
	}
	state := conn.ConnectionState()
	t.Logf("msspi RSA: version=0x%04x cipher=0x%04x", state.Version, state.CipherSuite)
}

// mutualCheck asserts a mutual-TLS handshake completed: data echoes and each
// side received the other's certificate.
func mutualCheck(t *testing.T, conn *tls.Conn, infos <-chan connInfo, payload string) {
	t.Helper()
	info := awaitServer(t, infos)
	if info.err != nil {
		t.Fatalf("server handshake: %v", info.err)
	}
	if len(info.state.PeerCertificates) == 0 {
		t.Fatal("server did not receive the client certificate")
	}
	if len(conn.ConnectionState().PeerCertificates) == 0 {
		t.Fatal("client did not receive the server certificate")
	}
	if got := string(roundtrip(t, conn, []byte(payload))); got != payload {
		t.Fatalf("echo mismatch: %q", got)
	}
}

// TestMutualMsspiRSA: mutual TLS with both peers on msspi over RSA.
func TestMutualMsspiRSA(t *testing.T) {
	addr, infos := echoServer(t, &tls.Config{
		Certificates: []tls.Certificate{loadCert(t, serverRsaCert())},
		ClientAuth:   tls.RequireAnyClientCert,
	})
	clientCfg := &tls.Config{
		ServerName:         serverCN,
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{loadCert(t, clientRsaCert())},
	}
	mutualCheck(t, dial(t, addr, clientCfg), infos, "mtls-msspi")
}

// TestMutualCrossMsspiServerGoClient: mutual TLS, msspi (RSA) server and a
// standard Go client presenting a Go-issued RSA certificate.
func TestMutualCrossMsspiServerGoClient(t *testing.T) {
	addr, infos := echoServer(t, &tls.Config{
		Certificates: []tls.Certificate{loadCert(t, serverRsaCert())},
		ClientAuth:   tls.RequireAnyClientCert,
	})
	goCert := generateRSACert(t)
	clientCfg := &tls.Config{
		ServerName:         serverCN,
		InsecureSkipVerify: true,
		MsspiByCertOnly:    true,
		// The msspi server advertises its trusted CAs in the CertificateRequest;
		// force the Go client to present its certificate regardless, so the
		// exchange is exercised even with a self-signed certificate.
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &goCert, nil
		},
	}
	mutualCheck(t, dial(t, addr, clientCfg), infos, "mtls-m2g")
}

// TestMutualCrossGoServerMsspiClient: mutual TLS, standard Go server and an msspi
// client presenting its CSP RSA certificate.
func TestMutualCrossGoServerMsspiClient(t *testing.T) {
	addr, infos := echoServer(t, &tls.Config{
		Certificates:    []tls.Certificate{generateRSACert(t)},
		ClientAuth:      tls.RequireAnyClientCert,
		MsspiByCertOnly: true,
	})
	clientCfg := &tls.Config{
		ServerName:         serverCN,
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{loadCert(t, clientRsaCert())},
	}
	mutualCheck(t, dial(t, addr, clientCfg), infos, "mtls-g2m")
}

// TestMutualGoRSA: mutual TLS with both peers on the standard Go stack.
func TestMutualGoRSA(t *testing.T) {
	addr, infos := echoServer(t, &tls.Config{
		Certificates:    []tls.Certificate{generateRSACert(t)},
		ClientAuth:      tls.RequireAnyClientCert,
		MsspiByCertOnly: true,
	})
	clientCfg := &tls.Config{
		ServerName:         serverCN,
		InsecureSkipVerify: true,
		MsspiByCertOnly:    true,
		Certificates:       []tls.Certificate{generateRSACert(t)},
	}
	mutualCheck(t, dial(t, addr, clientCfg), infos, "mtls-go")
}

// TestConnectionState verifies that a completed handshake reports a sane TLS
// version, a (GOST) cipher suite, the requested server name and the peer chain.
func TestConnectionState(t *testing.T) {
	addr, _ := echoServer(t, serverConfig(t, tls.NoClientCert))
	state := dial(t, addr, clientConfig(t, false, false)).ConnectionState()

	switch state.Version {
	case tls.VersionTLS12, tls.VersionTLS13:
	default:
		t.Fatalf("unexpected TLS version 0x%04x", state.Version)
	}
	if state.CipherSuite == 0 {
		t.Fatal("cipher suite is zero")
	}
	if state.ServerName != serverCN {
		t.Fatalf("server name %q, want %q", state.ServerName, serverCN)
	}
	if len(state.PeerCertificates) == 0 {
		t.Fatal("no peer certificates")
	}
	t.Logf("version=0x%04x cipher=0x%04x peerCN=%q", state.Version, state.CipherSuite, peerCN(state))
}

// TestDataIntegrity streams a large random payload through the echo server and
// checks it returns byte-for-byte.
func TestDataIntegrity(t *testing.T) {
	addr, _ := echoServer(t, serverConfig(t, tls.NoClientCert))
	conn := dial(t, addr, clientConfig(t, false, false))

	const size = 4 << 20 // 4 MiB, well past a single TLS record
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		done <- err
	}()

	got := make([]byte, size)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(payload, got) {
		t.Fatal("payload corrupted in transit")
	}
}

// TestFullDuplex drives reads and writes on the same connection concurrently,
// exercising the single-handle read/write path under contention.
func TestFullDuplex(t *testing.T) {
	addr, _ := echoServer(t, serverConfig(t, tls.NoClientCert))
	conn := dial(t, addr, clientConfig(t, false, false))

	const chunks = 256
	const chunkSize = 16 << 10

	var wg sync.WaitGroup
	wg.Add(2)

	go func() { // writer
		defer wg.Done()
		buf := make([]byte, chunkSize)
		for i := 0; i < chunks; i++ {
			buf[0] = byte(i)
			if _, err := conn.Write(buf); err != nil {
				t.Errorf("write chunk %d: %v", i, err)
				return
			}
		}
	}()

	go func() { // reader
		defer wg.Done()
		buf := make([]byte, chunkSize)
		for i := 0; i < chunks; i++ {
			if _, err := io.ReadFull(conn, buf); err != nil {
				t.Errorf("read chunk %d: %v", i, err)
				return
			}
			if buf[0] != byte(i) {
				t.Errorf("chunk %d out of order: marker %d", i, buf[0])
				return
			}
		}
	}()

	wg.Wait()
}

// TestConcurrentConnections opens many independent connections in parallel.
func TestConcurrentConnections(t *testing.T) {
	addr, _ := echoServer(t, serverConfig(t, tls.NoClientCert))

	const n = 32
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				t.Errorf("dial %d: %v", i, err)
				return
			}
			defer conn.Close()
			tc := tls.Client(conn, clientConfig(t, false, false))
			defer tc.Close()

			msg := []byte(fmt.Sprintf("conn-%d", i))
			if _, err := tc.Write(msg); err != nil {
				t.Errorf("write %d: %v", i, err)
				return
			}
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(tc, got); err != nil {
				t.Errorf("read %d: %v", i, err)
				return
			}
			if !bytes.Equal(msg, got) {
				t.Errorf("conn %d echo mismatch: %q", i, got)
			}
		}(i)
	}
	wg.Wait()
}

// TestExternalGOST is an opt-in interop check against a public GOST endpoint.
func TestExternalGOST(t *testing.T) {
	if os.Getenv("MSSPI_EXTERNAL") == "" {
		t.Skip("set MSSPI_EXTERNAL=1 to run the gost.cryptopro.ru interop test")
	}

	conn, err := net.DialTimeout("tcp", "gost.cryptopro.ru:443", 10*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	tc := tls.Client(conn, &tls.Config{ServerName: "gost.cryptopro.ru", InsecureSkipVerify: true})
	defer tc.Close()
	if err := tc.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	req := "GET / HTTP/1.1\r\nHost: gost.cryptopro.ru\r\nConnection: close\r\n\r\n"
	if _, err := tc.Write([]byte(req)); err != nil {
		t.Fatalf("write: %v", err)
	}

	body, err := io.ReadAll(tc)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("read: %v", err)
	}
	const ms, me = `ssl_cipher</td><td class="wr"><b>`, "</b>"
	s := string(body)
	cipher := ""
	if i := strings.Index(s, ms); i != -1 {
		if j := strings.Index(s[i+len(ms):], me); j != -1 {
			cipher = s[i+len(ms) : i+len(ms)+j]
		}
	}
	t.Logf("server-reported cipher: %q; ConnectionState: version=0x%04x cipher=0x%04x",
		cipher, tc.ConnectionState().Version, tc.ConnectionState().CipherSuite)
	if cipher == "" {
		t.Fatalf("could not read the server-reported cipher from the response")
	}
	// the msspi client must negotiate GOST with the GOST endpoint; a standard
	// suite here means the CSP GOST provider wasn't actually used.
	if !strings.Contains(strings.ToUpper(cipher), "GOST") {
		t.Fatalf("expected a GOST cipher from the msspi client, got %q", cipher)
	}
}

// TestExternalStandard connects to a public GOST-capable endpoint with the
// standard Go TLS stack (MsspiByCertOnly, no CSP certificate) and expects a
// non-GOST cipher suite — i.e. the standard stack and a real server interoperate
// outside msspi.
func TestExternalStandard(t *testing.T) {
	if os.Getenv("MSSPI_EXTERNAL") == "" {
		t.Skip("set MSSPI_EXTERNAL=1 to run the gost.cryptopro.ru interop test")
	}

	conn, err := net.DialTimeout("tcp", "gost.cryptopro.ru:443", 10*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	tc := tls.Client(conn, &tls.Config{
		ServerName:         "gost.cryptopro.ru",
		InsecureSkipVerify: true,
		MsspiByCertOnly:    true,
	})
	defer tc.Close()
	if err := tc.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	state := tc.ConnectionState()
	name := tls.CipherSuiteName(state.CipherSuite)
	t.Logf("standard stack negotiated: version=0x%04x cipher=%s", state.Version, name)
	if name == "" || strings.HasPrefix(name, "0x") {
		t.Fatalf("expected a standard (named) cipher suite, got %q", name)
	}
}

// BenchmarkHandshake measures full TLS handshakes per second (dial, handshake,
// close) against the loopback echo server.
func BenchmarkHandshake(b *testing.B) {
	addr, _ := echoServer(b, serverConfig(b, tls.NoClientCert))
	cfg := clientConfig(b, false, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			b.Fatalf("dial: %v", err)
		}
		tc := tls.Client(conn, cfg)
		if err := tc.Handshake(); err != nil {
			b.Fatalf("handshake: %v", err)
		}
		tc.Close()
	}
}

// BenchmarkThroughput measures application-data throughput over an established
// connection (write a chunk, read it echoed back).
func BenchmarkThroughput(b *testing.B) {
	addr, _ := echoServer(b, serverConfig(b, tls.NoClientCert))
	conn := dial(b, addr, clientConfig(b, false, false))

	const chunk = 64 << 10
	payload := make([]byte, chunk)
	got := make([]byte, chunk)

	b.SetBytes(chunk)
	b.ResetTimer()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < b.N; i++ {
			if _, err := conn.Write(payload); err != nil {
				return
			}
		}
	}()

	for i := 0; i < b.N; i++ {
		if _, err := io.ReadFull(conn, got); err != nil {
			b.Fatalf("read: %v", err)
		}
	}
	<-done
}
