package ccp

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/liviusnl/go-ccp/internal"
)

//
// Server Certificate Validation
// 		Testing TLS Server uses self signed certificates
//

// Create TLS Connection, validate connection using custom Root Certificate
func TestTLSConnection1(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, client")
	}))
	defer ts.Close()

	hostname, err := url.Parse(ts.URL)
	if err != nil {
		t.Errorf("unable to parse utl: %v: %v", ts.URL, err)
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ts.Certificate().Raw,
	}))

	tc, err := NewClient(&Config{
		Hostname:      hostname.Host,
		ApplicationID: "MyApp",
		RootCAs:       rootCAs,
	})
	if err != nil {
		t.Errorf("unable to initialize CCP Client: %v", err)
	}

	_, err = tc.config.HTTPClient.Get(fmt.Sprintf("https://%v", tc.config.Hostname))
	if err != nil {
		t.Errorf("server certificate validation failed: %v", err)
	}
}

// Create TLS Connection, skip connection validation, i.e. not using system Root Certificates
func TestTLSConnection2(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, client")
	}))
	defer ts.Close()

	hostname, err := url.Parse(ts.URL)
	if err != nil {
		t.Errorf("unable to parse utl: %v: %v", ts.URL, err)
	}

	tc, err := NewClient(&Config{
		Hostname:      hostname.Host,
		ApplicationID: "MyApp",
		SkipTLSVerify: true,
	})
	if err != nil {
		t.Errorf("unable to initialize CCP Client: %v", err)
	}

	_, err = tc.config.HTTPClient.Get(fmt.Sprintf("https://%v", tc.config.Hostname))
	if err != nil {
		t.Errorf("skip server certificate validation failed: %v", err)
	}
}

// Create TLS Connection, validate connection using system Root Certificates
func TestTLSConnection3(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, client")
	}))
	defer ts.Close()

	hostname, err := url.Parse(ts.URL)
	if err != nil {
		t.Errorf("unable to parse utl: %v: %v", ts.URL, err)
	}

	tc, err := NewClient(&Config{
		Hostname:      hostname.Host,
		ApplicationID: "MyApp",
	})
	if err != nil {
		t.Errorf("unable to initialize CCP Client: %v", err)
	}

	_, err = tc.config.HTTPClient.Get(fmt.Sprintf("https://%v", tc.config.Hostname))
	if err == nil {
		t.Error("server certificate validation should fail, no custom CA provided.")
	}
}

//
// Client Certificate Validation
//

// Server require a client certificate
func TestClientCertConnection1(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, client")
	}))
	ts.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	ts.StartTLS()
	defer ts.Close()

	hostname, err := url.Parse(ts.URL)
	if err != nil {
		t.Errorf("unable to parse utl: %v: %v", ts.URL, err)
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ts.Certificate().Raw,
	}))

	tc, err := NewClient(&Config{
		Hostname:      hostname.Host,
		ApplicationID: "MyApp",
		RootCAs:       rootCAs,
	})
	if err != nil {
		t.Errorf("unable to initialize CCP Client: %v", err)
	}

	_, err = tc.config.HTTPClient.Get(fmt.Sprintf("https://%v", tc.config.Hostname))
	if err == nil {
		t.Errorf("client certificate validation should fail, no certifcate presented")
	}
}

// Provide Client Certificate, Client Certifcate Key , server checks Certficate
func TestClientCertConnection2(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, client")
	}))
	ca, err := internal.NewCA()
	if err != nil {
		t.Errorf("unable to create CA: %v", err)
	}
	ts.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  x509.NewCertPool(),
	}
	ts.TLS.ClientCAs.AddCert(ca.Certificate)
	ts.StartTLS()
	defer ts.Close()

	hostname, err := url.Parse(ts.URL)
	if err != nil {
		t.Errorf("unable to parse utl: %v: %v", ts.URL, err)
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ts.Certificate().Raw,
	}))
	clientCertPEM, clientCertKeyPEM, err := ca.NewClientCert("client.eample.com")
	clientCert, err := tls.X509KeyPair(clientCertPEM, clientCertKeyPEM)
	tc, err := NewClient(&Config{
		Hostname:      hostname.Host,
		ApplicationID: "MyApp",
		Certificate:   &clientCert,
		RootCAs:       rootCAs,
	})
	if err != nil {
		t.Errorf("unable to initialize CCP Client: %v", err)
	}

	_, err = tc.config.HTTPClient.Get(fmt.Sprintf("https://%v", tc.config.Hostname))
	if err != nil {
		t.Errorf("REST call failed: %v", err)
	}
}
