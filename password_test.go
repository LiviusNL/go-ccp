package ccp

import (
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"testing"

	"github.com/liviusnl/go-ccp/ccptest"
)

// TestAuthenticationRequest test authentcation with different client side certificates
func TestAuthenticationRequest(t *testing.T) {
	var tests = []struct {
		applicationID string
		clientCertID  string
		valid1        bool // Client created
		valid2        bool // CCP Request technical succeeded
		valid3        bool // CCP Request logical succeeded
	}{
		{"MyApp", "MyApp", true, true, true},
		{"MyApp", "OtherApp", true, true, false},
		{"MyApp", "", true, true, false},
	}
	ts := ccptest.NewCCPServer()
	defer ts.Close()

	for _, test := range tests {
		conf := &Config{
			Host:          ts.Host,
			ApplicationID: test.applicationID,
			RootCAs:       x509.NewCertPool(),
		}
		conf.RootCAs.AppendCertsFromPEM(ts.ServerRootCA())
		cert, _ := tls.X509KeyPair(ts.ClientCertificate(test.clientCertID))
		conf.ClientCertificate = &cert

		tc, err := NewClient(conf)
		if (err == nil) != test.valid1 {
			t.Errorf("fail %v: %v", test, err)
		}

		var v url.Values
		_, logicalError, err := tc.ccpRequest(&v)
		defer tc.Close()
		if (err == nil) != test.valid2 {
			t.Errorf("fail %v: %v", test, err)
		}
		if (logicalError == "") != test.valid3 {
			t.Errorf("fail %v: %v", test, logicalError)
		}
	}
}

// TestRequest test password requests
func TestRequest(t *testing.T) {
	applicationID := "MyApp"
	var tests = []struct {
		Safe   string
		Folder string
		Object string
		valid2 bool // CCP Request technical succeeded
		valid3 bool // CCP Request logical succeeded
	}{
		{"MySafe", "", "MyObject", true, true},
		{"MySafe", "MyFolder", "MyObject", true, true},
		{"OtherSafe", "OtherFolder", "OtherObject", true, false},
	}
	ts := ccptest.NewCCPServer()
	defer ts.Close()

	conf := &Config{
		Host:          ts.Host,
		ApplicationID: applicationID,
		RootCAs:       x509.NewCertPool(),
	}
	conf.RootCAs.AppendCertsFromPEM(ts.ServerRootCA())
	cert, _ := tls.X509KeyPair(ts.ClientCertificate(applicationID))
	conf.ClientCertificate = &cert

	tc, err := NewClient(conf)
	if err != nil {
		t.Errorf("fail: %v", err)
	}

	for _, test := range tests {
		_, logicalError, err := tc.Request(&PasswordRequest{
			Safe:   test.Safe,
			Folder: test.Folder,
			Object: test.Object,
		})
		if (err == nil) != test.valid2 {
			t.Errorf("fail %v: %v", test, err)
		}
		if (logicalError == "") != test.valid3 {
			t.Errorf("fail %v: %v", test, logicalError)
		}
	}
}

func TestQuery(t *testing.T) {
	applicationID := "MyApp"
	var tests = []struct {
		Safe     string
		UserName string
		valid2   bool // CCP Request technical succeeded
		valid3   bool // CCP Request logical succeeded
	}{
		{"MySafe", "MyUser", true, true},
		{"MySafe", "MyOtherUser", true, true},
	}
	ts := ccptest.NewCCPServer()
	defer ts.Close()

	conf := &Config{
		Host:          ts.Host,
		ApplicationID: applicationID,
		RootCAs:       x509.NewCertPool(),
	}
	conf.RootCAs.AppendCertsFromPEM(ts.ServerRootCA())
	cert, _ := tls.X509KeyPair(ts.ClientCertificate(applicationID))
	conf.ClientCertificate = &cert

	tc, err := NewClient(conf)
	if err != nil {
		t.Errorf("fail: %v", err)
	}

	for _, test := range tests {
		_, logicalError, err := tc.Query(&PasswordRequest{
			Safe:   test.Safe,
			Folder: test.UserName,
		}, QueryFormatExact)
		if (err == nil) != test.valid2 {
			t.Errorf("fail %v: %v", test, err)
		}
		if (logicalError == "") != test.valid3 {
			t.Errorf("fail %v: %v", test, logicalError)
		}
	}
}
