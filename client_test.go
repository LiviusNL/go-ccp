package ccp

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/liviusnl/go-ccp/ccptest"
)

// TestClient test the creation of the CCP client
func TestClient(t *testing.T) {
	var tests = []struct {
		host          string
		applicationID string
		valid         bool
	}{
		{"", "", false},
		{"", "AcmeApp", false},

		{"ccp.acme.com", "", false},
		{"ccp.acme.com", "AcmeApp", true},
	}

	for _, test := range tests {
		_, err := NewClient(&Config{
			Host:          test.host,
			ApplicationID: test.applicationID,
		})
		if (err == nil) != test.valid {
			t.Errorf("fail %v: %v", test, err)
		}
	}
}

// TestHost tests modifications to the client Host
func TestHost(t *testing.T) {
	var tests = []struct {
		host          string
		applicationID string
		setHost       bool // false, i.e newHost = ""
		newHost       string
		valid1        bool // Client created
		valid2        bool // Update succeeded
		valid3        bool // Original host stored
		valid4        bool // New host stored
	}{
		{"ccp.acme.com", "AcmeApp", false, "", true, true, true, false},
		{"ccp.acme.com", "AcmeApp", true, "", true, false, true, false},
		{"ccp.acme.com", "AcmeApp", true, "ccp.example.com", true, true, false, true},
	}

	for _, test := range tests {
		c, err := NewClient(&Config{
			Host:          test.host,
			ApplicationID: test.applicationID,
		})
		if (err == nil) != test.valid1 {
			t.Errorf("fail %v: %v", test, err)
		}

		if c != nil {
			if test.setHost {
				err = c.SetHost(test.newHost)
				if (err == nil) != test.valid2 {
					t.Errorf("fail %v: %v", test, err)
				}
			}

			if (test.host == c.Host()) != test.valid3 {
				t.Errorf("fail %v", test)
			}
			if (test.newHost == c.Host()) != test.valid4 {
				t.Errorf("fail %v", test)
			}
		}
	}
}

// TestConnectionTimeout tests modifications to the client ConnectionTimeout
func TestConnectionTimeout(t *testing.T) {
	var tests = []struct {
		host                 string
		applicationID        string
		initTimeout          bool // false, i.e. connectionTimeOut = 0
		connectionTimeout    int
		setConnectionTimeout bool // false, i.e. newConnectionTimeuut = 0
		newConnectionTimeout int
		valid1               bool // Client created
		valid2               bool // Update succeeded
		valid3               bool // Original connection timeout stored
		valid4               bool // New connection timeout stored
	}{
		{"ccp.acme.com", "AcmeApp", false, 0, true, -1, true, false, true, false},
		{"ccp.acme.com", "AcmeApp", false, 0, true, 0, true, true, true, true},
		{"ccp.acme.com", "AcmeApp", false, 0, true, 10, true, true, false, true},

		{"ccp.acme.com", "AcmeApp", true, -1, false, 0, false, false, false, false},

		{"ccp.acme.com", "AcmeApp", true, 0, false, 0, true, true, true, true},
		{"ccp.acme.com", "AcmeApp", true, 0, true, -1, true, false, true, false},
		{"ccp.acme.com", "AcmeApp", true, 0, true, 0, true, true, true, true},
		{"ccp.acme.com", "AcmeApp", true, 0, true, 10, true, true, false, true},

		{"ccp.acme.com", "AcmeApp", true, 10, false, 0, true, true, true, false},
		{"ccp.acme.com", "AcmeApp", true, 10, true, -1, true, false, true, false},
		{"ccp.acme.com", "AcmeApp", true, 10, true, 0, true, true, false, true},

		{"ccp.acme.com", "AcmeApp", true, 10, true, 20, true, true, false, true},
	}

	for _, test := range tests {
		conf := &Config{
			Host:          test.host,
			ApplicationID: test.applicationID,
		}
		if test.initTimeout {
			conf.ConnectionTimeout = test.connectionTimeout
		}
		c, err := NewClient(conf)
		if (err == nil) != test.valid1 {
			t.Errorf("fail %v: %v", test, err)
		}

		if c != nil {
			if test.setConnectionTimeout {
				err = c.SetConnectionTimeout(test.newConnectionTimeout)
				if (err == nil) != test.valid2 {
					t.Errorf("Fail %v: %v", test, err)
				}
			}

			if (test.connectionTimeout == c.ConnectionTimeout()) != test.valid3 {
				t.Errorf("fail %v", test)
			}
			if (test.newConnectionTimeout == c.ConnectionTimeout()) != test.valid4 {
				t.Errorf("fail %v", test)
			}
		}
	}
}

// TestFailRequestOnPasswordChange test modifications to the client FailRequestOnPasswordChange
func TestFailRequestOnPasswordChange(t *testing.T) {
	var tests = []struct {
		host                            string
		applicationID                   string
		initFailRequestOnPasswordChange bool // false, i.e. failRequestOnPasswordChange = false
		failRequestOnPasswordChange     bool
		setFailRequestOnPasswordChange  bool // false, i.e. newFailRequestOnPasswordChange
		newFailRequestOnPasswordChange  bool
		valid1                          bool // Client created
		valid3                          bool // Original fail request on password change stored
		valid4                          bool // New fail request on password change stored
	}{
		{"ccp.acme.com", "AcmeApp", false, false, false, false, true, true, true},
		{"ccp.acme.com", "AcmeApp", false, false, true, false, true, true, true},
		{"ccp.acme.com", "AcmeApp", false, false, true, true, true, false, true},

		{"ccp.acme.com", "AcmeApp", true, false, false, false, true, true, true},
		{"ccp.acme.com", "AcmeApp", true, false, true, false, true, true, true},
		{"ccp.acme.com", "AcmeApp", true, false, true, true, true, false, true},

		{"ccp.acme.com", "AcmeApp", true, true, false, false, true, true, false},
		{"ccp.acme.com", "AcmeApp", true, true, true, false, true, false, true},
		{"ccp.acme.com", "AcmeApp", true, true, true, true, true, true, true},
	}

	for _, test := range tests {
		conf := &Config{
			Host:          test.host,
			ApplicationID: test.applicationID,
		}
		if test.initFailRequestOnPasswordChange {
			conf.FailRequestOnPasswordChange = test.failRequestOnPasswordChange
		}
		c, err := NewClient(conf)
		if (err == nil) != test.valid1 {
			t.Errorf("fail %v: %v", test, err)
		}

		if c != nil {
			if test.setFailRequestOnPasswordChange {
				c.SetFailRequestOnPasswordChange(test.newFailRequestOnPasswordChange)
			}

			if (test.failRequestOnPasswordChange == c.FailRequestOnPasswordChange()) != test.valid3 {
				t.Errorf("fail %v", test)
			}
			if (test.newFailRequestOnPasswordChange == c.FailRequestOnPasswordChange()) != test.valid4 {
				t.Errorf("fail %v", test)
			}
		}
	}
}

// TestTLS tests the diffentent TLS Configurations for Server & Client validation
func TestTLS(t *testing.T) {
	var tests = []struct {
		applicationID       string
		skipTLSVerify       bool // true, i.e. rootCAs = nil
		rootCAs             *x509.CertPool
		clientUseClientCert bool
		valid1              bool // Client created
		valid2              bool // HTTP Request succeeded
		vaild2StatusCode    int  // HTTTP Status Code expected, when valid2 == true
	}{
		{"MyApp", false, nil, false, true, false, 0},
		{"MyApp", true, nil, false, true, false, 0},
		{"MyApp", false, x509.NewCertPool(), false, true, false, 0},

		{"MyApp", false, nil, true, true, false, 0},
		{"MyApp", true, nil, true, true, true, 400},
		{"MyApp", false, x509.NewCertPool(), true, true, true, 400},
	}

	for _, test := range tests {
		ts := ccptest.NewCCPServer()
		defer ts.Close()

		conf := &Config{
			Host:          ts.Host,
			ApplicationID: test.applicationID,
			RootCAs:       test.rootCAs,
			SkipTLSVerify: test.skipTLSVerify,
		}
		if test.rootCAs != nil {
			conf.RootCAs.AppendCertsFromPEM(ts.ServerRootCA())
		}
		if test.clientUseClientCert {
			cert, _ := tls.X509KeyPair(ts.ClientCertificate(test.applicationID))
			conf.ClientCertificate = &cert
		}
		tc, err := NewClient(conf)
		if (err == nil) != test.valid1 {
			t.Errorf("fail %v: %v", test, err)
		}

		resp, err := tc.config.HTTPClient.Get("https://" + tc.config.Host + "/AIMWebService/api/Accounts")
		if (err == nil) != test.valid2 {
			t.Errorf("fail %v: %v", test, err)
		}

		if resp != nil {
			defer tc.Close()
			defer resp.Body.Close()

			if test.vaild2StatusCode != resp.StatusCode {
				t.Errorf("fail %v: Got %v, Want %v", test, resp.StatusCode, test.vaild2StatusCode)
			}
		}
	}
}
