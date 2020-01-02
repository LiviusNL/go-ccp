package ccp

import (
	"testing"
)

//
// CCP Client
//

func TestClient(t *testing.T) {
	var tests = []struct {
		hostname      string
		applicationID string
		valid         bool
	}{
		{"", "", false},
		{"", "MyApp", false},
		{"localhost", "", false},
		{"localhost", "MyApp", true},
	}

	for _, test := range tests {
		_, err := NewClient(&Config{
			Hostname:      test.hostname,
			ApplicationID: test.applicationID,
		})
		if (err == nil) != test.valid {
			t.Errorf("fail %v: %v", test, err)
		}
	}
}

//
// Hostname
//

//  Hostname initialisation default, no variable change
func TestHostname1(t *testing.T) {
	h := "ccp.example.com"

	c, err := NewClient(&Config{
		Hostname:      h,
		ApplicationID: "MyApp",
	})
	if err != nil {
		t.Errorf("unable to initialize CCP Client: %v", err)
	}

	if h != c.Hostname() {
		t.Errorf("set hostname %v is not equal to read hostname %v", h, c.Hostname())
	}
}

//  Hostname initialisation 'localhost', variable change to 'ccp.example.com'
func TestHostname2(t *testing.T) {
	h := "ccp.example.com"

	c, err := NewClient(&Config{
		Hostname:      "localhost",
		ApplicationID: "MyApp",
	})
	if err != nil {
		t.Errorf("unable to initialize CCP Client: %v", err)
	}

	err = c.SetHostname(h)
	if err != nil {
		t.Errorf("unable to set hostname: %v", err)
	}

	if h != c.Hostname() {
		t.Errorf("set hostname %v is not equal to read hostname %v", h, c.Hostname())
	}
}

//  Hostname initialisation 'localhost', change to empty value
func TestHostname3(t *testing.T) {
	var h string

	c, err := NewClient(&Config{
		Hostname:      "localhost",
		ApplicationID: "MyApp",
	})
	if err != nil {
		t.Errorf("unable to initialize CCP Client: %v", err)
	}

	err = c.SetHostname(h)
	if err == nil {
		t.Errorf("unable to set empty hostname: %v", err)
	}
}

//
// ConnectionTimeout
//

//  ConnectionTimeout initialisation default, no variable change
func TestConnectionTimeout1(t *testing.T) {
	to := 0

	c, err := NewClient(&Config{
		Hostname:      "localhost",
		ApplicationID: "MyApp",
	})
	if err != nil {
		t.Errorf("unable to initialize CCP Client: %v", err)
	}

	if to != c.ConnectionTimeout() {
		t.Errorf("default ConnectionTimeout %v is not equal to read ConnectionTimeout %v", to, c.ConnectionTimeout())
	}
}

//  ConnectionTimeout initialisation '10', no variable change
func TestConnectionTimeout2(t *testing.T) {
	to := 10

	c, err := NewClient(&Config{
		Hostname:          "localhost",
		ApplicationID:     "MyApp",
		ConnectionTimeout: to,
	})
	if err != nil {
		t.Errorf("unable to initialize CCP Client: %v", err)
	}

	if to != c.ConnectionTimeout() {
		t.Errorf("set ConnectionTimeout %v is not equal to read ConnectionTimeout %v", to, c.ConnectionTimeout())
	}
}

//  ConnectionTimeout initialisation '-1', no variable change
func TestConnectionTimeout3(t *testing.T) {
	to := -1

	_, err := NewClient(&Config{
		Hostname:          "localhost",
		ApplicationID:     "MyApp",
		ConnectionTimeout: to,
	})
	if err == nil {
		t.Errorf("setting ConnectionTineout should fail")
	}
}

//  ConnectionTimeout initialisation default, variable change to '10'
func TestConnectionTimeout4(t *testing.T) {
	to := 10

	c, err := NewClient(&Config{
		Hostname:      "localhost",
		ApplicationID: "MyApp",
	})
	if err != nil {
		t.Errorf("unable to initialize CCP Client: %v", err)
	}

	err = c.SetConnectionTimeout(to)
	if err != nil {
		t.Errorf("unable to set ConnectionTimeout: %v", err)
	}
	if to != c.ConnectionTimeout() {
		t.Errorf("set ConnectionTimeout %v is not equal to read ConnectionTimeout %v", to, c.ConnectionTimeout())
	}
}

//  ConnectionTimeout initialisation default, variable change to '-1'
func TestConnectionTimeout5(t *testing.T) {
	to := -1

	c, err := NewClient(&Config{
		Hostname:      "localhost",
		ApplicationID: "MyApp",
	})
	if err != nil {
		t.Errorf("unable to initialize CCP Client: %v", err)
	}

	err = c.SetConnectionTimeout(to)
	if err == nil {
		t.Errorf("setting ConnectionTineout should fail")
	}
}

//
// FailRequestOnPasswordChange
//

//  FailRequestOnPasswordChange initialisation default, no variable change
func TestFailRequestOnPasswordChange1(t *testing.T) {
	var f bool = false

	c, err := NewClient(&Config{
		Hostname:      "localhost",
		ApplicationID: "MyApp",
	})
	if err != nil {
		t.Errorf("unable to initialize CCP Client: %v", err)
	}

	if f != c.FailRequestOnPasswordChange() {
		t.Errorf("default FailRequestOnPasswordChange %v is not equal to read FailRequestOnPasswordChange %v", f, c.FailRequestOnPasswordChange())
	}
}

//  FailRequestOnPasswordChange initialisation 'true', no variable change
func TestFailRequestOnPasswordChange2(t *testing.T) {
	var f bool = true

	c, err := NewClient(&Config{
		Hostname:                    "localhost",
		ApplicationID:               "MyApp",
		FailRequestOnPasswordChange: f,
	})
	if err != nil {
		t.Errorf("unable to initialize CCP Client: %v", err)
	}

	if f != c.FailRequestOnPasswordChange() {
		t.Errorf("set FailRequestOnPasswordChange %v is not equal to read FailRequestOnPasswordChange %v", f, c.FailRequestOnPasswordChange())
	}
}

// FailRequestOnPasswordChange initialisation default, variable change to 'true'
func TestFailRequestOnPasswordChange3(t *testing.T) {
	var f bool = true

	c, err := NewClient(&Config{
		Hostname:      "localhost",
		ApplicationID: "MyApp",
	})
	if err != nil {
		t.Errorf("unable to initialize CCP Client: %v", err)
	}

	c.SetFailRequestOnPasswordChange(f)
	if f != c.FailRequestOnPasswordChange() {
		t.Errorf("set FailRequestOnPasswordChange %v is not equal to read FailRequestOnPasswordChange %v", f, c.FailRequestOnPasswordChange())
	}
}
