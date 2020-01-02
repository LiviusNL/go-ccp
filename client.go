// Package ccp implements the CyberArk Credentials Provider (CCP) REST API client
package ccp

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"sync"
)

// Config is used to configure the creation of the CCP client
// After one has been passed to a CCP function it must not be modified.
type Config struct {
	modifyLock sync.RWMutex

	// The hostname of CCP Web Service host.
	// This should be a hostname with an optipnal port number.
	// Using the format: hostname[:port]
	Hostname string

	// HttpClient is the HTTP client to use to access the CCP Web Service
	HTTPClient *http.Client

	// The ID of the application performing the password request
	ApplicationID string

	// The number of seconds that the Central Credential Provider
	// will try to retrieve the password. The timeout is calculated
	// when the request is sent from the web service to the Vault
	// and returned back to the web service.
	// If zero the default connection timeout will be used.
	ConnectionTimeout int

	// Whether or not an error will be returned, if the web service
	// is called when a password change process is underway.
	// To fail a request Aduring a password change, set this value to true
	FailRequestOnPasswordChange bool

	// Certificate is used to to authenticate against the CCP Web Service
	Certificate *tls.Certificate

	// SkipTLSVerify disbles or enables service certificate Validation
	SkipTLSVerify bool

	// RootCA is a PEM encoded certificate or bundle to verify the
	// CCP Web Service Server Certificat
	RootCAs *x509.CertPool
}

const (
	valueApplicationID               = "AppID"
	valueSafe                        = "Safe"
	valueFolder                      = "Folder"
	valueObject                      = "Object"
	valueUserName                    = "UserName"
	valueAddress                     = "Address"
	valueDatabase                    = "Database"
	valuePolicyID                    = "PolicyID"
	valueQuery                       = "Query"
	valueQueryFormat                 = "QueryFormat"
	valueConnectionTimeout           = "ConnectionTimeout"
	valueFailRequestOnPasswordChange = "FailRequestOnPasswordChange"
	valueReason                      = "Reason"
)

// Client implements the CCP client, which communicates with the CCP Web Servie
type Client struct {
	modifyLock sync.RWMutex

	config *Config

	url url.URL
}

// NewClient creates a CCP client given the provided Config
func NewClient(c *Config) (*Client, error) {
	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	if len(c.Hostname) == 0 {
		return nil, errors.New("Hostname is empty")
	}
	if c.HTTPClient == nil {
		c.HTTPClient = CredentialProviderHTTPClient()
	}
	if len(c.ApplicationID) == 0 {
		return nil, errors.New("ApplicationID is empty")
	}
	if c.ConnectionTimeout < 0 {
		return nil, errors.New("CommectionTimeout must be positive")
	}

	tlsClientConfig := &tls.Config{}
	if c.Certificate != nil {
		tlsClientConfig.Certificates = append(tlsClientConfig.Certificates, *c.Certificate)
	}
	if c.SkipTLSVerify {
		tlsClientConfig.InsecureSkipVerify = true
	}
	if c.RootCAs != nil {
		tlsClientConfig.RootCAs = c.RootCAs
	}
	c.HTTPClient.Transport.(*http.Transport).TLSClientConfig = tlsClientConfig

	client := &Client{
		config: c,
		url: url.URL{
			Scheme: "https",
			Host:   c.Hostname,
			Path:   "/AIMWebService/api/Accounts",
		},
	}
	client.updateQueryValues()

	return client, nil
}

// Close HTTP idle connections
func (c *Client) Close() {
	c.config.HTTPClient.CloseIdleConnections()
}

// Hostname returns the CCP Web Service hostname
func (c *Client) Hostname() string {
	c.modifyLock.RLock()
	c.config.modifyLock.RLock()
	defer c.config.modifyLock.RUnlock()
	c.modifyLock.RUnlock()

	return c.config.Hostname
}

// SetHostname sets the CCP Web Service hostname
func (c *Client) SetHostname(v string) error {
	c.modifyLock.RLock()
	c.config.modifyLock.Lock()
	defer c.config.modifyLock.Unlock()
	c.modifyLock.RUnlock()

	if len(v) == 0 {
		return errors.New("Hostname is empty")
	}
	c.config.Hostname = v

	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()
	c.url.Host = v

	return nil
}

// ConnectionTimeout returns the connection timeout to EPV from the CCP Server
func (c *Client) ConnectionTimeout() int {
	c.modifyLock.RLock()
	c.config.modifyLock.RLock()
	defer c.config.modifyLock.RUnlock()
	c.modifyLock.RUnlock()

	return c.config.ConnectionTimeout
}

// SetConnectionTimeout sets the connection timeout to EPV from the CCP Server
func (c *Client) SetConnectionTimeout(v int) error {
	c.modifyLock.RLock()
	c.config.modifyLock.Lock()
	defer c.config.modifyLock.Unlock()
	c.modifyLock.RUnlock()

	if v < 0 {
		return errors.New("ConnectionTimeout must be positive")
	}
	c.config.ConnectionTimeout = v
	c.updateQueryValues()

	return nil
}

// FailRequestOnPasswordChange returns the request behaviour, when a password change is in progress
func (c *Client) FailRequestOnPasswordChange() bool {
	c.modifyLock.RLock()
	c.config.modifyLock.RLock()
	defer c.config.modifyLock.RUnlock()
	c.modifyLock.RUnlock()

	return c.config.FailRequestOnPasswordChange
}

// SetFailRequestOnPasswordChange sets the request behaviour, when a password change is in progress
func (c *Client) SetFailRequestOnPasswordChange(v bool) {
	c.modifyLock.RLock()
	c.config.modifyLock.Lock()
	defer c.config.modifyLock.Unlock()
	c.modifyLock.RUnlock()

	c.config.FailRequestOnPasswordChange = v
	c.updateQueryValues()
}

func (c *Client) updateQueryValues() {
	v := url.Values{}

	v.Set(valueApplicationID, c.config.ApplicationID)
	if c.config.ConnectionTimeout != 0 && c.config.ConnectionTimeout != 30 {
		v.Set(valueConnectionTimeout, strconv.Itoa(c.config.ConnectionTimeout))
	}
	if c.config.FailRequestOnPasswordChange {
		v.Set(valueFailRequestOnPasswordChange, strconv.FormatBool(c.config.FailRequestOnPasswordChange))
	}

	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()
	c.url.RawQuery = v.Encode()
}
