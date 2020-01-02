package ccp

import (
	"net"
	"net/http"
	"time"
)

// CredentialProviderHTTPTransport returns a new http.Transport with similar
// default values to http.DefaultTransport.
func CredentialProviderHTTPTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// CredentialProviderHTTPClient returns a new http.Client with similar
// defaults to http.Client, but using a dedicated transport.
func CredentialProviderHTTPClient() *http.Client {
	return &http.Client{
		Transport: CredentialProviderHTTPTransport(),
	}
}