# go-ccp
CyberArk Credentials Provider Go REST Client

## Overview

The `go-ccp` package implements a client to interact with the REST API provided by the CyberArk Central Credentials provider. Thereby making it easier to consume secrets from Go based application.

The `cli` directory contains a command line client client based on the implemented API.

---

## Documentation

### func CredentialProviderHTTPClient

```go
func CredentialProviderHTTPClient() *http.Client
```
CredentialProviderHTTPClient returns a new http.Client with similar defaults to http.Client, but using a dedicated transport.

### func CredentialProviderHTTPTransport

```go
func CredentialProviderHTTPTransport() *http.Transport
```
CredentialProviderHTTPTransport returns a new http.Transport with similar default values to http.DefaultTransport.

### type Client

Client implements the CCP client, which communicates with the CCP Web Servie

```go
type Client struct {
    // contains filtered or unexported fields
}
```

#### func NewClient

```go
func NewClient(c *Config) (*Client, error)
```
NewClient creates a CCP client given the provided Config

#### func (*Client) Close

```go
func (c *Client) Close()
```
Close HTTP idle connections

#### func (*Client) ConnectionTimeout

```go
func (c *Client) ConnectionTimeout() int
```
ConnectionTimeout returns the connection timeout to EPV from the CCP Server

#### func (*Client) FailRequestOnPasswordChange

```go
func (c *Client) FailRequestOnPasswordChange() bool
```
FailRequestOnPasswordChange returns the request behaviour, when a password change is in progress

#### func (*Client) Host

```go
func (c *Client) Host() string
```
Host returns the CCP Web Service host

#### func (*Client) Query

```go
func (c *Client) Query(ctx context.Context, r *PasswordRequest, qf QueryFormat) (*PasswordResponse, string, error)
```
Query queries the CCP Web Service for a password

#### func (*Client) Request

```go
func (c *Client) Request(ctx context.Context, r *PasswordRequest) (*PasswordResponse, string, error)
```
Request requests a password from the CCP Web Service

#### func (*Client) SetConnectionTimeout

```go
func (c *Client) SetConnectionTimeout(v int) error
```
SetConnectionTimeout sets the connection timeout to EPV from the CCP Server

#### func (*Client) SetFailRequestOnPasswordChange

```go
func (c *Client) SetFailRequestOnPasswordChange(v bool)
```
SetFailRequestOnPasswordChange sets the request behaviour, when a password change is in progress

#### func (*Client) SetHost

```go
func (c *Client) SetHost(v string) error
```
SetHost sets the CCP Web Service host

### type Config

Config is used to configure the creation of the CCP client After one has been passed to a CCP function it must not be modified.

```go
type Config struct {

    // The host of CCP Web Service host.
    // This should be a hostname with an optional port number.
    // Using the format: hostname[:port]
    Host string

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
    ClientCertificate *tls.Certificate

    // SkipTLSVerify disbles or enables service certificate Validation
    SkipTLSVerify bool

    // Enable TLS Renegotiation
    EnableTLSRenegotiation bool

    // RootCA is a PEM encoded certificate or bundle to verify the
    // CCP Web Service Server Certificat
    RootCAs *x509.CertPool
    // contains filtered or unexported fields
}
```

### type PasswordRequest

PasswordRequest defines the query parameters to search for a password

```go
type PasswordRequest struct {
    Safe, Folder, Object        string
    UserName, Address, Database string
    PolicyID                    string

    // Password request reason
    Reason string
}
```

### type PasswordResponse

PasswordResponse contains the retrieved password information

```go
type PasswordResponse struct {
	SequenceID int `mapstructure2:"sequence_id,omitempty"`
	// Password
	Content string `mapstructure2:"content"`

	Safe               string `mapstructure2:"safe"`
	Folder             string `mapstructure2:"folder"`
	UserName           string `mapstructure2:"username"`
	LogonDomain        string `mapstructure2:"logon_domain"`
	Name               string `mapstructure2:"name,omitempty"`
	AccountDescription string `mapstructure2:"account_description,omitempty"`
	Address            string `mapstructure2:"address,omitempty"`
	DeviceType         string `mapstructure2:"device_type,omitempty"`
	Environment        string `mapstructure2:"content,omitempty"`
	Database           string `mapstructure2:"database,omitempty"` // Is Database a valid response?
	CreationMethod     string `mapstructure2:"creation_method,omitempty"`

	PolicyID    string `mapstructure2:"policy_id,omitempty"`
	CPMStatus   string `mapstructure2:"cpm_status,omitempty"`
	CPMDisabled string `mapstructure2:"cpm_disabled,omitempty"`

	PasswordChangeInProcess bool `mapstructure2:"password_change_in_process"`

	LastTask                  string `mapstructure2:"last_task,omitempty"`
	LastSuccessReconciliation int64  `mapstructure2:"last_success_reconciliation,omitempty"` // Unix time, the number of seconds elapsed since January 1, 1970 UTC

	RetriesCount int `mapstructure2:"retries_count,omitempty"`

	// Error Information
	ErrorCode string `mapstructure2:"error_code,omitempty"`
	ErrorMsg  string `mapstructure2:"error_msg,omitempty"`
}
```

#### func MapSnakeCase

```go
func (pr *PasswordResponse) MapSnakeCase() (map[string]interface{}, error)
```

MapSnakeCase returns PasswordResponse a map[string]interface{}, using snake case keys

### type QueryFormat

QueryFormat specifies the type query being executed

```go
type QueryFormat int
```
QueryFormat Values

```go
const (
    // QueryFormatExact specifies a query in Exact format
    QueryFormatExact QueryFormat = iota
    // QueryFormatRegEx specifies a query in Regular Expression format
    QueryFormatRegEx
)
```
