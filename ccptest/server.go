package ccptest

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
)

// Server is a mock CCP WebService implementation for testing purposes
type Server struct {
	// Host is the hostname with an optional port number.
	Host string

	// HTTP Test Server
	ts *httptest.Server

	// The CA used to generate Client Certificates
	ca *CA
}

// testPasswordResponse contains the retrieved password information
type testPasswordResponse struct {
	// Password
	Content        string
	CreationMethod string

	Safe, Folder          string
	UserName, LogonDomain string
	Name                  string
	Address, DeviceType   string
	Database              string // Is this a valid response parameter?
	PolicyID              string

	PasswordChangeInProcess bool

	// Error Information
	ErrorCode string
	ErrorMsg  string
}

// NewCCPServer start a mock CCP Web Service
func NewCCPServer() *Server {
	ca, err := NewCA()
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", http.HandlerFunc(defaultHandler))
	mux.HandleFunc("/AIMWebService/api/Accounts", http.HandlerFunc(ccpHandler))
	ts := httptest.NewUnstartedServer(mux)

	ts.TLS = &tls.Config{
		ClientCAs:  x509.NewCertPool(),
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	ts.TLS.ClientCAs.AddCert(ca.Certificate)
	ts.StartTLS()

	url, err := url.Parse(ts.URL)
	if err != nil {
		panic(err)
	}

	return &Server{
		Host: url.Host,
		ts:   ts,
		ca:   ca,
	}
}

// Default Handler return 403 Error
func defaultHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)

	e := json.NewEncoder(w)
	e.Encode(testPasswordResponse{
		ErrorCode: "CCPWS403E",
		ErrorMsg:  "An error occured " + http.StatusText(http.StatusForbidden),
	})
}

// CCP Web Serivce Handler
func ccpHandler(w http.ResponseWriter, r *http.Request) {
	status := http.StatusOK

	// Status 401, No Client Certificate Privided or Common Name is empty
	var cn string
	if status == http.StatusOK {
		if len(r.TLS.PeerCertificates) != 0 {
			for _, pc := range r.TLS.PeerCertificates {
				cn = pc.Subject.CommonName
				if len(cn) == 0 {
					status = http.StatusUnauthorized
				}
			}
		} else {
			status = http.StatusUnauthorized
		}
	}

	// Status 400, Form Parsing failed
	err := r.ParseForm()
	if status == http.StatusOK && err != nil {
		status = http.StatusBadRequest
	}

	// Status 400, No AppID provided
	appID := r.Form.Get("AppID")
	if status == http.StatusOK && len(appID) == 0 {
		status = http.StatusBadRequest
	}

	// Status 403, ClientCert CN != AppID
	if status == http.StatusOK && cn != appID {
		status = http.StatusForbidden
	}

	resp := testPasswordResponse{}

	// Object, OtherObject results in error
	object := r.Form.Get("Object")
	if len(object) != 0 {
		if object == "OtherObject" {
			status = http.StatusNotFound
		}
	}

	// Safe
	safe := r.Form.Get("Safe")
	if len(safe) != 0 {
		resp.Safe = safe
	}
	// Folder
	folder := r.Form.Get("Folder")
	if len(folder) != 0 {
		resp.Folder = folder
	} else {
		resp.Folder = "Root"
	}

	// UserName
	resp.UserName = "user-" + object
	// Password
	passwd := func() string {
		const chars = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
		b := make([]byte, 8)
		for i := range b {
			b[i] = chars[rand.Int63()%int64(len(chars))]
		}
		return string(b)
	}
	resp.Content = passwd()

	switch status {
	case http.StatusBadRequest: // 400
		fallthrough
	case http.StatusUnauthorized: // 401
		fallthrough
	case http.StatusForbidden: // 403
		fallthrough
	case http.StatusNotFound: // 404
		resp = testPasswordResponse{
			ErrorCode: "CCPWS" + strconv.Itoa(status) + "E",
			ErrorMsg:  "An error occured " + strconv.Itoa(status) + " " + http.StatusText(status),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	e := json.NewEncoder(w)
	e.Encode(resp)
}

/*
	StatusBadRequest                   = 400 // RFC 7231, 6.5.1
		AIMWS030E	BadRequest (400) // invalid query format, etc
		APPAP227E	BadRequest (400) // 1. too many objects
		APPAP228E	BadRequest (400) // 2. too many objects
		APPAP229E	BadRequest (400) // 3. too many objects
		APPAP007E	BadRequest (400) // Connection to the Vault has failed
		APPAP081E	BadRequest (400) // Request Message content is invalid
		CASVL010E	BadRequest (400) // Invalid characters in User Name
		AIMWS031E	BadRequest (400) // Invalid request. The AppID Parameter is require
*/

// ServerRootCA returns the server's (root) Certificate
func (s *Server) ServerRootCA() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: s.ts.Certificate().Raw,
	})
}

// ClientCertificate creates a new test client certificate
func (s *Server) ClientCertificate(cn string) ([]byte, []byte) {
	cert, key, err := s.ca.NewClientCertificate(cn)
	if err != nil {
		panic(err)
	}
	return cert, key
}

// Close shuts down the server and blocks until all outstanding requests
// on this server have completed.
func (s *Server) Close() {
	s.ts.Close()
}
