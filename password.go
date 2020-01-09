package ccp

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

const defaultFolder = "Root"

// QueryFormat specifies the type query being executed
type QueryFormat int

// QueryFormat Values
const (
	// QueryFormatExact specifies a query in Exact format
	QueryFormatExact QueryFormat = iota
	// QueryFormatRegEx specifies a query in Regular Expression format
	QueryFormatRegEx
)

const (
	queryFormatExact = "Exact"
	queryFormatRegex = "RegEx"
)

// PasswordRequest defines the query parameters to search for a password
type PasswordRequest struct {
	Safe, Folder, Object        string
	UserName, Address, Database string
	PolicyID                    string

	// Password request reason
	Reason string
}

// PasswordResponse contains the retrieved password information
type PasswordResponse struct {
	// Password
	Content        string
	CreationMethod string

	Safe, Folder          string
	UserName, LogonDomain string
	Name                  string
	Address, DeviceType   string
	Database              string // Is this a valid response?
	PolicyID              string

	PasswordChangeInProcess bool

	// Error Information
	ErrorCode string
	ErrorMsg  string
}

// Request requests a password from the CCP Web Service
func (c *Client) Request(r *PasswordRequest) (*PasswordResponse, string, error) {
	v := &url.Values{}

	if len(r.Safe) != 0 {
		v.Set(valueSafe, r.Safe)
	}
	if len(r.Folder) != 0 && r.Folder != defaultFolder {
		v.Set(valueFolder, r.Folder)
	}
	if len(r.Object) != 0 {
		v.Set(valueObject, r.Object)
	}

	if len(r.UserName) != 0 {
		v.Set(valueUserName, r.UserName)
	}
	if len(r.Address) != 0 {
		v.Set(valueAddress, r.Address)
	}
	if len(r.Database) != 0 {
		v.Set(valueDatabase, r.Database)
	}

	if len(r.PolicyID) != 0 {
		v.Set(valuePolicyID, r.PolicyID)
	}

	if len(r.Reason) != 0 {
		v.Set(valueReason, r.Reason)
	}

	return c.ccpRequest(v)
}

// Query queries the CCP Web Service for a password
func (c *Client) Query(r *PasswordRequest, qf QueryFormat) (*PasswordResponse, string, error) {
	qv := make(map[string]string, 8)

	if len(r.Safe) != 0 {
		qv[valueSafe] = r.Safe
	}
	if len(r.Folder) != 0 {
		qv[valueFolder] = r.Folder
	}
	if len(r.Object) != 0 {
		qv[valueObject] = r.Object
	}

	if len(r.UserName) != 0 {
		qv[valueUserName] = r.UserName
	}
	if len(r.Address) != 0 {
		qv[valueAddress] = r.Address
	}
	if len(r.Database) != 0 {
		qv[valueDatabase] = r.Database
	}

	if len(r.PolicyID) != 0 {
		qv[valuePolicyID] = r.PolicyID
	}

	// Build the query
	var qs strings.Builder
	for k := range qv {
		if qs.Len() > 0 {
			qs.WriteByte(';')
		}
		qs.WriteString(k)
		qs.WriteByte('=')
		qs.WriteString(qv[k])
	}

	v := &url.Values{}

	v.Set(valueQuery, qs.String())
	if qf == QueryFormatRegEx {
		v.Set(valueQueryFormat, queryFormatRegex)
	}
	if len(r.Reason) != 0 {
		v.Set(valueReason, r.Reason)
	}

	return c.ccpRequest(v)
}

func (c *Client) ccpRequest(v *url.Values) (*PasswordResponse, string, error) {
	req, err := http.NewRequest(http.MethodGet, c.url.String()+"&"+v.Encode(), nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Add("Content-Type", "application/json")

	resp, err := c.config.HTTPClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	var logicalError string
	switch resp.StatusCode {
	case http.StatusOK:
		break
	case http.StatusBadRequest: //400
		fallthrough
	case http.StatusUnauthorized: //401
		fallthrough
	case http.StatusForbidden: // 403
		fallthrough
	case http.StatusNotFound: // 404
		logicalError = resp.Status
	default:
		return nil, "", errors.New("unexpected http status: " + resp.Status)
	}

	r := &PasswordResponse{}
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	err = dec.Decode(r)
	if err != nil {
		return nil, "", err
	}

	return r, logicalError, nil
}
