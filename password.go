package ccp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
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

// MapSnakeCase returns PasswordResponse a map[string]interface{}, using snake case keys
func (pr *PasswordResponse) MapSnakeCase() (map[string]interface{}, error) {
	var r map[string]interface{}
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName: "mapstructure2",
		Result:  &r,
	})
	if err != nil {
		return nil, err
	}

	err = dec.Decode(pr)
	if err != nil {
		return nil, err
	}
	r["last_success_reconciliation"] = time.Unix(pr.LastSuccessReconciliation, 0)

	return r, nil
}

// Request requests a password from the CCP Web Service
func (c *Client) Request(ctx context.Context, r *PasswordRequest) (*PasswordResponse, string, error) {
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

	return c.ccpRequest(ctx, v)
}

// Query queries the CCP Web Service for a password
func (c *Client) Query(ctx context.Context, r *PasswordRequest, qf QueryFormat) (*PasswordResponse, string, error) {
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

	return c.ccpRequest(ctx, v)
}

func (c *Client) ccpRequest(ctx context.Context, v *url.Values) (*PasswordResponse, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url.String()+"&"+v.Encode(), nil)
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

	var raw map[string]interface{}

	// The CCP does not return proper JSON
	// Unmarshall JSON first in map of generic types
	jdec := json.NewDecoder(resp.Body)
	jdec.UseNumber()
	err = jdec.Decode(&raw)
	if err != nil {
		return nil, "", err
	}

	// Decode Map into final structure
	r := &PasswordResponse{}
	err = mapstructure.WeakDecode(raw, r)
	if err != nil {
		return nil, "", err
	}

	return r, logicalError, nil
}
