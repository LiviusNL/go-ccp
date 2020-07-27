package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"

	ccp "github.com/liviusnl/go-ccp"
)

func main() {
	client, err := ccp.NewClient(parseCmdLine())
	if err != nil {
		panic(err)
	}

	re := regexp.MustCompile("([^/]+)/.*$")
	action := re.FindStringSubmatch(flag.Arg(0))
	if len(action) == 0 {
		flag.Usage()
		log.Fatalf("invalid operation: use object or query")
	}
	switch action[1] {
	case "object":
		re := regexp.MustCompile("object/([^/]+)/(?:(.*)/)?([^/]+)$")
		request := re.FindStringSubmatch(flag.Arg(0))
		if len(request) != 4 {
			log.Fatalf("invalid object request: %v", flag.Arg(0))
		}

		resp, logicalError, err := client.Request(&ccp.PasswordRequest{
			Safe:   request[1],
			Folder: request[2],
			Object: request[3],
			Reason: flag.Arg(1),
		})
		if err != nil {
			log.Fatalf("password request failed: %v", err)
		}
		if logicalError != "" {
			log.Fatalf("password request failed: %v", logicalError)
		}
		fmt.Printf("Response:\n%v\n", resp)
	case "query":
		re := regexp.MustCompile("([^=/]+)=([^=/]+)")
		params := re.FindAllStringSubmatch(flag.Arg(0), -1)
		req := &ccp.PasswordRequest{
			Reason: flag.Arg(1),
		}
		for _, param := range params {
			switch param[1] {
			case "Safe":
				req.Safe = param[2]
			case "Folder":
				req.Folder = param[2]
			case "Object":
				req.Object = param[2]
			case "UserName":
				req.UserName = param[2]
			case "Address":
				req.Address = param[2]
			case "Database":
				req.Database = param[2]
			case "PolicyID":
				req.PolicyID = param[2]
			default:
				log.Fatalf("invalid query parameter %v", param[1])
			}
		}

		qf := ccp.QueryFormatExact
		if len(flag.Arg(2)) != 0 {
			re := regexp.MustCompile("^((?i)(?:exact)|(?:regex))$")
			format := re.FindStringSubmatch(flag.Arg(2))
			if len(format) != 2 {
				log.Fatal("use query format: exact or regex")
			}
			switch strings.ToLower(format[1]) {
			case "exact":
				qf = ccp.QueryFormatExact
			case "regex":
				qf = ccp.QueryFormatRegEx
			}
		}

		resp, logicalError, err := client.Query(req, qf)
		if err != nil {
			log.Fatalf("password query failed %v", err)
		}
		if logicalError != "" {
			log.Fatalf("password query failed: %v", logicalError)
		}
		fmt.Printf("Response:\n%v\n", resp)
	default:
		log.Fatalf("invalid operation: %v, use object or query", action[1])
	}
	client.Close()
}

func parseCmdLine() *ccp.Config {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintln(flag.CommandLine.Output(), " ccpcli object/:safe/:folder/:object [reason]")
		fmt.Fprintln(flag.CommandLine.Output(), " ccpcli object/:safe/:object [reason]")
		fmt.Fprintln(flag.CommandLine.Output(), " ccpcli query/queryparam[/queryparam[...]] [reason] [exact|regex]")
	}
	c := &ccp.Config{}
	flag.StringVar(&c.Host, "host", "", "The `hostname:[port]` of the CCP Web Server")
	flag.StringVar(&c.ApplicationID, "app-id", "", "The `application_identifier` of the application performing the request")
	flag.IntVar(&c.ConnectionTimeout, "timeout", 30, "The CCP server `timeout` in seconds")
	flag.BoolVar(&c.FailRequestOnPasswordChange, "fail", false, "Fail Request, when a password change is in progress")
	flag.BoolVar(&c.SkipTLSVerify, "skip-tls", false, "Skip the verification of the server certificate")
	flag.BoolVar(&c.EnableTLSRenegotiation, "tls-renegotiation", false, "Enable TLS renegotiation support")

	var certFile, keyFile, caFile string
	flag.StringVar(&certFile, "cert", "", "A file containing the client `certificate` for web service authentication")
	flag.StringVar(&keyFile, "key", "", "A file containing the client certificate `key` for web service authentication")
	flag.StringVar(&caFile, "ca", "", "A file containing a PEM `certificate or bundle` to verify the server certificate")
	flag.Parse()

	if len(c.Host) == 0 {
		log.Fatalf("missing required --host parameter")
	}
	if len(c.ApplicationID) == 0 {
		log.Fatalf("missing required --app-id parameter")
	}
	switch {
	case len(certFile) != 0 && len(keyFile) != 0:
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatalf("%v", err)
		}
		c.ClientCertificate = &cert
	case len(certFile) != 0 || len(keyFile) != 0:
		log.Fatalf("parameters --cert and --key must be used together")
	}
	if len(caFile) != 0 {
		data, err := ioutil.ReadFile(caFile)
		if err != nil {
			log.Fatalf("%v", err)
		}
		rootCAs := x509.NewCertPool()
		ok := rootCAs.AppendCertsFromPEM(data)
		if !ok {
			log.Fatalf("unable to parse ca certificates")
		}
		c.RootCAs = rootCAs
	}

	return c
}
