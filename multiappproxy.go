package main

import (
	"fmt"
	"log"
	"net/http"
)

type MultiAppProxyOptions struct {
	RequestLogging       bool                `flag:"request-logging" cfg:"request_logging"`
	RequestLoggingFormat string              `flag:"request-logging-format" cfg:"request_logging_format"`
	HttpAddress          string              `flag:"http-address" cfg:"http_address"`
	HttpsAddress         string              `flag:"https-address" cfg:"https_address"`
	TLSCertFile          string              `flag:"tls-cert" cfg:"tls_cert_file"`
	TLSKeyFile           string              `flag:"tls-key" cfg:"tls_key_file"`
	Apps                 map[string]*Options `cfg:apps`
}

func NewMultiAppProxyOptions() *MultiAppProxyOptions {
	return &MultiAppProxyOptions{
		HttpAddress:          "127.0.0.1:4180",
		HttpsAddress:         ":443",
		RequestLogging:       true,
		RequestLoggingFormat: defaultRequestLoggingFormat,
		Apps:                 make(map[string]*Options),
	}
}

type MultiAppProxy struct {
	// maps domain to an OAuthProxy
	AppToOAuthProxy map[string]*OAuthProxy
}

func (m MultiAppProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// TODO: is r.Host the right thing to switch on?

	k := r.Host

	oap, ok := m.AppToOAuthProxy[k]
	if !ok {
		// TODO: is 404 the right way to handle this?
		// nginx just masks this as 500 to the client
		log.Printf("DEBUG: '%s' 404", k, oap)
		//TODO is
		http.Error(w, fmt.Sprintf("app for %s not found", k), 404)
		return
	}
	// TODO: log better
	log.Printf("DEBUG: '%s' routed to %v", k, oap)

	oap.ServeHTTP(w, r)
}
