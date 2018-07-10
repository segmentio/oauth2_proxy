package main

import (
	"fmt"
	"log"
	"net/http"
)

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
