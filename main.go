package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/BurntSushi/toml"
	"github.com/mreiferson/go-options"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	flagSet := flag.NewFlagSet("oauth2_proxy", flag.ExitOnError)

	config := flagSet.String("config", "", "path to config file")
	showVersion := flagSet.Bool("version", false, "print version string")

	flagSet.String("http-address", "127.0.0.1:4180", "[http://]<addr>:<port> or unix://<path> to listen on for HTTP clients")
	flagSet.String("https-address", ":443", "<addr>:<port> to listen on for HTTPS clients")
	flagSet.String("tls-cert", "", "path to certificate file")
	flagSet.String("tls-key", "", "path to private key file")

	flagSet.Bool("request-logging", true, "Log requests to stdout")
	flagSet.String("request-logging-format", defaultRequestLoggingFormat, "Template for log lines")

	flagSet.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("oauth2_proxy v%s (built with %s)\n", VERSION, runtime.Version())
		return
	}

	opts := NewMultiAppProxyOptions()
	cfg := make(EnvOptions)
	if *config != "" {
		_, err := toml.DecodeFile(*config, &cfg)
		if err != nil {
			log.Fatalf("ERROR: failed to load config file %s - %s", *config, err)
		}
	}
	cfg.LoadEnvForStruct(opts)
	options.Resolve(opts, flagSet, cfg)

	multiappproxy := MultiAppProxy{
		AppToOAuthProxy: make(map[string]*OAuthProxy),
	}
	for domain, appOpts := range opts.Apps {
		err := appOpts.Validate()
		if err != nil {
			log.Printf("%s", err)
			os.Exit(1)
		}
		validator := NewValidator(appOpts.EmailDomains, appOpts.AuthenticatedEmailsFile)
		oap := NewOAuthProxy(
			appOpts,
			validator,
		)
		log.Printf("INFO: added app; domain '%s' -> clientid '%s'", domain, appOpts.ClientID)
		multiappproxy.AppToOAuthProxy[domain] = oap
	}

	s := &Server{
		Handler: LoggingHandler(os.Stdout, multiappproxy, opts.RequestLogging, opts.RequestLoggingFormat),
		Opts:    opts,
	}
	s.ListenAndServe()
}
