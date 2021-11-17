package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/mousybusiness/firebase_token/creds"
	"github.com/mousybusiness/firebase_token/fireb"
	log "github.com/sirupsen/logrus"
	"os"
	"strings"
)

var (
	err      error
	logLevel = log.ErrorLevel
)

func main() {
	// allow log level override for debugging
	ll := os.Getenv("LOG_LEVEL")
	if ll != "" {
		logLevel, err = log.ParseLevel(strings.ToLower(ll))
		if err != nil {
			log.Fatal(err)
		}
	}
	log.SetLevel(logLevel)
	log.SetOutput(os.Stderr)

	var cfg, apiKey, refresh string
	var token bool
	flag.StringVar(&apiKey, "apiKey", "", "Admin service account API key (see README.md)")
	flag.StringVar(&cfg, "config", "", "Web app config JSON (see README.md)")
	flag.StringVar(&refresh, "refresh", "", "Refresh without UI using existing refresh token")
	flag.BoolVar(&token, "token", false, "Only returns IDToken if successful, useful for scripts")

	flag.Parse()

	if apiKey == "" {
		log.Fatal("require key flag")
	}

	if cfg == "" {
		log.Fatal("require config flag")
	}

	path := cfg
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Fatal("config file doesn't exist")
	}

	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	var root fireb.Root
	if err := json.Unmarshal(b, &root); err != nil {
		log.Fatal(err)
	}

	config := root.Config

	if config.ClientID == "" || config.ClientSecret == "" || config.TokenURI == "" || config.AuthURI == "" {
		log.Fatal("malformed config")
	}

	config.APIKey = apiKey

	log.Debugf("config: %v", config)

	c := fireb.New(config)

	var credentials *creds.Credentials
	if refresh == "" {
		credentials = c.Auth()

	} else {
		log.Debugf("using refresh token")
		credentials, _ = c.Refresh(creds.RefreshToken(refresh))
	}

	if credentials == nil {
		log.Fatal("failed")
	}

	if token {
		fmt.Printf("%v", credentials.IDToken)
		os.Exit(0)
	}

	fmt.Printf("UID: %v\n", credentials.UID)
	fmt.Printf("ID_TOKEN: %v\n", credentials.IDToken)
	fmt.Printf("REFRESH_TOKEN: %v\n", credentials.RefreshToken)
}
