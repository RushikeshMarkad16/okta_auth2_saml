package main

import (
	"github.com/RushikeshMarkad16/okta_auth2_saml/config"
	"github.com/RushikeshMarkad16/okta_auth2_saml/server"
)

func main() {
	config.Load()
	server.StartServer()
}
