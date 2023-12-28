package main

import (
	"github.com/RushikeshMarkad16/saml_test/config"
	"github.com/RushikeshMarkad16/saml_test/server"
)

func main() {
	config.Load()
	server.StartServer()
}
