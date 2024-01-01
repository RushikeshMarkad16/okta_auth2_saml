package server

import (
	"fmt"
	"os"

	"github.com/urfave/negroni"
)

// StartServer ...
func StartServer() {
	server := negroni.Classic()

	router := InitRouter()

	server.UseHandler(router)

	port := os.Getenv("PORT")
	server.Run(fmt.Sprintf(":%s", port))

}
