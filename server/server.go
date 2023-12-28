package server

import (
	"fmt"

	"github.com/urfave/negroni"
)

func StartServer() {
	server := negroni.Classic()

	router := InitRouter()

	server.UseHandler(router)
	server.Run(fmt.Sprintf(":%s", "8080"))

}
