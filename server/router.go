package server

import (
	"net/http"

	"github.com/RushikeshMarkad16/saml_test/config"
	"github.com/RushikeshMarkad16/saml_test/handler"
	"github.com/gorilla/mux"
)

func InitRouter() (router *mux.Router) {

	router = mux.NewRouter()
	samlRoute := router.PathPrefix("").Subrouter()

	samlRoute.Handle("/saml/login", config.SamlSP.RequireAccount(http.HandlerFunc(handler.Login))).Methods(http.MethodGet)
	samlRoute.Handle("/saml/acs", config.SamlSP).Methods(http.MethodPost)

	return
}
