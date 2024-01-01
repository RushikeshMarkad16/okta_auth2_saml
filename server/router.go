package server

import (
	"net/http"

	"github.com/RushikeshMarkad16/okta_auth2_saml/config"
	"github.com/RushikeshMarkad16/okta_auth2_saml/handler"
	"github.com/gorilla/mux"
)

// InitRouter ...
func InitRouter() (router *mux.Router) {

	router = mux.NewRouter()
	oAuthRouter := router.PathPrefix("").Subrouter()

	oAuthRouter.HandleFunc("/oauth/login", handler.HandleOauthLogin).Methods(http.MethodGet)
	oAuthRouter.HandleFunc("/authorization-code/callback", handler.HandleCallback).Methods(http.MethodGet)
	http.Handle("/", router)

	samlRouter := router.PathPrefix("").Subrouter()
	samlRouter.Handle("/saml/login", config.SamlSP.RequireAccount(http.HandlerFunc(handler.HandleSamlLogin))).Methods(http.MethodGet)
	samlRouter.Handle("/saml/acs", config.SamlSP).Methods(http.MethodPost)

	return
}
