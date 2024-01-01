package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"

	"github.com/RushikeshMarkad16/okta_auth2_saml/config"
	"github.com/crewjam/saml/samlsp"
)

// HandleSamlLogin ...
func HandleSamlLogin(w http.ResponseWriter, r *http.Request) {

	tmpl, err := template.ParseFiles("../template/home.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//  Get SAML session from the request context
	s := samlsp.SessionFromContext(r.Context())
	if s == nil {
		// if no session return
		return
	}

	sa, ok := s.(samlsp.SessionWithAttributes)
	if !ok {
		return
	}

	// Extract user attributes from the SAML session
	data := map[string]string{
		"Name":  sa.GetAttributes().Get("name"),
		"Email": sa.GetAttributes().Get("email"),
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// HandleOauthLogin ...
func HandleOauthLogin(w http.ResponseWriter, r *http.Request) {
	// Generate authorization url with state
	url := config.OktaOauthConfig.AuthCodeURL(config.OauthStateString)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// HandleCallback ...
func HandleCallback(w http.ResponseWriter, r *http.Request) {

	// Get state from query parameter
	state := r.URL.Query().Get("state")

	// Check if the state matches the expected OAuth state string
	if state != config.OauthStateString {
		http.Error(w, "Invalid oauth state", http.StatusBadRequest)
		return
	}

	// Get code from query parameter
	code := r.URL.Query().Get("code")
	fmt.Println("code : ", code)

	// Exchange token for authorization code
	token, err := config.OktaOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusBadRequest)
		return
	}
	fmt.Println("AccessToken : ", token.AccessToken)

	// Create an HTTP client
	client := config.OktaOauthConfig.Client(context.Background(), token)

	// Fetch user information from the Okta UserInfo endpoint
	response, err := client.Get("https://dev-64613000.okta.com/oauth2/default/v1/userinfo")
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusBadRequest)
		return
	}
	defer response.Body.Close()

	var userInfo map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&userInfo)
	if err != nil {
		http.Error(w, "Failed to parse userInfo", http.StatusBadRequest)
		return
	}

	tmpl, err := template.ParseFiles("../template/home.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Name":  userInfo["name"],
		"Email": userInfo["email"],
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
