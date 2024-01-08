package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/RushikeshMarkad16/okta_auth2_saml/config"
	"github.com/RushikeshMarkad16/okta_auth2_saml/utils"
	"github.com/crewjam/saml/samlsp"
	"github.com/gorilla/sessions"
)

var (
	sessionStore = sessions.NewCookieStore([]byte("sdfg34jb%^"))
	Client       *http.Client
)

func HandleLandingPage(w http.ResponseWriter, r *http.Request) {

	tmpl, err := template.ParseFiles("./template/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := struct{}{}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// HandleSamlLogin ...
func HandleSamlLogin(w http.ResponseWriter, r *http.Request) {

	tmpl, err := template.ParseFiles("./template/home.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//  Get SAML session from the request context
	s := samlsp.SessionFromContext(r.Context())
	if s == nil {
		fmt.Println("Session does not exist")
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
		"Type":  "saml",
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// HandleSamlLogout ...
func HandleSamlLogout(w http.ResponseWriter, r *http.Request) {

	// Get session from the request context
	s := samlsp.SessionFromContext(r.Context())
	if s == nil {
		fmt.Println("Session does not exist")
		return
	}

	sa, ok := s.(samlsp.SessionWithAttributes)
	if !ok {
		return
	}

	// Generate a SAML LogoutRequest
	logoutURL, err := config.SamlSP.ServiceProvider.MakeRedirectLogoutRequest(sa.GetAttributes().Get("email"), "")
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating LogoutRequest: %s", err), http.StatusInternalServerError)
		return
	}

	err = config.SamlSP.Session.DeleteSession(w, r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error deleting cookies: %s", err), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, logoutURL.String(), http.StatusFound)
}

// SamlSLOLogout ...
func SamlSLOLogout(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login", http.StatusFound)
}

// HandleOauthLogin ...
func HandleOauthLogin(w http.ResponseWriter, r *http.Request) {

	OauthStateString := utils.GenerateRandomState(10)

	session, err := sessionStore.Get(r, "okta-session")
	if err != nil {
		http.Error(w, "Failed to get session", http.StatusInternalServerError)
		return
	}
	session.Values["state"] = OauthStateString
	session.Save(r, w)

	// Generate authorization url with state
	url := config.OktaOauthConfig.AuthCodeURL(OauthStateString)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// HandleCallback ...
func HandleCallback(w http.ResponseWriter, r *http.Request) {

	var err error

	session, err := sessionStore.Get(r, "okta-session")
	if err != nil {
		http.Error(w, "Failed to get session", http.StatusInternalServerError)
		return
	}

	storedState, ok := session.Values["state"].(string)
	if !ok {
		http.Error(w, "Invalid session state", http.StatusBadRequest)
		return
	}

	// Check the state returned in the callback matches the stored state
	state := r.URL.Query().Get("state")
	if state != storedState {
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

	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "ID token not found", http.StatusBadRequest)
		return
	}
	fmt.Println("idToken : ", idToken)

	session.Values["id_token"] = idToken
	session.Values["access_token"] = token.AccessToken
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	// Create an HTTP client
	Client = config.OktaOauthConfig.Client(context.Background(), token)

	http.Redirect(w, r, "/home", http.StatusFound)
}

// HandleHome ...
func HandleHome(w http.ResponseWriter, r *http.Request) {

	// Fetch user information from the Okta UserInfo endpoint
	response, err := Client.Get(os.Getenv("UserInfoEndpoint"))
	if err != nil || response.StatusCode != http.StatusOK {
		http.Error(w, "Invalid access token", response.StatusCode)
		return
	}
	defer response.Body.Close()

	var userInfo map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&userInfo)
	if err != nil {
		http.Error(w, "Failed to parse UserInfo", http.StatusBadRequest)
		return
	}

	tmpl, err := template.ParseFiles("./template/home.html")
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

// HandleOauthLogout ...
func HandleOauthLogout(w http.ResponseWriter, r *http.Request) {

	session, err := sessionStore.Get(r, "okta-session")
	if err != nil {
		http.Error(w, "Failed to get session", http.StatusInternalServerError)
		return
	}

	idToken := session.Values["id_token"].(string)

	oktaLogoutURL := os.Getenv("LOGOUT_URL") + fmt.Sprintf("?id_token_hint=%s&post_logout_redirect_uri=%s", idToken, "https://okta-auth2-saml.onrender.com/logout/callback")
	fmt.Println("oktaLogoutURL : ", oktaLogoutURL)

	http.Redirect(w, r, oktaLogoutURL, http.StatusFound)

}

// HandleLogoutCallback ...
func HandleLogoutCallback(w http.ResponseWriter, r *http.Request) {

	session, err := sessionStore.Get(r, "okta-session")
	if err != nil {
		http.Error(w, "Failed to get session", http.StatusInternalServerError)
		return
	}

	accessToken := session.Values["access_token"].(string)

	session.Values = map[interface{}]interface{}{}
	session.Options.MaxAge = -1
	session.Save(r, w)

	data := url.Values{}
	data.Set("token", accessToken)
	data.Set("token_type_hint", "access_token")

	client := &http.Client{}
	req, err := http.NewRequest("POST", os.Getenv("REVOKE_TOKEN_URL"), strings.NewReader(data.Encode()))
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	req.Header.Add("Authorization", "Basic MG9hZHphbG11M0JrQTZKdVo1ZDc6V0pDa1RHaHVhbmM3ODYwNFFfN05FQ0RmYjJDVHh5b2FNVGd4ZG5MQk1uTXNkc21BdVJVazJ1X2tsZDNuV01NZA==")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	fmt.Println("req", req)
	res, err := client.Do(req)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if res.StatusCode != http.StatusOK {
		http.Error(w, "Invalid req", res.StatusCode)
		return
	}

	http.Redirect(w, r, "/login", http.StatusFound)
}
