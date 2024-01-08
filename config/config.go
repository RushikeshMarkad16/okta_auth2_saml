package config

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

var (
	SamlSP          *samlsp.Middleware
	OktaOauthConfig *oauth2.Config
)

func oauthConfig() {
	OktaOauthConfig = &oauth2.Config{
		ClientID:     os.Getenv("ClientID"),
		ClientSecret: os.Getenv("ClientSecret"),
		RedirectURL:  os.Getenv("RedirectURL"),
		Scopes:       []string{"openid", "profile", "email", "address", "phone"},
		Endpoint: oauth2.Endpoint{
			TokenURL: os.Getenv("TokenURL"),
			AuthURL:  os.Getenv("AuthURL"),
		},
	}
}

func samlConfig() {
	keyPair, err := tls.LoadX509KeyPair("./certificate.pem", "./privatekey.pem")
	if err != nil {
		fmt.Println("Error : ", err)
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		fmt.Println("Error : ", err)
	}

	idpMetadataURL, err := url.Parse(os.Getenv("MetadataURL"))
	if err != nil {
		fmt.Println("Error : ", err)
	}
	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient,
		*idpMetadataURL)
	if err != nil {
		fmt.Println("Error : ", err)
	}

	rootURL, err := url.Parse(os.Getenv("RootURL"))
	if err != nil {
		fmt.Println("Error : ", err)
	}

	SamlSP, err = samlsp.New(samlsp.Options{
		EntityID:    os.Getenv("EntityID"),
		URL:         *rootURL,
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
		SignRequest: true,
	})
	// SamlSP.ServiceProvider.AuthnNameIDFormat = saml.UnspecifiedNameIDFormat
	SamlSP.Binding = saml.HTTPPostBinding
	if err != nil {
		fmt.Println("Error : ", err)
	}
}

// Load ...
func Load() {
	err := godotenv.Load("./.env")
	if err != nil {
		fmt.Println("error : ", err)
		log.Fatal("Error loading .env file")
	}

	oauthConfig()
	samlConfig()
}
