package config

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"

	"github.com/crewjam/saml/samlsp"
)

var SamlSP *samlsp.Middleware

func serviceProviderConfig() error {
	keyPair, err := tls.LoadX509KeyPair("../myservice.cert", "../myservice.key")
	if err != nil {
		return err
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return err
	}

	idpMetadataURL, err := url.Parse("https://dev-64613000.okta.com/app/exke1hterjGJvfW4w5d7/sso/saml/metadata")
	if err != nil {
		return err
	}
	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient,
		*idpMetadataURL)
	if err != nil {
		return err
	}

	rootURL, err := url.Parse("http://localhost:8080")
	if err != nil {
		return err
	}

	SamlSP, err = samlsp.New(samlsp.Options{
		EntityID:    "http://localhost:8080",
		URL:         *rootURL,
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
	})

	if err != nil {
		fmt.Println("Error : ", err)
		return err

	}
	return nil
}

func Load() {
	err := serviceProviderConfig()
	if err != nil {
		fmt.Println("Error : ", err)
	}
}
