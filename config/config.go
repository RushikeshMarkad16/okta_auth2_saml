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

var (
	SamlSP *samlsp.Middleware
)

func congifSP() {
	keyPair, err := tls.LoadX509KeyPair("../myservice.cert", "../myservice.key")
	if err != nil {
		panic(err)
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err)
	}

	idpMetadataURL, err := url.Parse("https://dev-64613000.okta.com/app/exke1hterjGJvfW4w5d7/sso/saml/metadata")
	if err != nil {
		panic(err)
	}
	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient,
		*idpMetadataURL)
	if err != nil {
		panic(err)
	}

	rootURL, err := url.Parse("http://localhost:8080")
	if err != nil {
		panic(err)
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
		panic(err)

	}
}

func Load() {
	congifSP()
}
