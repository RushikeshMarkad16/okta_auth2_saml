package handler

import (
	"fmt"
	"net/http"

	"github.com/crewjam/saml/samlsp"
)

func Login(w http.ResponseWriter, r *http.Request) {

	fmt.Fprintf(w, "Hello, %s!", samlsp.AttributeFromContext(r.Context(), "name"))

	s := samlsp.SessionFromContext(r.Context())
	if s == nil {
		return
	}

	sa, ok := s.(samlsp.SessionWithAttributes)
	if !ok {
		return
	}
	fmt.Fprintf(w, "Token contents, %+v!", sa.GetAttributes())
}
