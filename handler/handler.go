package handler

import (
	"fmt"
	"net/http"

	"github.com/crewjam/saml/samlsp"
)

func Login(w http.ResponseWriter, r *http.Request) {

	fmt.Fprintln(w, "Hello, ", samlsp.AttributeFromContext(r.Context(), "name"), " !!!")

	s := samlsp.SessionFromContext(r.Context())
	if s == nil {
		return
	}

	sa, ok := s.(samlsp.SessionWithAttributes)
	if !ok {
		return
	}

	fmt.Fprintln(w, "Name : ", sa.GetAttributes().Get("name"))
	fmt.Fprintln(w, "Email : ", sa.GetAttributes().Get("email"))

}
