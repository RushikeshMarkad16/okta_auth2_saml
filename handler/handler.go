package handler

import (
	"html/template"
	"net/http"

	"github.com/crewjam/saml/samlsp"
)

func Login(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.New("login").Parse(`
	<!DOCTYPE html>
	<html>
	<head>
		<title>Home Page</title>
		<style>
			body {
				font-family: Arial, sans-serif;
				background-color: #f4f4f4;
				text-align: center;
			}
			.container {
				display: inline-block;
				text-align: left;
				border: 1px solid #ccc;
				padding: 10px;
				margin: 20px;
				border-radius: 5px;
				background-color: #fff;
			}
			h1 {
				color: #333;
			}
			p {
				color: #666;
				margin: 5px 0;
			}
		</style>
	</head>
	<body>
		<div class="container">
			<h1>Hello, {{.Name}} !!!</h1>
			<p><strong>Name:</strong> {{.Name}}</p>
			<p><strong>Email:</strong> {{.Email}}</p>
		</div>
	</body>
	</html>`))

	s := samlsp.SessionFromContext(r.Context())
	if s == nil {
		return
	}

	sa, ok := s.(samlsp.SessionWithAttributes)
	if !ok {
		return
	}

	data := map[string]string{
		"Name":  sa.GetAttributes().Get("name"),
		"Email": sa.GetAttributes().Get("email"),
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
