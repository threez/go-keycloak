package main

import (
	"log"
	"net/http"
	"os"
	"text/template"

	oidc "github.com/coreos/go-oidc"
	"github.com/gorilla/handlers"
	"github.com/threez/go-keycloak"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/home", func(w http.ResponseWriter, r *http.Request) {
		s := keycloak.GetSession(r.Context())
		var claims keycloak.StandardClaims
		err := s.Claims(&claims)
		if err != nil {
			log.Print(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		err = home.Execute(w, &claims)
		if err != nil {
			log.Print(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	})
	mux.Handle("/", http.FileServer(http.Dir("./public")))

	mdw := keycloak.Middleware{
		BaseURL:    "http://localhost:8080",
		PathPrefix: "/session",
		Logger:     log.Println,
		Scopes: []string{ // "openid" is a required scope for OpenID Connect flows.
			oidc.ScopeOpenID, "profile", "email",
		},
		SessionStore: keycloak.NewInsecureStore("/home"),
	}
	err := mdw.ConnectWithKeycloak("keycloak.json")
	if err != nil {
		log.Fatal(err)
	}

	loggedRouter := handlers.LoggingHandler(os.Stdout, mdw.Handler(mux))
	http.ListenAndServe(":8080", loggedRouter)
}

var home = template.Must(template.New("Index").Parse(`
<html>
<head>

</head>
<body>
	<h3>Hello {{ .Name }}</h3>

	<a href="/session/account">Account</a>
	<a href="/session/logout">Logout</a>
</body>
</html>
`))
