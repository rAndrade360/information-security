package main

import (
	"net/http"

	"github.com/rAndrade360/information-security/go/authentication/handlers"
)

func main() {
	httpHandler := handlers.NewHTTPHandler()

	http.HandleFunc("/hash", httpHandler.HashPassword)
	http.HandleFunc("/compare", httpHandler.ComparePassword)
	http.HandleFunc("/login", httpHandler.Login)
	http.HandleFunc("/private", httpHandler.Private)

	http.ListenAndServe(":3030", nil)
}
