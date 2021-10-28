package handlers

import (
	"fmt"
	"io"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

type HTTPHandler struct {
	hashed string
}

func NewHTTPHandler() *HTTPHandler {
	return &HTTPHandler{hashed: ""}
}

func (h *HTTPHandler) HashPassword(rw http.ResponseWriter, r *http.Request) {
	d, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(rw, "Error on get body", http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword(d, 10)
	if err != nil {
		http.Error(rw, "Error on hash password", http.StatusInternalServerError)
		return
	}

	h.hashed = string(hash)

	fmt.Fprintf(rw, "You hashed password is %s\n", hash)
}

func (h *HTTPHandler) ComparePassword(rw http.ResponseWriter, r *http.Request) {
	d, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(rw, "Error on get body", http.StatusBadRequest)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(h.hashed), d)
	if err != nil {
		http.Error(rw, "Passwords does not match\n", http.StatusBadRequest)
		return
	}

	fmt.Fprintf(rw, "Passwords match\n")
}
