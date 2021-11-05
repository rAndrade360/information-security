package handlers

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
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

func (h *HTTPHandler) Login(rw http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(rw, "Internal server error \n", http.StatusInternalServerError)
		return
	}

	user := r.PostFormValue("username")
	password := r.PostFormValue("password")

	if user != "admin" {
		http.Error(rw, "User not found \n", http.StatusNotFound)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(h.hashed), []byte(password))
	if err != nil {
		http.Error(rw, "Passwords does not match\n", http.StatusBadRequest)
		return
	}

	token := jwt.New(jwt.SigningMethodHS256)
	refresh_token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["id"] = 1
	claims["username"] = user
	claims["exp"] = time.Now().Add(time.Hour * 1).Unix()

	rtclaims := refresh_token.Claims.(jwt.MapClaims)
	rtclaims["exp"] = time.Now().Add(time.Hour * 6).Unix()
	rtclaims["id"] = 1

	t, err := token.SignedString([]byte("secret"))
	if err != nil {
		http.Error(rw, "Internal server error \n", http.StatusInternalServerError)
		return
	}

	rt, err := refresh_token.SignedString([]byte("secret"))
	if err != nil {
		http.Error(rw, "Internal server error \n", http.StatusInternalServerError)
		return
	}

	fmt.Fprint(rw, map[string]string{"token": t, "refresh_token": rt})
}
