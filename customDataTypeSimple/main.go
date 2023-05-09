package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
)

type User struct {
	Name string
	Age  int
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/set", setCookieHandler)
	mux.HandleFunc("/get", getCookieHandler)

	log.Print("Listening...")
	err := http.ListenAndServe(":3100", mux)
	if err != nil {
		log.Fatal(err)
	}
}

func setCookieHandler(w http.ResponseWriter, r *http.Request) {
	user := User{Name: "Alice", Age: 30}
	userJSON, err := json.Marshal(user)
	if err != nil {
		log.Println(err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	cookieValue := base64.URLEncoding.EncodeToString(userJSON)
	cookie := http.Cookie{
		Name:     "setCookie",
		Value:    cookieValue,
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, &cookie)

	w.Write([]byte("cookie set!"))
}

func getCookieHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("setCookie")
	if err != nil {
		switch {
		case errors.Is(err, http.ErrNoCookie):
			http.Error(w, "cookie not found", http.StatusBadRequest)
		default:
			log.Println(err)
			http.Error(w, "server error", http.StatusInternalServerError)
		}
		return
	}

	userJSON, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		http.Error(w, "invalid cookie", http.StatusBadRequest)
		return
	}

	var user User
	err = json.Unmarshal(userJSON, &user)
	if err != nil {
		http.Error(w, "invalid cookie", http.StatusBadRequest)
		return
	}

	fmt.Fprintf(w, "Name: %q\n", user.Name)
	fmt.Fprintf(w, "Age: %d\n", user.Age)
}
