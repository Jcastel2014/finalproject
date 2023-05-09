package main

import (
	"errors"
	"log"
	"net/http"
)

func setCookieHandler(w http.ResponseWriter, r *http.Request) {

	cookie := http.Cookie{
		Name:     "setCookie",
		Value:    "setCookie",
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, &cookie)

	w.Write([]byte(cookie.Value))
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

	cookie.Value = "getCookie"

	w.Write([]byte(cookie.Value))
}

func main() {

	mux := http.NewServeMux()
	mux.HandleFunc("/set", setCookieHandler)
	mux.HandleFunc("/get", getCookieHandler)

	err := http.ListenAndServe(":3000", mux)

	log.Print("starting server: 4000")

	if err != nil {
		log.Fatal(err)
	}

}
