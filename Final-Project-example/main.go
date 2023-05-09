// Filename: main.go
package main

import (
    "encoding/base64"
    "errors"
    "net/http"
    "log"
)

var (
    ErrValueTooLong = errors.New("cookie value too long")
    ErrInvalidValue = errors.New("invalid cookie value")
)

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
    // Initialize the cookie as normal.
    cookie := http.Cookie{
        Name:     "exampleCookie",
        Value:    "Hello Zoë!",
        Path:     "/",
        MaxAge:   3600,
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteLaxMode,
    }

    err := Write(w, cookie)
    if err != nil {
        log.Println(err)
        http.Error(w, "server error", http.StatusInternalServerError)
        return
    }

    w.Write([]byte("cookie set!"))
}

func getCookieHandler(w http.ResponseWriter, r *http.Request) {
    
    value, err := Read(r, "exampleCookie")
    if err != nil {
        switch {
        case errors.Is(err, http.ErrNoCookie):
            http.Error(w, "cookie not found", http.StatusBadRequest)
        case errors.Is(err, ErrInvalidValue):
            http.Error(w, "invalid cookie", http.StatusBadRequest)
        default:
            log.Println(err)
            http.Error(w, "server error", http.StatusInternalServerError)
        }
        return
    }

    w.Write([]byte(value))
}

func Write(w http.ResponseWriter, cookie http.Cookie) error {
    
    cookie.Value = base64.URLEncoding.EncodeToString([]byte(cookie.Value))

    if len(cookie.String()) > 4096 {
        return ErrValueTooLong
    }

    http.SetCookie(w, &cookie)

    return nil
}

func Read(r *http.Request, name string) (string, error) {
    cookie, err := r.Cookie(name)
    if err != nil {
        return "", err
    }

    value, err := base64.URLEncoding.DecodeString(cookie.Value)
    if err != nil {
        return "", ErrInvalidValue
    }

    return string(value), nil
}
