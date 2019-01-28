package main

import (
	"github.com/gorilla/mux"
	"github.com/gorilla/handlers"
	"log"
	jwt "github.com/dgrijalva/jwt-go"
	"net/http"
	"fmt"
	"time"
	"encoding/json"
	"os"
	"github.com/chongpq/login"
	"github.com/chongpq/jwtAuth"
)

const (
	TOKEN_SECRET = "TOKEN_SECRET"
	ACCESS_TOKEN_DUR = time.Hour * 24
	REFRESH_TOKEN_DUR = ACCESS_TOKEN_DUR * 7
)

var processError = func (msg string, w http.ResponseWriter) {
	w.WriteHeader(http.StatusForbidden)
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{} {"status" : false, "message" : msg})
}

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	fmt.Fprintf(w, "{}")
}

func refreshHandler(w http.ResponseWriter, r *http.Request) {
	processToken := func(t *jwt.Token) {
		w.Header().Add("Content-Type", "application/json")
		if claim, ok := t.Claims.(*jwt.StandardClaims); ok && t.Valid {
			if loginDetail, ok := login.Logins[claim.Audience]; ok {
				if loginDetail.RefreshToken == t.Raw {
					now := time.Now();
					claims := &jwt.StandardClaims{
							ExpiresAt: now.Add(ACCESS_TOKEN_DUR).Unix(),
							Audience:  claim.Audience,
						}
					token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
					accessTokenString, _ := token.SignedString([]byte(os.Getenv(TOKEN_SECRET)))

					json.NewEncoder(w).Encode(map[string]interface{} {"status" : true, "message" : "Logged In", "access_token" : accessTokenString})
				} else {
					w.WriteHeader(http.StatusForbidden)
					json.NewEncoder(w).Encode(map[string]interface{} {"status" : false, "message" : "Invalid login credentials. Please try again"})
				}
			} else {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]interface{} {"status" : false, "message" : "Invalid login credentials. Please try again"})
			}
		} else { //Token is invalid, maybe not signed on this server
			processError("Token is not valid.", w)
		}
	}

	jwtAuth.ProcessAuthorizationHeader(w, r, processToken, processError)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	w.Header().Add("Content-Type", "application/json")
	if loginDetail, ok := login.Logins[r.Form.Get("username")]; ok {
		if loginDetail.Password == r.Form.Get("password") {
			now := time.Now();
			claims := &jwt.StandardClaims{
				    ExpiresAt: now.Add(ACCESS_TOKEN_DUR).Unix(),
				    Audience:  r.Form.Get("username"),
				}
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			accessTokenString, _ := token.SignedString([]byte(os.Getenv(TOKEN_SECRET)))

			claims.ExpiresAt = now.Add(REFRESH_TOKEN_DUR).Unix()
			token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			refreshTokenString, _ := token.SignedString([]byte(os.Getenv(TOKEN_SECRET)))
			loginDetail.RefreshToken = refreshTokenString
			login.Logins[r.Form.Get("username")] = loginDetail
			json.NewEncoder(w).Encode(map[string]interface{} {"status" : true, "message" : "Logged In", "access_token" : accessTokenString, "refresh_token" : refreshTokenString})
		} else {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{} {"status" : false, "message" : "Invalid login credentials. Please try again"})
		}
	} else {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{} {"status" : false, "message" : "Invalid login credentials. Please try again"})
	}
}

func main() {
	jwtAuth.JwtAuthExcludedList = []string{"/login","/refresh"}
	jwtAuth.TOKEN_SECRET = os.Getenv(TOKEN_SECRET)
	jwtAuth.ProcessErr = processError
	login.ReadCsv()
	r := mux.NewRouter()
	r.HandleFunc("/refresh", refreshHandler).Methods("POST")
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/", handler).Methods("GET")
	r.Use(jwtAuth.JwtAuthentication)
	headersOk := handlers.AllowedHeaders([]string{"X-Requested-With"})
	originsOk := handlers.AllowedOrigins([]string{"*"})
	methodsOk := handlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "OPTIONS"})
	log.Fatal(http.ListenAndServe(":8000", handlers.CORS(originsOk, headersOk, methodsOk)(r)))
}
