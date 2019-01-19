package main

import (
	"bufio"
	"encoding/csv"
	"io"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"fmt"
	"strings"
	"time"
	"encoding/json"
	jwt "github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"os"
)

type loginDetail struct {
	Password  string
	RefreshToken string
}

var logins = make(map[string]loginDetail)

var jwtAuthentication = func(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		requestPath := r.URL.Path //current request path

		//check if request does not need authentication, serve the request if it doesn't need it
		for _, value := range []string{"/login", "/refresh"} {

			if value == requestPath {
				next.ServeHTTP(w, r)
				return
			}
		}
		a := func(t *jwt.Token) {
			if _, ok := t.Claims.(*jwt.StandardClaims); ok && t.Valid {
				//Everything went well, proceed with the request
				next.ServeHTTP(w, r)
			} else { //Token is invalid, maybe not signed on this server
				create403Response("Token is not valid.", w)
				return
			}
		}
		authorizationHeaderCheck(w, r, a)
	});
}

func authorizationHeaderCheck(w http.ResponseWriter, r *http.Request, callback func(t *jwt.Token)) {
	tokenHeader := r.Header.Get("Authorization") //Grab the token from the header

	if tokenHeader == "" { //Token is missing, returns with error code 403 Unauthorized
		create403Response("Missing auth token", w)
		return
	}

	splitted := strings.Split(tokenHeader, " ") //The token normally comes in format `Bearer {token-body}`, we check if the retrieved token matched this requirement
	if len(splitted) != 2 {
		create403Response("Invalid/Malformed auth token", w)
		return
	}

	tokenPart := splitted[1] //Grab the token part, what we are truly interested in

	token, err := jwt.ParseWithClaims(tokenPart, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("secret")), nil
	})

	if err != nil { //Malformed token, returns with http code 403 as usual
		log.Println(err)
		create403Response("Malformed authentication token", w)
		return
	}

	callback(token)
}

func readCsv() {
	csvFile, err := os.Open("people.csv")
	if err != nil {
		log.Fatal(err)
	}
	reader := csv.NewReader(bufio.NewReader(csvFile))
	for {
		line, error := reader.Read()
		if error == io.EOF {
			break
		} else if error != nil {
			log.Fatal(error)
		}
		logins[line[0]] = loginDetail{ Password: line[1] }
	}
}

func create403Response(msg string, w http.ResponseWriter) {
	w.WriteHeader(http.StatusForbidden)
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{} {"status" : false, "message" : msg})
	return
}

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	fmt.Fprintf(w, "{}")
}

func refreshHandler(w http.ResponseWriter, r *http.Request) {
	a := func(t *jwt.Token) {
		if claim, ok := t.Claims.(*jwt.StandardClaims); ok && t.Valid {
			w.Header().Add("Content-Type", "application/json")
			if loginDetail, ok := logins[claim.Audience]; ok {
			fmt.Println(claim.Audience)
			fmt.Println(loginDetail)
			fmt.Println(t.Raw)
				hashedRefreshToken, _  := bcrypt.GenerateFromPassword([]byte(t.Raw), bcrypt.DefaultCost)
			fmt.Println(string(hashedRefreshToken))
				if loginDetail.RefreshToken == t.Raw { //string(hashedRefreshToken) {
					now := time.Now();
					claims := &jwt.StandardClaims{
							ExpiresAt: now.Add(time.Minute * 1).Unix(),
							Audience:  claim.Audience,
						}
					token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
					accessTokenString, _ := token.SignedString([]byte(os.Getenv("secret")))

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
			create403Response("Token is not valid.", w)
			return
		}
	}
	authorizationHeaderCheck(w, r, a)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	w.Header().Add("Content-Type", "application/json")
	if loginDetail, ok := logins[r.Form.Get("username")]; ok {
		if loginDetail.Password == r.Form.Get("password") {
			now := time.Now();
			claims := &jwt.StandardClaims{
				    ExpiresAt: now.Add(time.Minute * 1).Unix(),
				    Audience:  r.Form.Get("username"),
				}
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			accessTokenString, _ := token.SignedString([]byte(os.Getenv("secret")))

			claims.ExpiresAt = now.Add(time.Minute * 10).Unix()
			token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			refreshTokenString, _ := token.SignedString([]byte(os.Getenv("secret")))
			//hashedRefreshTokenString, _ := bcrypt.GenerateFromPassword([]byte(refreshTokenString), bcrypt.DefaultCost)
			loginDetail.RefreshToken = refreshTokenString //string(hashedRefreshTokenString)
			logins[r.Form.Get("username")] = loginDetail
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
	readCsv()
	r := mux.NewRouter()
	//r.Headers("Content-Type", "application/json")
	r.HandleFunc("/refresh", refreshHandler).Methods("POST")
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/", handler).Methods("GET")

	r.Use(jwtAuthentication)
	log.Fatal(http.ListenAndServe(":8000",r))
}
