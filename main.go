package main

import (
	"encoding/json"
	"io/ioutil"
	"jwt/types"
	"log"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/julienschmidt/httprouter"
	"github.com/rs/cors"

	auth "jwt/auth"
)

const (
	// PORT is the port the server uses
	PORT = "8000"
	// SECRET key for signing password
	SECRET = "secret"
)

// Just check auth at start of handlers

func main() {
	router := httprouter.New()
	router.POST("/login", login)
	router.POST("/account", auth.GetUser)

	handler := cors.Default().Handler(router)

	log.Println("Listening for connections on port: ", PORT)
	log.Fatal(http.ListenAndServe(":"+PORT, handler))
}

func login(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		http.Error(w, "Login failed!", http.StatusUnauthorized)
		return
	}

	var userData map[string]string
	json.Unmarshal(body, &userData)

	// Demo - in real case scenario you'd check this against your database
	if userData["email"] == "admin@gmail.com" && userData["password"] == "admin123" {
		claims := types.JWTData{
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
			},

			CustomClaims: map[string]string{
				"userid": "u1",
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(SECRET))
		if err != nil {
			log.Println(err)
			http.Error(w, "Login failed!", http.StatusUnauthorized)
			return
		}

		tStruct := struct {
			Token string `json:"token"`
		}{
			tokenString,
		}

		auth.JsonResponse(tStruct, w)

		if err != nil {
			log.Println(err)
			http.Error(w, "Login failed!", http.StatusUnauthorized)
		}

	} else {
		http.Error(w, "Login failed!", http.StatusUnauthorized)
	}
}
