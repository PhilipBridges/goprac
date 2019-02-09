package auth

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"jwt/types"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/julienschmidt/httprouter"
)

const (
	SECRET = "secret"
)

func main() {}

func JsonResponse(response interface{}, w http.ResponseWriter) {

	json, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(json)
}

// Function for retreiving a current account
// Make this return data, err
func GetUser(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	authToken := r.Header.Get("Authorization")
	authArr := strings.Split(authToken, " ")

	if len(authArr) != 2 {
		log.Println("Authentication header is invalid: " + authToken)
		http.Error(w, "Request failed!", http.StatusUnauthorized)
		return
	}

	jwtToken := authArr[1]

	claims, err := jwt.ParseWithClaims(jwtToken, &types.JWTData{}, func(token *jwt.Token) (interface{}, error) {
		if jwt.SigningMethodHS256 != token.Method {
			return nil, errors.New("Invalid signing algorithm")
		}
		return []byte(SECRET), nil
	})

	if err != nil {
		log.Println(err)
		http.Error(w, "Request failed!", http.StatusUnauthorized)
		return
	}

	data := claims.Claims.(*types.JWTData)

	userID := data.CustomClaims["userid"]

	// fetch some data based on the userID and then send that data back to the user in JSON format
	jsonData, err := GetAccountData(userID)
	if err != nil {
		log.Println(err)
		http.Error(w, "Request failed!", http.StatusUnauthorized)
	}

	w.Write(jsonData)
}

func GetAccountData(userID string) ([]byte, error) {
	output := types.Account{"nikola.breznjak@gmail.com", 3.14, "BTC"}
	json, err := json.Marshal(output)
	if err != nil {
		return nil, err
	}

	return json, nil
}
