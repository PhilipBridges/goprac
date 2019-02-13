package auth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"jwt/types"

	"jwt/database"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/crypto/bcrypt"
)

const (
	// SECRET for jwt
	SECRET = "secret"
)

var db *sql.DB

func main() {}

// Exists checkes if a username is already in use
func Exists(username string) bool {
	var exists bool

	_ = database.DBConn.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username=?)", username).Scan(&exists)

	if exists == true {
		return true
	}

	return false
}

// Register registers the user
func Register(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		http.Error(w, "Registration failed! (ioutil)", http.StatusBadRequest)
		return
	}

	var userData map[string]string
	json.Unmarshal(body, &userData)

	// Check if username is already in use
	existBool := Exists(userData["username"])

	fmt.Println(existBool)
	if existBool == true {
		http.Error(w, "Username already exists", http.StatusBadRequest)
		return
	}

	stmt, Preperr := database.DBConn.Prepare("INSERT INTO users(username, password) VALUES (?, ?)")

	if Preperr != nil {
		http.Error(w, Preperr.Error(), http.StatusInternalServerError)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(userData["password"]), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Registration failed.", http.StatusBadRequest)
	}

	if err != nil {
		fmt.Printf("Something went wrong: %s", err)
		return
	}
	_, DBerr := stmt.Exec(userData["username"], string(hash))

	if DBerr != nil {
		http.Error(w, Preperr.Error(), http.StatusInternalServerError)
	} else {
		JSONResponse(http.StatusOK, w)
	}

}

// Login logs the user in
func Login(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		http.Error(w, "Login failed!", http.StatusUnauthorized)
		return
	}

	var userData map[string]string
	json.Unmarshal(body, &userData)

	var username string
	var password []byte
	var id int

	rowErr := database.DBConn.QueryRow("SELECT id, username, password FROM users WHERE username=?", userData["username"]).Scan(&id, &username, &password)

	if rowErr != nil {
		http.Error(w, "User not found.", http.StatusBadRequest)
		return
	}
	hashErr := bcrypt.CompareHashAndPassword(password, []byte(userData["password"]))

	if hashErr != nil {
		http.Error(w, "Invalid password.", http.StatusUnauthorized)
		return
	}

	// Demo - in real case scenario you'd check this against your database
	claims := types.JWTData{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},

		CustomClaims: map[string]interface{}{
			"username": username,
			"userid":   id,
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

	if err != nil {
		fmt.Println("token error")
		log.Println(err)
		http.Error(w, "Login failed!", http.StatusUnauthorized)
	} else {
		JSONResponse(tStruct, w)
	}
}

// JSONResponse is a template for JSON responses
func JSONResponse(response interface{}, w http.ResponseWriter) {

	json, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(json)
}

// GetUser retrieves the current account
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

// GetAccountData queries the current user
func GetAccountData(userID interface{}) ([]byte, error) {
	var id int
	var username string

	rowErr := database.DBConn.QueryRow("SELECT id, username FROM users WHERE id=?", userID).Scan(&id, &username)

	if rowErr != nil {
		return nil, rowErr
	}
	output := types.UserPublic{ID: id, Username: username}
	
	json, err := json.Marshal(output)
	if err != nil {
		return nil, err
	}

	return json, nil
}
