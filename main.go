package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
	"github.com/julienschmidt/httprouter"
	"github.com/rs/cors"

	auth "jwt/auth"
	"jwt/database"
	posts "jwt/posts"
)

const (
	// PORT is the port the server uses
	PORT = "8000"
	// SECRET key for signing password
	SECRET = "secret"
)

var db *sql.DB

// Just check auth at start of handlers

func main() {
	var err error

	database.DBConn, err = sql.Open("mysql", "<username>:<password>@<db-address>")
	defer db.Close()

	if err != nil {
		fmt.Println("WOW PANIC")
		panic(err.Error()) // Just for example purpose. You should use proper error handling instead of panic
	}

	router := httprouter.New()
	router.POST("/login", auth.Login)
	router.POST("/register", auth.Register)
	router.GET("/account", auth.GetUser)
	// TODO
	router.POST("/posts", posts.CreatePost)

	handler := cors.Default().Handler(router)

	log.Println("Listening for connections on port: ", PORT)
	log.Fatal(http.ListenAndServe(":"+PORT, handler))
}
