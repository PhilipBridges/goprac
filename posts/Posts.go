package posts

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	auth "jwt/auth"
	"jwt/database"
	"jwt/types"

	"github.com/julienschmidt/httprouter"
)

var db *sql.DB

func main() {}

// CreatePost ...creates a post
func CreatePost(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

	body, err := ioutil.ReadAll(r.Body)

	if err != nil {
		http.Error(w, "Post failed! (Couldn't read body", http.StatusBadRequest)
		return
	}

	var postData map[string]string
	json.Unmarshal(body, &postData)

	fmt.Println(postData["body"])
	stmt, Preperr := database.DBConn.Prepare("INSERT INTO posts(body, author_id) VALUES (?, ?)")

	if Preperr != nil {
		http.Error(w, Preperr.Error(), http.StatusInternalServerError)
		return
	}
	stmt.Exec(postData["body"], postData["author_id"])
	auth.JSONResponse(types.Generic{Data: "OK"}, w)
}
