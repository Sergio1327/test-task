package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"testtask/domain"
	"testtask/internal/db"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

func RegisterHandler(db *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		login := r.PostFormValue("login")
		password := r.PostFormValue("password")

		login = "123"
		password = "sa2003"

		if login == "" || password == "" {
			http.Error(w, "login or password is empty", http.StatusBadRequest)
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		_, err = db.Exec("insert into users(login,password) values(?,?)", login, hashedPassword)
		if err != nil {
			http.Error(w, "error", http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, "succesfully registered")
	}
}

func AuthHandler(db *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		User := domain.User{}

		err := json.NewDecoder(r.Body).Decode(&User)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		RegUser := domain.RegisteredUser{}
		err = db.Db.QueryRow("select id,login,password from users where login=?", User.Login).Scan(
			&RegUser.ID, &RegUser.Login, &RegUser.HashedPassword)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				http.Error(w, "invalid login or password", http.StatusUnauthorized)
				return
			}
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}

		err = bcrypt.CompareHashAndPassword(RegUser.HashedPassword, []byte(User.Password))
		if err != nil {
			http.Error(w, "invalid login or password", http.StatusUnauthorized)
			return
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id": RegUser.ID,
			"login":   RegUser.Login,
		})
		secretKey := []byte("")
		tokenString, err := token.SignedString(secretKey)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "SESSTOKEN",
			Value:    tokenString,
			HttpOnly: true,
			Path:     "/",
		})
		fmt.Fprint(w, "User authenticated successfully")
	}
}

func GetUserByName(db *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := mux.Vars(r)["name"]
		var U domain.UsersTable
		row := db.Db.QueryRow("select id,name,age from userstable where name=?", name)

		err := row.Scan(&U.Id, &U.Name, &U.Age)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				http.Error(w, "no user with this name", http.StatusInternalServerError)
				return
			}
			log.Println(err)
			return
		}
		json.NewEncoder(w).Encode(U)
	}

}
