package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"strconv"
	"testtask/domain"
	"testtask/internal/db"
)

func RegisterHandler(db *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		login := r.PostFormValue("login")
		password := r.PostFormValue("password")

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
		secretKey := []byte("123456789")
		tokenString, err := token.SignedString(secretKey)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "SESSTOKEN",
			Value:    tokenString,
			HttpOnly: true,
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

func PhoneAddHandler(db *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not alowed", http.StatusMethodNotAllowed)
			return
		}
		var PhoneData domain.PhoneData
		err := json.NewDecoder(r.Body).Decode(&PhoneData)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if len(PhoneData.PhoneNumber) > 12 {
			http.Error(w, "Phone-Number cannot have more than 12 digits", http.StatusInternalServerError)
			return
		}
		userID := strconv.FormatFloat(r.Context().Value("user_id").(float64), 'f', -1, 64)

		var count int

		err = db.QueryRow("select count(*) from user_details where user_id=? and phone=?", userID, PhoneData.PhoneNumber).Scan(&count)
		if err != nil {
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
		if count > 0 {
			http.Error(w, "phone number already exists", http.StatusConflict)
			return
		}

		var isMobile int
		if PhoneData.IsMobile {
			isMobile = 1
		} else {
			isMobile = 0
		}

		_, err = db.Exec("insert into user_details(user_id,phone,description,isMobile) values(?,?,?,?)", userID, PhoneData.PhoneNumber, PhoneData.Description, isMobile)
		if err != nil {
			fmt.Fprint(w, err)
			http.Error(w, "error", http.StatusInternalServerError)
			return
		}
	}
}
