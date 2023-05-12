package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
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

func PhoneHandler(db *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
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
				http.Error(w, "error", http.StatusInternalServerError)
				return
			}
			var PhoneNumId int
			err = db.QueryRow("select phoneNumID from user_details where phone=?", PhoneData.PhoneNumber).Scan(&PhoneNumId)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					http.Error(w, "No phone number", http.StatusInternalServerError)
				}
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			fmt.Fprintf(w, "id of your phoneNumber is %d", PhoneNumId)
		case http.MethodGet:
			num := r.URL.Query().Get("q")
			rows, err := db.Query("select * from user_details where phone=?", num)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					http.Error(w, "no data with this phone number", http.StatusInternalServerError)
					return
				}
				http.Error(w, "error", http.StatusInternalServerError)
				return
			}
			defer rows.Close()
			var numData []domain.DBPhoneData
			for rows.Next() {
				var Phone domain.DBPhoneData
				var ismobile int
				if err := rows.Scan(&Phone.PhoneNumID, &Phone.ID, &Phone.PhoneNumber, &Phone.Description, &ismobile); err != nil {
					http.Error(w, "error with parsing", http.StatusInternalServerError)
				}
				if ismobile == 1 {
					Phone.IsMobile = true
				} else {
					Phone.IsMobile = false
				}
				numData = append(numData, Phone)
			}
			json.NewEncoder(w).Encode(numData)
		case http.MethodPut:
			phoneNumId := r.URL.Query().Get("id")
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
			userId := strconv.FormatFloat(r.Context().Value("user_id").(float64), 'f', -1, 64)

			var count int
			err = db.QueryRow("select count(*) from user_details where user_id=? and phoneNumID=?", userId, phoneNumId).Scan(&count)
			if err != nil {
				http.Error(w, "error", http.StatusInternalServerError)
			}
			if count == 0 {
				http.Error(w, "phone number does not exist", http.StatusNotFound)
				return
			}
			var isMobile int
			if PhoneData.IsMobile {
				isMobile = 1
			} else {
				isMobile = 0
			}
			_, err = db.Exec("update user_details set phone=?,description=?, isMobile=? where user_id=? and phoneNumID=?", PhoneData.PhoneNumber, PhoneData.Description, isMobile, userId, phoneNumId)
			if err != nil {
				fmt.Fprint(w, err)
				http.Error(w, "error", http.StatusInternalServerError)
				return
			}
			fmt.Fprint(w, "the data was succesfull update")
		}
	}
}
