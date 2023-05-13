// Defining handler functionality for each ro
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

// Handler with HTTPmethod POST
//
//	function for login and password registration from the form.
//
// The password is hashed and stored in the database along with the logn.
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

// The authentication handler with HTTPmethod POST takes the data from the request body in json format (login and password)
// and compares it with the data from the database.
// As there is a hashed password in the database,
// it compares the password from the form with the hashed password by hashing algorithm.
// If the login and password match, it creates a jwt token
// and writes the ID and login of the authorized user in the payload. At the end we write the jwt token in the cookie
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
			http.Error(w, err.Error(), http.StatusInternalServerError)
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

// The GetUSerByName handler with  GET HTTPmethod retrieves the user from the database.
// The url has the {name} parameter,
// which is the name by which the user will be searched for in the database and his id,name,age will be sent in json format.
//
//	url structure : /user/{name}
//
// Example:  127.0.0.1:8080/user/Sergey
// Then you will get in response data about the user Sergey
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

// The PhoneHandler function handles 4 methods
// POST/GET/PUT/DELETE
func PhoneHandler(db *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {


		// With POST method user can add phone number to the database
		//  where each number will have its own unique phonNumID.
		// The data is taken from the request body. Recorded:
		//  the phone number , the description of the number and whether it is mobile
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
					return
				}
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			fmt.Fprintf(w, "id of your phoneNumber is %d", PhoneNumId)


		// With the Get method
		// The user has to enter a phone number in the q in url parameter and he will get a list of all the people who have this number
		// Structure url:127.0.0.1:8080/user/phone?q=<phone-number>
		// Example:
		// 127.0.0.1:8080/user/phone?q=998333040827
		// Returns the  all users who have this number
		case http.MethodGet:
			num := r.URL.Query().Get("q")
			if num == "" {
				http.Error(w, "missing phone number", http.StatusBadRequest)
				return
			}
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
				if err := rows.Scan(&Phone.PhoneNumID, &Phone.User_ID, &Phone.PhoneNumber, &Phone.Description, &ismobile); err != nil {
					http.Error(w, "error with parsing", http.StatusInternalServerError)
					return
				}
				if ismobile == 1 {
					Phone.IsMobile = true
				} else {
					Phone.IsMobile = false
				}
				numData = append(numData, Phone)
			}
			json.NewEncoder(w).Encode(numData)


		// With the http PUT method in the url by the id parameter, which is phoneNumID, 
		// you can update the number data, description and whether it is mobile or fax.
		// Example:
		// 127.0.0.1:8080/user/phone?id=5
		// the phone number with id=5 will be updated 
		// The data to update are taken from the body of the request	
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
				return
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
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			fmt.Fprint(w, "the data was succesfull update")


		// With the DELETE method 
		// You can delete a phone number and its data 
		// user_id is taken from the query context
		// The phone number is taken from the request body.
		// It checks if this number is in the database, if not, it returns an error.
		// If there are no errors the number is successfully removed from the database			
		case http.MethodDelete:
			var phoneNumber domain.PhoneData
			err := json.NewDecoder(r.Body).Decode(&phoneNumber)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			userId := strconv.FormatFloat(r.Context().Value("user_id").(float64), 'f', -1, 64)
			var count int
			err = db.QueryRow("select count(*) from user_details where user_id=? and phone=?", userId, phoneNumber.PhoneNumber).Scan(&count)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if count == 0 {
				http.Error(w, "this number does not exist in the database", http.StatusInternalServerError)
				return
			}
			_, err = db.Exec("delete from user_details where user_id=? and phone=?", userId, phoneNumber.PhoneNumber)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "phone number was succesfully deleted")
		default:
			http.Error(w, "mehtod not allowed", http.StatusMethodNotAllowed)
		}
	}
}
