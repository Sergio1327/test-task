// Creating an http server and defining route
package server

import (
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"testtask/internal/db"
)

func Run() error {
	db, err := db.DBConnect()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	router := mux.NewRouter()
	router.HandleFunc("/user/register", RegisterHandler(db))
	router.HandleFunc("/user/auth", AuthHandler(db))
	router.HandleFunc("/user/phone", AuthMiddleWare(PhoneHandler(db)))
	router.HandleFunc("/user/{name}", AuthMiddleWare(GetUserByName(db)))

	err = http.ListenAndServe(":8080", router)
	if err != nil {
		log.Fatal(err)
	}

	return nil
}
