package server

import (
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
	router := http.NewServeMux()
	router.HandleFunc("/user/register", RegisterHandler(db))
	router.HandleFunc("/user/auth", AuthHandler(db))
	router.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {})

	err = http.ListenAndServe(":8080", router)
	if err != nil {
		log.Println(err)
		return err
	}

	return nil
}
