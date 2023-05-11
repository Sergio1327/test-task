package db

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"log"
)

type DB struct {
	Db *sql.DB
}

func DBConnect() (*DB, error) {
	db, err := sql.Open("sqlite3", "internal/db/users.db")
	if err != nil {
		log.Println(err)
		return nil, err
	}
	if err := db.Ping(); err != nil {
		log.Println(err)
		return nil, err
	}
	log.Println("successfully connected to database")

	_, err = db.Exec("create table if not exists users(id integer primary key autoincrement,login text not null unique,password text not null)")
	if err != nil {
		log.Fatal(err)
	}
	
	_, err = db.Exec("create table if not exists user_details(user_id integer references users(id),phone text,description text,isMobile integer check(isMobile in (0,1)))")
	if err != nil {
		log.Fatal(err)
	}

	return &DB{
		Db: db,
	}, nil
}

func (d *DB) Close() error {
	return d.Db.Close()
}

func (d *DB) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return d.Db.Query(query, args...)
}

func (d *DB) QueryRow(query string, args ...interface{}) (*sql.Row, error) {
	return d.Db.QueryRow(query, args...), nil
}

func (d *DB) Exec(query string, args ...interface{}) (sql.Result, error) {
	return d.Db.Exec(query, args...)
}
