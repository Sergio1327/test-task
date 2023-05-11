package domain

type User struct {
	Id       int    `json:"id"`
	Login    string `json:"login"`
	Password string `json:"password"`
	
}

type RegisteredUser struct {
	ID       int
	Login    string
	HashedPassword []byte
}
