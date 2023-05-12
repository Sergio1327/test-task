package domain

type User struct {
	Id       int    `json:"id"`
	Login    string `json:"login"`
	Password string `json:"password"`
}

type RegisteredUser struct {
	ID             int
	Login          string
	HashedPassword []byte
}

type UsersTable struct {
	Id   int    `json:"id"`
	Name string `json:"name"`
	Age  int    `json:"age"`
}

type PhoneData struct {
	PhoneNumber string `json:"phone"`
	Description string `json:"description"`
	IsMobile    bool   `json:"isMobile"`
}
