
// package that contains the main structures and entities
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
type DBPhoneData struct {
	PhoneNumID  int	`db:"phonNumID"`
	User_ID          float64	`db:"user_id"`
	PhoneNumber string	`db:"phone"`
	Description string `db:"description"`
	IsMobile    bool	
}

