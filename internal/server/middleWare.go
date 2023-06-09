package server

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt"
	"net/http"
)


// Create a middleware function that will check if the user is authorized.
//  This function will get the jwt token from the cookie and if the token is valid it will run the next handler,
//  if not it will return an error

func AuthMiddleWare(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("SESSTOKEN")
		if err != nil {
			http.Error(w, "Unauthorized 1", http.StatusUnauthorized)
			return
		}

		tokenString := cookie.Value
		if tokenString == "" {
			http.Error(w, "unauthorized 2 | cookie is empty ", http.StatusUnauthorized)
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte("123456789"), nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized | token invalid", http.StatusUnauthorized)
			return
		}
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			value := claims["user_id"]
			r = r.WithContext(context.WithValue(r.Context(), "user_id", value))
		}
		next.ServeHTTP(w, r)
	})
}
