package server

import (
	"context"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt"
)

func AuthMiddleWare(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		 cookie, err := r.Cookie("SESSTOKEN")
		 if err != nil {
			  http.Error(w, "Unauthorized", http.StatusUnauthorized)
			  return
		 }
		 tokenString := cookie.Value
		 token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			  if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			  }
			  return []byte("secret"), nil
		 })
		 if err != nil || !token.Valid {
			  http.Error(w, "Unauthorized", http.StatusUnauthorized)
			  return
		 }
		 if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			  r = r.WithContext(context.WithValue(r.Context(), "user_id", claims["user_id"]))
		 }
		 next.ServeHTTP(w, r)
	})
}