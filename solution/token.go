package solution

import "github.com/dgrijalva/jwt-go"

type TokenClaims struct {
	jwt.StandardClaims
	Login string `json:"login"`
}
type TokenResponse struct {
	Token string `json:"token"`
}
type TokenLogin struct {
	Token string `json:"token"`
	Login string `json:"login"`
}
