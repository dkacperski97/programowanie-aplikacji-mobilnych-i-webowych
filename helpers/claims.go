package helpers

import (
	"github.com/dgrijalva/jwt-go"
	models "github.com/dkacperski97/programowanie-aplikacji-mobilnych-i-webowych-models"
)

func GetSenderToken(login string, secret []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, models.UserClaims{
		User: login,
		Role: "sender",
	})
	return token.SignedString(secret)
}
