package types

import jwt "github.com/dgrijalva/jwt-go"

type (
	JWTData struct {
		// Standard claims are the standard jwt claims from the IETF standard
		// https://tools.ietf.org/html/rfc7519
		jwt.StandardClaims
		CustomClaims map[string]string `json:"custom,omitempty"`
	}
)

type (
	Account struct {
		Email    string  `json:"email"`
		Balance  float64 `json:"balance"`
		Currency string  `json:"currency"`
	}
)

type (
	Response struct {
		Data string `json:"data"`
	}
)
