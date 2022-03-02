package middlewares

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	jwt1 "github.com/form3tech-oss/jwt-go"
	"github.com/gin-gonic/gin"
)

// JSONWebKeys struct
type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

// Jwks struct
type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

var jwtMiddleWare *jwtmiddleware.JWTMiddleware

func init() {
	// jwtMiddleWare = jwtmiddleware.New(jwtmiddleware.Options{
	// 	ValidationKeyGetter: validationKeyGetter1,
	// 	SigningMethod:       jwt1.SigningMethodRS256,
	// })
}

// func validationKeyGetter1(token *jwt1.Token) (interface{}, error) {
// 	audience := os.Getenv("AUTH0_AUDIENCE")
// 	checkAudience := token.Claims.(jwt1.MapClaims).VerifyAudience(audience, false)
// 	if !checkAudience {
// 		return token, errors.New("invalid audience")
// 	}

// 	issuer := "https://" + os.Getenv("AUTH0_DOMAIN") + "/"
// 	checkIssuser := token.Claims.(jwt1.MapClaims).VerifyIssuer(issuer, false)
// 	if !checkIssuser {
// 		return token, errors.New("invalid issuer")
// 	}

// 	cert, err := getPemCert(token)
// 	if err != nil {
// 		return nil, err
// 	}

// 	result, error := jwt1.ParseRSAPublicKeyFromPEM([]byte(cert))
// 	return result, error
// }

func getPemCert(token *jwt1.Token) (string, error) {
	cert := ""
	url := "https://" + os.Getenv("AUTH0_DOMAIN") + "/.well-known/jwks.json"
	resp, err := http.Get(url)
	if err != nil {
		return cert, err
	}
	defer resp.Body.Close()

	var jwks = Jwks{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)
	if err != nil {
		return cert, err
	}

	x5c := jwks.Keys[0].X5c
	for k, v := range x5c {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + v + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		return cert, errors.New("unable to find appropriate key")
	}

	return cert, nil
}

// AuthMiddleware function based on
// https://auth0.com/docs/quickstart/backend/golang
func AuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		err := jwtMiddleWare.CheckJWT(ctx.Writer, ctx.Request)
		if err != nil {
			log.Printf("error validating auth token: %v\n", err)
			ctx.Abort()
			ctx.Writer.WriteHeader(http.StatusUnauthorized)
			ctx.Writer.Write([]byte("Unauthorized"))
			return
		}

		authToken := ctx.Request.Header["Authorization"][0]
		splitToken := strings.Split(authToken, "Bearer ")
		authToken = splitToken[1]
		parsedToken, _ := jwt1.ParseWithClaims(authToken, &jwt1.StandardClaims{}, nil)
		if err != nil {
			log.Printf("error parsing token: %v\n", err)
			ctx.Abort()
			ctx.Writer.WriteHeader(http.StatusUnauthorized)
			ctx.Writer.Write([]byte("Unauthorized"))
			return
		}
		tokenData := parsedToken.Claims.(*jwt1.StandardClaims)

		log.Printf("claims retrieved %+v\n", tokenData)
		ctx.Set("userid", tokenData.Subject)
	}
}
