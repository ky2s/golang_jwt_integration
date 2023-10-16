package middleware

import (
	"fmt"
	"golang_redis_integration/models"
	"strconv"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var identityKey = "id"

func SetupMiddleware(db *gorm.DB) *jwt.GinJWTMiddleware {

	authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:       "jwt",
		Key:         []byte("#test-code-bank-ina#"),
		Timeout:     time.Duration(24*365) * time.Hour,
		MaxRefresh:  time.Duration(24*365) * time.Hour,
		IdentityKey: identityKey,
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			// simpan data login (save token)
			fmt.Println("PayloadFunc -----------------------primary--------------------------------")

			if v, ok := data.(*models.UserAuth); ok {
				fmt.Println("identityKey: v. --------------------second-----------------------------------", identityKey, v.ID)

				tokenResult := jwt.MapClaims{
					identityKey: v.ID,
				}

				fmt.Println("dataaaa payload----- ", v.ID, v.Email, tokenResult)

				return tokenResult
			}

			return jwt.MapClaims{}
		},
		IdentityHandler: func(c *gin.Context) interface{} {
			fmt.Println("IdentityHandler ----- ")
			claims := jwt.ExtractClaims(c)

			fmt.Println("extraxt", len(claims), " claims---", claims, len(claims))

			if len(claims) == 4 {
				if claims[identityKey] == nil {
					return &models.UserAuth{}
				}

			}

			return &models.UserAuth{
				ID: claims[identityKey].(string),
			}
		},
		Authorizator: func(data interface{}, c *gin.Context) bool {
			//pengecekan token yg sudah disimpan di DB
			fmt.Println("Authorizator ----- ")
			if v, ok := data.(*models.UserAuth); ok {

				fmt.Println("v.ID------>>>>>>", v.ID)
				var userData models.Users

				errc := db.Debug().Scopes(models.SchemaPublic("users")).First(&userData, "id = ? ", v.ID).Error
				if errc != nil {
					fmt.Println(errc)
					return false
				}

				fmt.Println("return userData.ID------>>>>>>", userData.ID)
				if userData.ID > 0 {
					return true
				}
			}

			fmt.Println("---false---->>", data)

			return false
		},
		Authenticator: func(c *gin.Context) (interface{}, error) {
			// pengecekan akun login
			var loginVals models.Login
			if err := c.ShouldBind(&loginVals); err != nil {
				return "", jwt.ErrMissingLoginValues
			}

			fmt.Println("Authenticator ----- ", loginVals)

			var userData models.Users
			errc := db.Debug().Scopes(models.SchemaPublic("users")).First(&userData, "lower(email) = lower(?)", loginVals.Email).Error
			if errc != nil {
				fmt.Println(errc)
			}
			// jika user admin tidak di dalam organization manapunn then is not allowed

			if userData.ID >= 1 {

				checkPassword := VerifyPassword(loginVals.Password, userData.Password)
				fmt.Println("checkPassword ::::", loginVals.Password, userData.Password, checkPassword)
				if checkPassword {
					fmt.Println("getUserData---", userData)

					// save tokeN here
					return &models.UserAuth{
						ID:    strconv.Itoa(userData.ID),
						Email: userData.Email,
					}, nil
				}
			}

			return nil, jwt.ErrFailedAuthentication
		},

		Unauthorized: func(c *gin.Context, code int, message string) {
			fmt.Println("Unauthorized ---user_task-- ", code)

			c.JSON(code, gin.H{
				"code":    code,
				"status":  false,
				"message": message,
			})
		},
		TokenLookup:   "header: Authorization, query: token, cookie: jwt",
		TokenHeadName: "Bearer",
		TimeFunc:      time.Now,
	})

	if err != nil {
		fmt.Println("Err: ", err)
		return nil
	}

	return authMiddleware
}

func VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func GenerateTokenNew(data interface{}) string {
	authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:       "jwt",
		Key:         []byte("#test-code-bank-ina#"),
		Timeout:     time.Duration(24*365) * time.Hour,
		MaxRefresh:  time.Duration(24*365) * time.Hour,
		IdentityKey: identityKey,
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			// simpan data login (save token)
			fmt.Println("PayloadFunc ------------------??-------------------------------------")

			if v, ok := data.(*models.UserAuth); ok {
				fmt.Println("identityKey: v. -------------------------------------------------------", identityKey, v.ID)

				tokenResult := jwt.MapClaims{
					identityKey: v.ID,
				}

				fmt.Println("dataaaa payload----- ", v.ID, v.Email, tokenResult)

				return tokenResult
			}

			return jwt.MapClaims{}
		},
		TokenLookup:   "header: Authorization, query: token, cookie: jwt",
		TokenHeadName: "Bearer",
		TimeFunc:      time.Now,
	})
	if err != nil {
		fmt.Println("Err generate token: ", err)
		return ""
	}

	userToken, _, _ := authMiddleware.TokenGenerator(jwt.MapClaims{})

	return userToken
}

/*
func GenerateJWT(id string) (string, error) {
	token, err := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	claims["authorized"] = true
	claims["id"] = id
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()

	tokenString, err := token.SignedString([]byte("#test-code-bank-ina#"))

	if err != nil {
		fmt.Errorf("Something Went Wrong: %s", err.Error())
		return "", err
	}
	return tokenString, nil
}*/

// func (mw *GinJWTMiddleware) GenerateToken22(userID string) string {
// 	token := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
// 	claims := token.Claims.(jwt.MapClaims)

// 	claims["id"] = userID

// 	expire := mw.TimeFunc().Add(mw.Timeout)
// 	claims["exp"] = expire.Unix()
// 	claims["orig_iat"] = mw.TimeFunc().Unix()
// 	tokenString, err := mw.signedString(token)
// 	if err != nil {
// 		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrFailedTokenCreation, c))
// 		return ""
// 	}

// 	return tokenString
// }

// var key = []byte("#test-code-bank-ina#")

// func GenerateToken(userID string) string {
// 	SigningAlgorithm := "HS256"

// 	token := jwt.New(jwt.GetSigningMethod(SigningAlgorithm))
// 	claims := token.Claims.(jwt.MapClaims)
// 	claims["identity"] = userID
// 	claims["exp"] = time.Now().Add(time.Hour).Unix()
// 	claims["orig_iat"] = time.Now().Unix()
// 	var tokenString string
// 	if SigningAlgorithm == "RS256" {
// 		keyData, _ := os.ReadFile("testdata/jwtRS256.key")
// 		signKey, _ := jwt.ParseRSAPrivateKeyFromPEM(keyData)
// 		tokenString, _ = token.SignedString(signKey)
// 	} else {
// 		tokenString, _ = token.SignedString(key)
// 	}

// 	return tokenString
// }
