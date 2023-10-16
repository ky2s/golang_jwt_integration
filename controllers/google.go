package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"golang_redis_integration/middleware"
	"golang_redis_integration/models"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gorm.io/gorm"
)

type GoogleController interface {
	GoogleLogin(c *gin.Context)
	GoogleLoginCallback(c *gin.Context)
}

type googleController struct {
	userMod models.UserModels
	db      *gorm.DB
}

func NewGoogleController(googleModels models.UserModels) GoogleController {
	return &googleController{
		userMod: googleModels,
	}
}

func SetupConfig() *oauth2.Config {
	conf := &oauth2.Config{
		ClientID:     "525486579481-3bm754i69vhkmmbnl6iiafq4nfcivck2.apps.googleusercontent.com",
		ClientSecret: "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",
		RedirectURL:  "http://localhost:8080/auth/google/callback",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	return conf
}

func (ctr *googleController) GoogleLogin(c *gin.Context) {

	gConfig := SetupConfig()
	url := gConfig.AuthCodeURL("randomstate")

	fmt.Println(url)
	c.Redirect(http.StatusSeeOther, url)

	// c.JSON(http.StatusOK, gin.H{
	// 	"status":  true,
	// 	"message": "Success created data",
	// })
	// return
}

func (ctr *googleController) GoogleLoginCallback(c *gin.Context) {
	//https://accounts.google.com/o/oauth2/auth/oauthchooseaccount?client_id=525486579481-3bm754i69vhkmmbnl6iiafq4nfcivck2.apps.googleusercontent.com&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fauth%2Fgoogle%2Fcallback&response_type=code&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email%20https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.profile&state=randomstate&service=lso&o2v=1&theme=glif&flowName=GeneralOAuthFlow
	state := c.Request.URL.Query().Get("state")
	if state != "randomstate" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  false,
			"message": "failed get state",
		})
		return
	}

	code := c.Request.URL.Query().Get("code")

	// config
	gConfig := SetupConfig()

	// exchange code for token
	token, err := gConfig.Exchange(context.Background(), code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  false,
			"message": "failed exhange",
		})
		return
	}

	resp, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  false,
			"message": "failed get user info",
		})
		return
	}

	userData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  false,
			"message": "failed get user info",
			"err":     err,
		})
		return
	}

	// set data to struct
	var response models.GoogleUserInfo
	err = json.Unmarshal(userData, &response)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  false,
			"message": "failed get user info",
			"err":     err,
		})
		return
	}

	checkUser, err := ctr.userMod.GetUserRow(models.Users{Email: response.Email})
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  false,
			"message": "failed check user info",
			"err":     err,
		})
		return
	}

	if checkUser.ID <= 0 {
		// auto register

		var postData models.Users
		postData.Name = response.Name
		postData.Email = response.Email
		postData.Password = ""
		createData, err := ctr.userMod.CreateUser(postData)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"status":  false,
				"message": "Failed",
			})
			return
		}

		var res models.UserViews
		res.ID = createData.ID
		res.Name = response.Name
		res.Email = response.Email
		res.CreatedAt = createData.CreatedAt

		// tokenString := GenerateToken(strconv.Itoa(createData.ID))
		// tokenString := middleware.GenerateTokenNew(strconv.Itoa(checkUser.ID))

		dataToken := map[string]interface{}{
			"id": strconv.Itoa(createData.ID),
		}
		tokenString := middleware.GenerateTokenNew(dataToken)

		c.JSON(http.StatusOK, gin.H{
			"status":  true,
			"message": "Success login using Google Account",
			"data":    res,
			"token":   tokenString,
		})
		return
	}

	// get userdata existing
	var res models.UserViews
	res.ID = checkUser.ID
	res.Name = checkUser.Name
	res.Email = checkUser.Email
	res.CreatedAt = checkUser.CreatedAt

	// tokenString := middleware.GenerateTokenNew(strconv.Itoa(checkUser.ID))
	dataToken := map[string]interface{}{
		"id": strconv.Itoa(checkUser.ID),
	}
	tokenString := middleware.GenerateTokenNew(dataToken)

	// fmt.Println("authMiddleware :: ", authMiddleware)

	// var data map[string]interface{}
	// dataToken := map[string]interface{}{
	// 	"id": strconv.Itoa(checkUser.ID),
	// }
	// tokenString, _, err := jwt.TokenGenerator(dataToken)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  false,
			"message": "Failed generate token",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  true,
		"message": "Success login using Google Account",
		"data":    res,
		"token":   tokenString,
	})
	return
}
