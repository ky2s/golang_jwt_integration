package controllers

import (
	"fmt"
	"golang_redis_integration/models"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"golang.org/x/crypto/bcrypt"
)

type UserController interface {
	InsertUser(c *gin.Context)
	GetUser(c *gin.Context)
	UpdateUser(c *gin.Context)
	DestroyUser(c *gin.Context)
}

type userController struct {
	userMod models.UserModels
}

func NewUserController(userModels models.UserModels) UserController {
	return &userController{
		userMod: userModels,
	}
}

func Hash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func (ctr *userController) InsertUser(c *gin.Context) {

	var reqData models.Users
	err := c.ShouldBindJSON(&reqData)
	if err != nil {
		fmt.Println(err.Error())
		if strings.Contains(err.Error(), "invalid character") == true {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		errorMessages := []string{}
		for _, e := range err.(validator.ValidationErrors) {
			errorMessage := fmt.Sprintf("Error validate %s, condition: %s", e.Field(), e.ActualTag())
			errorMessages = append(errorMessages, errorMessage)
		}

		c.JSON(http.StatusBadRequest, gin.H{
			"error": errorMessages,
		})
		return

	}

	hash, err := Hash(reqData.Password)
	if err != nil {
		fmt.Println(err)
		return
	}

	var postData models.Users
	postData.Name = reqData.Name
	postData.Email = reqData.Email
	postData.Password = hash
	createData, err := ctr.userMod.CreateUser(postData)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  false,
			"message": "Failed",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  true,
		"message": "Success created data",
		"data":    createData,
	})
	return
}

func (ctr *userController) GetUser(c *gin.Context) {

	if c.Param("id") != "" {
		userID, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"status": false,
				"error":  err,
			})
			return
		}

		if userID >= 1 {
			dataRow, err := ctr.userMod.GetUserRow(models.Users{ID: userID})
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"status":  false,
					"message": "Failed",
					"error":   err.Error(),
				})
				return
			}
			fmt.Println(dataRow.ID)
			if dataRow.ID <= 0 {
				c.JSON(http.StatusBadRequest, gin.H{
					"status":  false,
					"message": "Data is not available",
				})
				return
			}

			var result models.UserViews
			result.ID = dataRow.ID
			result.Name = dataRow.Name
			result.Email = dataRow.Email
			result.CreatedAt = dataRow.CreatedAt

			c.JSON(http.StatusOK, gin.H{
				"status":  true,
				"message": "Data is available",
				"data":    result,
			})
			return
		}
	}

	dataRows, err := ctr.userMod.GetUserRows(models.Users{})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  false,
			"message": "Failed",
			"error":   err.Error(),
		})
		return
	}

	if len(dataRows) <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  false,
			"message": "Data is not available",
		})
		return
	}

	var results []models.UserViews
	for i := 0; i < len(dataRows); i++ {
		var each models.UserViews
		each.ID = dataRows[i].ID
		each.Name = dataRows[i].Name
		each.Email = dataRows[i].Email
		each.CreatedAt = dataRows[i].CreatedAt

		results = append(results, each)
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  true,
		"message": "Success created data",
		"data":    results,
	})
	return
}

func (ctr *userController) UpdateUser(c *gin.Context) {
	if c.Param("id") != "" {
		userID, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"status": false,
				"error":  err,
			})
			return
		}

		if userID >= 1 {
			dataRow, err := ctr.userMod.GetUserRow(models.Users{ID: userID})
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"status":  false,
					"message": "Failed",
					"error":   err.Error(),
				})
				return
			}

			if dataRow.ID >= 1 {

				// data body
				var reqData models.Users
				err := c.ShouldBindJSON(&reqData)
				if err != nil {
					fmt.Println(err.Error())
					if strings.Contains(err.Error(), "invalid character") == true {
						c.JSON(http.StatusBadRequest, gin.H{
							"error": err.Error(),
						})
						return
					}

					errorMessages := []string{}
					for _, e := range err.(validator.ValidationErrors) {
						errorMessage := fmt.Sprintf("Error validate %s, condition: %s", e.Field(), e.ActualTag())
						errorMessages = append(errorMessages, errorMessage)
					}

					c.JSON(http.StatusBadRequest, gin.H{
						"error": errorMessages,
					})
					return
				}

				var postData models.Users
				postData.Name = reqData.Name
				postData.Email = reqData.Email
				updateData, err := ctr.userMod.UpdateUser(dataRow.ID, postData)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{
						"status":  false,
						"message": "Failed",
					})
					return
				}

				c.JSON(http.StatusOK, gin.H{
					"status":  true,
					"message": "Success update data",
					"data":    updateData,
				})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{
				"status":  false,
				"message": "User ID is not registered",
			})
			return

		}
	}
	c.JSON(http.StatusBadRequest, gin.H{
		"status":  false,
		"message": "User ID is required",
	})
	return
}

func (ctr *userController) DestroyUser(c *gin.Context) {
	if c.Param("id") != "" {
		userID, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"status": false,
				"error":  err,
			})
			return
		}

		if userID >= 1 {
			dataRow, err := ctr.userMod.GetUserRow(models.Users{ID: userID})
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"status":  false,
					"message": "Failed",
					"error":   err.Error(),
				})
				return
			}

			if dataRow.ID >= 1 {

				result, err := ctr.userMod.DeleteUser(dataRow.ID)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{
						"status":  false,
						"message": "Failed",
					})
					return
				}

				c.JSON(http.StatusOK, gin.H{
					"status":  true,
					"message": "Success delete data",
					"data":    result,
				})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{
				"status":  false,
				"message": "User ID is not registered",
			})
			return

		}
	}
	c.JSON(http.StatusBadRequest, gin.H{
		"status":  false,
		"message": "User ID is required",
	})
	return
}
