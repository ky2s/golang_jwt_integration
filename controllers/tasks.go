package controllers

import (
	"fmt"
	"golang_redis_integration/models"
	"net/http"
	"strconv"
	"strings"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

type TaskController interface {
	InsertTask(c *gin.Context)
	GetTask(c *gin.Context)
	UpdateTask(c *gin.Context)
	DestroyTask(c *gin.Context)
}

type taskController struct {
	taskMod models.TaskModels
}

func NewTaskController(taskModels models.TaskModels) TaskController {
	return &taskController{
		taskMod: taskModels,
	}
}

func (ctr *taskController) InsertTask(c *gin.Context) {

	claims := jwt.ExtractClaims(c)
	userID, _ := strconv.Atoi(claims["id"].(string))

	var reqData models.Tasks
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

	if userID <= 0 {
		userID = 1
	}

	var postData models.Tasks
	postData.UsersID = userID
	postData.Title = reqData.Title
	postData.Description = reqData.Description
	// postData.Status = reqData.Status
	createData, err := ctr.taskMod.CreateTask(postData)
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

func (ctr *taskController) GetTask(c *gin.Context) {

	if c.Param("id") != "" {
		TaskID, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"status": false,
				"error":  err,
			})
			return
		}

		if TaskID >= 1 {
			dataRow, err := ctr.taskMod.GetTaskRow(models.Tasks{ID: TaskID})
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

			var result models.TaskViews
			result.ID = dataRow.ID
			result.Title = dataRow.Title
			result.Description = dataRow.Description
			result.Status = dataRow.Status
			result.CreatedAt = dataRow.CreatedAt

			c.JSON(http.StatusOK, gin.H{
				"status":  true,
				"message": "Data is available",
				"data":    result,
			})
			return
		}
	}

	dataRows, err := ctr.taskMod.GetTaskRows(models.Tasks{})
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

	var results []models.TaskViews
	for i := 0; i < len(dataRows); i++ {
		var each models.TaskViews
		each.ID = dataRows[i].ID
		each.Title = dataRows[i].Title
		each.Description = dataRows[i].Description
		each.CreatedAt = dataRows[i].CreatedAt

		results = append(results, each)
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  true,
		"message": "Data is available",
		"data":    results,
	})
	return
}

func (ctr *taskController) UpdateTask(c *gin.Context) {
	if c.Param("id") != "" {
		TaskID, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"status": false,
				"error":  err,
			})
			return
		}

		if TaskID >= 1 {
			dataRow, err := ctr.taskMod.GetTaskRow(models.Tasks{ID: TaskID})
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
				var reqData models.Tasks
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

				var postData models.Tasks
				postData.Title = reqData.Title
				postData.Description = reqData.Description
				postData.Status = reqData.Status
				updateData, err := ctr.taskMod.UpdateTask(dataRow.ID, postData)
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
				"message": "Task ID is not registered",
			})
			return

		}
	}
	c.JSON(http.StatusBadRequest, gin.H{
		"status":  false,
		"message": "Task ID is required",
	})
	return
}

func (ctr *taskController) DestroyTask(c *gin.Context) {
	if c.Param("id") != "" {
		TaskID, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"status": false,
				"error":  err,
			})
			return
		}

		if TaskID >= 1 {
			dataRow, err := ctr.taskMod.GetTaskRow(models.Tasks{ID: TaskID})
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"status":  false,
					"message": "Failed",
					"error":   err.Error(),
				})
				return
			}

			if dataRow.ID >= 1 {

				result, err := ctr.taskMod.DeleteTask(dataRow.ID)
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
				"message": "Task ID is not registered",
			})
			return

		}
	}
	c.JSON(http.StatusBadRequest, gin.H{
		"status":  false,
		"message": "Task ID is required",
	})
	return
}
