package main

import (
	"fmt"
	"golang_redis_integration/controllers"
	"golang_redis_integration/middleware"
	"golang_redis_integration/models"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {

	dsn := "host=localhost user=postgres password=12345678 dbname=user_task_project port=5433 sslmode=disable TimeZone=Asia/Jakarta"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		panic("failed to connect err")
	}

	//automigrate
	db.AutoMigrate(&models.Users{}, &models.Tasks{})

	r := gin.Default()

	var userModels models.UserModels = models.NewUserModels(db)
	var userController controllers.UserController = controllers.NewUserController(userModels)
	var googleController controllers.GoogleController = controllers.NewGoogleController(userModels)

	var taskModels models.TaskModels = models.NewTaskModels(db)
	var taskController controllers.TaskController = controllers.NewTaskController(taskModels)

	auth := middleware.NewMiddleware(userModels)
	fmt.Println(taskController)
	/*
		authMiddleware := middleware.SetupMiddleware(db)

		errInit := authMiddleware.MiddlewareInit()
		if errInit != nil {
			log.Fatal("authMiddleware.MiddlewareInit() Error:" + errInit.Error())
		}

		r.NoRoute(authMiddleware.MiddlewareFunc(), func(c *gin.Context) {
			claims := jwt.ExtractClaims(c)
			log.Printf("NoRoute claims: %#v\n", claims)
			c.JSON(404, gin.H{"code": "PAGE_NOT_FOUND", "message": "Page not found"})
		})
	*/

	r.Use(gin.Logger())

	// Recovery middleware recovers from any panics and writes a 500 if there was one.
	r.Use(gin.Recovery())

	r.POST("/register", userController.InsertUser)
	// r.POST("/login", authMiddleware.LoginHandler)
	r.POST("/login", userController.Login)
	r.GET("/auth/google", googleController.GoogleLogin)
	r.GET("/auth/google/callback", googleController.GoogleLoginCallback)

	// user
	r.POST("/users", auth.Authorize, userController.InsertUser)
	r.GET("/users", auth.Authorize, userController.GetUser)
	r.GET("/users/:id", userController.GetUser)
	r.PUT("/users/:id", userController.UpdateUser)
	r.DELETE("/users/:id", userController.DestroyUser)

	// task
	r.POST("/tasks", auth.Authorize, taskController.InsertTask)
	r.GET("/tasks", auth.Authorize, taskController.GetTask)
	r.GET("/tasks/:id", auth.Authorize, taskController.GetTask)
	r.PUT("/tasks/:id", auth.Authorize, taskController.UpdateTask)
	r.DELETE("/tasks/:id", auth.Authorize, taskController.DestroyTask)

	r.Run()

}
