package main

import (
	"golang_redis_integration/controllers"
	middleware "golang_redis_integration/middleware"
	"golang_redis_integration/models"
	"log"

	jwt "github.com/appleboy/gin-jwt/v2"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {

	dsn := "host=localhost user=postgres password=12345678 dbname=user_task_db port=5433 sslmode=disable TimeZone=Asia/Jakarta"
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

	r.Use(gin.Logger())

	// Recovery middleware recovers from any panics and writes a 500 if there was one.
	r.Use(gin.Recovery())

	r.POST("/register", userController.InsertUser)
	r.POST("/login", authMiddleware.LoginHandler)
	r.GET("/auth/google", googleController.GoogleLogin)
	r.GET("/auth/google/callback", googleController.GoogleLoginCallback)

	user := r.Group("/")
	user.Use(authMiddleware.MiddlewareFunc())
	{
		user.POST("/users", userController.InsertUser)
		user.GET("/users", userController.GetUser)
		user.GET("/users/:id", userController.GetUser)
		user.PUT("/users/:id", userController.UpdateUser)
		user.DELETE("/users/:id", userController.DestroyUser)
	}

	// endpoint tasks
	task := r.Group("/")
	task.Use(authMiddleware.MiddlewareFunc())
	{
		task.POST("/tasks", taskController.InsertTask)
		task.GET("/tasks", taskController.GetTask)
		task.GET("/tasks/:id", taskController.GetTask)
		task.PUT("/tasks/:id", taskController.UpdateTask)
		task.DELETE("/tasks/:id", taskController.DestroyTask)
	}
	r.Run()

}
