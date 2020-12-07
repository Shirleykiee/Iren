package main

import (
	"Iren/config"
	"Iren/controller"
	"Iren/database"
	"Iren/middleware"
	"Iren/models"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

func main() {
	err := config.Viper()
	if err != nil {
		logrus.Printf("config.Viper:", err)
	}

	database.DB = database.GormDns()
	MysqlTable(database.DB)

	r := gin.Default()
	r.POST("/login", controller.Login)
	r.POST("/register", controller.RegisterUser)
	r.POST("/cmd", controller.Cmd)
	r.POST("/upload", controller.UploadFile)
	r.POST("/download", controller.DownFile)

	taR := r.Group("/data")
	taR.Use(middleware.JWTAuth())
	r.Run(":8080")
}

// MysqlTable ...
func MysqlTable(db *gorm.DB) {
	err := db.AutoMigrate(
		models.User{},
		models.SSHHost{},
	)

	if err != nil {
		logrus.Println("MysqlTable 初始化失败！")
	}
}
