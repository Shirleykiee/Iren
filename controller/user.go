package controller

import (
	"Iren/middleware"
	"Iren/models"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// LoginResult 登录结果结构
type LoginResult struct {
	Token string `json:"token"`
	*models.User
}

// Register 注册用户
func RegisterUser(c *gin.Context) {
	var registerInfo models.User
	err := c.BindJSON(&registerInfo)
	if err == nil {
		logrus.Println(registerInfo)
		err, _ := models.Register(registerInfo)
		if err == nil {
			c.JSON(http.StatusOK, gin.H{
				"status": 0,
				"msg":    "注册成功！",
			})
		} else {
			logrus.Println("models.register.err: ", err)
			c.JSON(http.StatusOK, gin.H{
				"status": -1,
				"msg":    "注册失败" + err.Error(),
			})
		}
	} else {
		logrus.Println("registerInfo.err: ", err)
		c.JSON(http.StatusOK, gin.H{
			"status": -1,
			"msg":    "解析数据失败！",
		})
	}
}

// Login 登录
func Login(c *gin.Context) {
	var loginReq *models.User
	if c.BindJSON(&loginReq) == nil {
		isPass, err, user := models.Loginer(loginReq)
		if isPass {
			generateToken(c, user)
		} else {
			c.JSON(http.StatusOK, gin.H{
				"status": -1,
				"msg":    "验证失败," + err.Error(),
			})
		}
	} else {
		c.JSON(http.StatusOK, gin.H{
			"status": -1,
			"msg":    "json 解析失败",
		})
	}
}

// 生成令牌
func generateToken(c *gin.Context, user *models.User) {
	j := &middleware.JWT{
		[]byte("newtrekWang"),
	}
	claims := middleware.CustomClaims{
		user.Username,
		jwt.StandardClaims{
			NotBefore: int64(time.Now().Unix() - 1000), // 签名生效时间
			ExpiresAt: int64(time.Now().Unix() + 3600), // 过期时间 一小时
			Issuer:    "newtrekWang",                   //签名的发行者
		},
	}

	token, err := j.CreateToken(claims)

	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": -1,
			"msg":    err.Error(),
		})
		return
	}

	log.Println(token)

	data := LoginResult{
		User:  user,
		Token: token,
	}
	c.JSON(http.StatusOK, gin.H{
		"status": 0,
		"msg":    "登录成功！",
		"data":   data,
	})
	return
}
