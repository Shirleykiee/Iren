package controller

import (
	"Iren/models"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// UFile ...
type UFile struct {
	Host     string
	Port     int
	User     string
	Password string
	SrcPath  string
	DestPath string
}

// UploadFile ...
func UploadFile(c *gin.Context) {
	var sshHost models.SSHHost
	var ufile UFile
	chSSH := make(chan models.SSHResult)
	var chip = make([]string, 0)

	err := c.BindJSON(&ufile)
	logrus.Println(ufile)
	if err == nil {
		logrus.Println("开始执行单个文件下发")
		chLimit := make(chan bool, 10)
		chs := make([]chan models.SSHResult, 10)
		limitFunc := func(chLimit chan bool, ch chan models.SSHResult, host models.SSHHost) {
			logrus.Println("limitFunc 中的models.DoSFTP")
			models.DoSFTP(ufile.User, ufile.Password, ufile.Host, "", ufile.SrcPath, ufile.DestPath, ufile.Port, chip, chSSH)
			<-chLimit
		}

		for i := 0; i < 10; i++ {
			chs[i] = make(chan models.SSHResult, 1)
			chLimit <- true
			go limitFunc(chLimit, chs[i], sshHost)
		}
		sshResults := []models.SSHResult{}
		for _, ch := range chs {
			res := <-ch
			if res.Result != "" {
				sshResults = append(sshResults, res)
				logrus.Println("执行结果: ", sshResults)
			}
			c.JSON(http.StatusOK, gin.H{
				"status": "ok",
				"msg":    sshResults[0].Result,
			})
		}
	} else {
		logrus.Println("UploadFile.c.BindJSON error: ", err)
		c.JSON(http.StatusOK, gin.H{
			"status": "-1",
			"msg":    "解析数据失败",
		})
	}
}

// DownFile ...
func DownFile(c *gin.Context) {
	var sshHost models.SSHHost
	var ufile UFile
	chSSH := make(chan models.SSHResult)
	var chip = make([]string, 0)

	err := c.BindJSON(&ufile)
	logrus.Println(ufile)
	if err == nil {
		logrus.Println("开始执行单个文件下载")
		chLimit := make(chan bool, 10)
		chs := make([]chan models.SSHResult, 10)
		limitFunc := func(chLimit chan bool, ch chan models.SSHResult, host models.SSHHost) {
			logrus.Println("limitFunc 中的models.Download")
			models.Download(ufile.User, ufile.Password, ufile.Host, "", ufile.SrcPath, ufile.DestPath, ufile.Port, chip, chSSH)
			<-chLimit
		}

		for i := 0; i < 10; i++ {
			chs[i] = make(chan models.SSHResult, 1)
			chLimit <- true
			go limitFunc(chLimit, chs[i], sshHost)
		}
		sshResults := []models.SSHResult{}
		for _, ch := range chs {
			res := <-ch
			if res.Result != "" {
				sshResults = append(sshResults, res)
				logrus.Println("执行结果: ", sshResults)
			}
			c.JSON(http.StatusOK, gin.H{
				"status": "ok",
				"msg":    sshResults[0].Result,
			})
		}
	} else {
		logrus.Println("Download.c.BindJSON error: ", err)
		c.JSON(http.StatusOK, gin.H{
			"status": "-1",
			"msg":    "解析数据失败",
		})
	}
}
