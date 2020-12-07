package controller

import (
	"Iren/models"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// Cmd ...
func Cmd(c *gin.Context) {
	var sshHost models.SSHHost
	chSSH := make(chan models.SSHResult)
	var chip = make([]string, 0)
	var cmdList = []string{"date", "whoami"}

	err := c.BindJSON(&sshHost)
	if err == nil {
		logrus.Println("并发执行开始")
		chLimit := make(chan bool, 10) //控制并发访问量
		chs := make([]chan models.SSHResult, 10)
		// 声明一个匿名变量函数
		limitFunc := func(chLimit chan bool, ch chan models.SSHResult, host models.SSHHost) {
			logrus.Println("limitFunc 中的models.Dossh")
			models.Dossh(host.Username, host.Password, host.Host, "", cmdList, host.Port, 30, chip, true, ch)
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
		logrus.Println("命令执行开始")
		models.Dossh(sshHost.Username, sshHost.Password, sshHost.Host, " ", cmdList, sshHost.Port, 30, chip, true, chSSH)
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"msg":    "命令执行成功",
		})
	}

}
