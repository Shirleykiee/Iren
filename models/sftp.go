package models

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"time"

	"github.com/pkg/sftp"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// ClientConfig ... 连接的配置
type ClientConfig struct {
	Host       string       //ip
	Port       int64        // 端口
	Username   string       //用户名
	Password   string       //密码
	sshClient  *ssh.Client  //ssh client
	sftpClient *sftp.Client //sftp client
	LastResult string       //最近一次运行的结果
}

// RunShell ...
func (cliConf *ClientConfig) RunShell(shell string) string {
	var (
		session *ssh.Session
		err     error
	)

	//获取session，这个session是用来远程执行操作的
	if session, err = cliConf.sshClient.NewSession(); err != nil {
		log.Fatalln("error occurred:", err)
	}
	//执行shell
	if output, err := session.CombinedOutput(shell); err != nil {
		fmt.Println(shell)
		log.Fatalln("error occurred:", err)
	} else {
		cliConf.LastResult = string(output)
	}
	return cliConf.LastResult
}

// Upload ...
func (cliConf *ClientConfig) Upload(srcPath, dstPath string) {
	srcFile, _ := os.Open(srcPath)                   //本地
	dstFile, _ := cliConf.sftpClient.Create(dstPath) //远程
	defer func() {
		_ = srcFile.Close()
		_ = dstFile.Close()
	}()
	buf := make([]byte, 1024)
	for {
		n, err := srcFile.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Fatalln("error occurred:", err)
			} else {
				break
			}
		}
		_, _ = dstFile.Write(buf[:n])
	}
	fmt.Println(cliConf.RunShell(fmt.Sprintf("ls %s", dstPath)))
}

// Download ...
func (cliConf *ClientConfig) Download(srcPath, dstPath string) {
	srcFile, err := cliConf.sftpClient.Open(srcPath) //远程
	fmt.Println(srcFile)
	if err != nil {
		fmt.Println(err.Error())
	}

	dstFile, _ := os.Create(dstPath) //本地
	defer func() {
		_ = srcFile.Close()
		_ = dstFile.Close()
	}()

	if _, err := srcFile.WriteTo(dstFile); err != nil {
		log.Fatalln("error occurred", err)
	}
	fmt.Println("文件下载完毕")
}

// SFTP 传输机遇SSH 所以先要SSH连接服务器
// connect ... 连接主机
func conn(user, password, host, key string, port int, cipherList []string) (*sftp.Client, error) {
	var (
		auth         []ssh.AuthMethod
		addr         string
		clientConfig *ssh.ClientConfig
		client       *ssh.Client
		config       ssh.Config
		sftpClient   *sftp.Client
		err          error
	)
	// get auth method
	auth = make([]ssh.AuthMethod, 0)
	if key == "" {
		auth = append(auth, ssh.Password(password))
	} else {
		pemBytes, err := ioutil.ReadFile(key)
		if err != nil {
			return nil, err
		}

		var signer ssh.Signer
		if password == "" {
			signer, err = ssh.ParsePrivateKey(pemBytes)
		} else {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(pemBytes, []byte(password))
		}
		if err != nil {
			return nil, err
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}

	if len(cipherList) == 0 {
		config = ssh.Config{
			Ciphers:      []string{"aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-gcm@openssh.com", "arcfour256", "arcfour128", "aes128-cbc", "3des-cbc", "aes192-cbc", "aes256-cbc"},
			KeyExchanges: []string{"diffie-hellman-group-exchange-sha1", "diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha256"},
		}
	} else {
		config = ssh.Config{
			Ciphers: cipherList,
		}
	}

	clientConfig = &ssh.ClientConfig{
		User:    user,
		Auth:    auth,
		Timeout: 30 * time.Second,
		Config:  config,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	// connet to ssh
	addr = fmt.Sprintf("%s:%d", host, port)

	if client, err = ssh.Dial("tcp", addr, clientConfig); err != nil {
		return nil, err
	}
	// create sftp client

	if sftpClient, err = sftp.NewClient(client); err != nil {
		return nil, err
	}

	return sftpClient, nil
}

// DoSFTP ... 上传单个文件
func DoSFTP(username, password, host, key, srcPath, destPath string, port int, cipherList []string, ch chan SSHResult) {
	sftpClient, err := conn(username, password, host, key, port, cipherList)
	var sshResult SSHResult
	sshResult.Host = host

	if err != nil {
		logrus.Println("doSFTP.conn.err: ", err)
		sshResult.Success = false
		sshResult.Result = fmt.Sprintf("<%s>", err.Error())
		ch <- sshResult
		return
	}

	defer sftpClient.Close()

	srcFile, err := os.Open(srcPath)
	if err != nil {
		logrus.Println("doSFTP.os.Open error: ", err)
	}

	defer srcFile.Close()

	var remotePathName = path.Base(destPath)

	destFile, err := sftpClient.Create(path.Join(destPath, remotePathName))
	if err != nil {
		logrus.Println("doSFTP.sftpClient.Create error: ", err)
	}

	defer destFile.Close()

	byteFile, err := ioutil.ReadAll(srcFile)
	if err != nil {
		logrus.Println("doSFTP.ioutil.ReadAll error: ", err)
	}

	_, err = destFile.Write(byteFile)
	if err != nil {
		logrus.Println("doSFTP.destFile.Write error: ", err)
	}
}

// DoSFTPDirectory ...  文件夹上传
func DoSFTPDirectory(username, password, host, key, srcPath, destPath string, port int, cipherList []string, ch chan SSHResult) {
	sftpClient, err := conn(username, password, host, key, port, cipherList)
	var sshResult SSHResult
	sshResult.Host = host

	if err != nil {
		logrus.Println("doSFTP.conn.err: ", err)
		sshResult.Success = false
		sshResult.Result = fmt.Sprintf("<%s>", err.Error())
		ch <- sshResult
		return
	}

	defer sftpClient.Close()

	fileName, err := ioutil.ReadDir(srcPath)
	if err != nil {
		logrus.Println("doSFTPDirectory.ioutil.ReadDir error: ", err)
	}

	for _, backupDir := range fileName {

		localFilePath := path.Join(srcPath, backupDir.Name())

		remoteFilePath := path.Join(destPath, backupDir.Name())

		if backupDir.IsDir() {
			sftpClient.Mkdir(remoteFilePath)
			DoSFTPDirectory(username, password, host, key, localFilePath, remoteFilePath, port, cipherList, ch)
		} else {
			DoSFTP(username, password, host, key, path.Join(srcPath, backupDir.Name()), remoteFilePath, port, cipherList, ch)
		}
	}
}

// Download ...
func Download(username, password, host, key, srcPath, destPath string, port int, cipherList []string, ch chan SSHResult) {
	sftpClient, err := conn(username, password, host, key, port, cipherList)
	var sshResult SSHResult
	sshResult.Host = host

	if err != nil {
		logrus.Println("Download.conn.err: ", err)
		sshResult.Success = false
		sshResult.Result = fmt.Sprintf("<%s>", err.Error())
		ch <- sshResult
		return
	}

	defer sftpClient.Close()

	desfFile, err := sftpClient.Open(destPath)
	if err != nil {
		logrus.Println("Download.sftpClient.Open error: ", err)
	}

	defer desfFile.Close()

	var localFileName = path.Base(destPath)

	srcFile, err := os.Create(path.Join(srcPath, localFileName))
	if err != nil {
		logrus.Println("Download.os.Create error: ", err)
	}
	defer srcFile.Close()

	if _, err = desfFile.WriteTo(srcFile); err != nil {
		logrus.Println("Download.desfFile.WriteTo error: ", err)
	}
}
