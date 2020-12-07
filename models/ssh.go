package models

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHHost ...
type SSHHost struct {
	Username string `gorm:"type:varchar(100);not null;"` // 操作名称
	Host     string `gorm:"type:varchar(100);not null;"` // 主机的IP地址，可以单台可以多台
	Port     int    `jorm:"type:int"`                    // 远程连接主机的端口,类似22默认端口
	Password string `jorm:"type:varchar(100);not null;"` // 远程连接用到的用户的密码
	//CmdFile  string `json:"cmdfile"`
	//Cmds     string `json:"cmds"`
	//CmdList []string
	//Key      string
	//Result   SSHResult
}

// SSHResult ...
type SSHResult struct {
	Host    string
	Success bool
	Result  string
}

// HostJson ...
type HostJson struct {
	SshHosts []SSHHost
}

// SplitString ... 判断string类型是不是已",", 或者是不是已";"进行分割的
func SplitString(str string) (strList []string) {
	if strings.Contains(str, ",") {
		strList = strings.Split(str, ",")
	} else {
		strList = strings.Split(str, ";")
	}
	return
}

// GetfileAll ...
func GetfileAll(filePath string) ([]byte, error) {
	result, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Println("read file ", filePath, err)
		return result, err
	}
	return result, nil
}

// Getfile ...
func Getfile(filePath string) ([]string, error) {
	result := []string{}
	b, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Println("read file ", filePath, err)
		return result, err
	}
	s := string(b)
	for _, lineStr := range strings.Split(s, "\n") {
		lineStr = strings.TrimSpace(lineStr)
		if lineStr == "" {
			continue
		}
		result = append(result, lineStr)
	}
	return result, nil
}

// GetJSONFile ...
func GetJSONFile(filePath string) ([]SSHHost, error) {
	result := []SSHHost{}
	b, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Println("read file ", filePath, err)
		return result, err
	}
	var m HostJson
	err = json.Unmarshal(b, &m)
	if err != nil {
		log.Println("read file ", filePath, err)
		return result, err
	}
	result = m.SshHosts
	return result, nil
}

// WriteIntoTxt ...
func WriteIntoTxt(sshResult SSHResult, locate string) error {
	outputFile, outputError := os.OpenFile(locate+sshResult.Host+".txt", os.O_WRONLY|os.O_CREATE, 0666)
	if outputError != nil {
		return outputError
	}
	defer outputFile.Close()

	outputWriter := bufio.NewWriter(outputFile)
	//var outputString string

	outputString := sshResult.Result
	outputWriter.WriteString(outputString)
	outputWriter.Flush()
	return nil
}

// GetIPList ...
func GetIPList(ipString string) ([]string, error) {
	res := SplitString(ipString)
	var allIP []string
	if len(res) > 0 {
		for _, sip := range res {
			aip := ParseIP(sip)
			for _, ip := range aip {
				allIP = append(allIP, ip)
			}
		}
	}
	return allIP, nil
}

// GetIPListFromFile ...
func GetIPListFromFile(filePath string) ([]string, error) {
	res, err := Getfile(filePath)
	if err != nil {
		return nil, nil
	}
	var allIP []string
	if len(res) > 0 {
		for _, sip := range res {
			aip := ParseIP(sip)
			for _, ip := range aip {
				allIP = append(allIP, ip)
			}
		}
	}
	return allIP, nil
}

// ParseIP ...
func ParseIP(ip string) []string {
	var availableIPs []string
	// if ip is "1.1.1.1/",trim /
	ip = strings.TrimRight(ip, "/")
	if strings.Contains(ip, "/") == true {
		if strings.Contains(ip, "/32") == true {
			aip := strings.Replace(ip, "/32", "", -1)
			availableIPs = append(availableIPs, aip)
		} else {
			availableIPs = GetAvailableIP(ip)
		}
	} else if strings.Contains(ip, "-") == true {
		ipRange := strings.SplitN(ip, "-", 2)
		availableIPs = GetAvailableIPRange(ipRange[0], ipRange[1])
	} else {
		availableIPs = append(availableIPs, ip)
	}
	return availableIPs
}

// GetAvailableIPRange ...
func GetAvailableIPRange(ipStart, ipEnd string) []string {
	var availableIPs []string

	firstIP := net.ParseIP(ipStart)
	endIP := net.ParseIP(ipEnd)
	if firstIP.To4() == nil || endIP.To4() == nil {
		return availableIPs
	}
	firstIPNum := ipToInt(firstIP.To4())
	EndIPNum := ipToInt(endIP.To4())
	pos := int32(1)

	newNum := firstIPNum

	for newNum <= EndIPNum {
		availableIPs = append(availableIPs, intToIP(newNum).String())
		newNum = newNum + pos
	}
	return availableIPs
}

// GetAvailableIP ...
func GetAvailableIP(ipAndMask string) []string {
	var availableIPs []string

	ipAndMask = strings.TrimSpace(ipAndMask)
	ipAndMask = IPAddressToCIDR(ipAndMask)
	_, ipnet, _ := net.ParseCIDR(ipAndMask)

	firstIP, _ := networkRange(ipnet)
	ipNum := ipToInt(firstIP)
	size := networkSize(ipnet.Mask)
	pos := int32(1)
	max := size - 2 // -1 for the broadcast address, -1 for the gateway address

	var newNum int32
	for attempt := int32(0); attempt < max; attempt++ {
		newNum = ipNum + pos
		pos = pos%max + 1
		availableIPs = append(availableIPs, intToIP(newNum).String())
	}
	return availableIPs
}

// IPAddressToCIDR ...
func IPAddressToCIDR(ipAdress string) string {
	if strings.Contains(ipAdress, "/") == true {
		ipAndMask := strings.Split(ipAdress, "/")
		ip := ipAndMask[0]
		mask := ipAndMask[1]
		if strings.Contains(mask, ".") == true {
			mask = IPMaskStringToCIDR(mask)
		}
		return ip + "/" + mask
	} else {
		return ipAdress
	}
}

// IPMaskStringToCIDR ...
func IPMaskStringToCIDR(netmask string) string {
	netmaskList := strings.Split(netmask, ".")
	var mint []int
	for _, v := range netmaskList {
		strv, _ := strconv.Atoi(v)
		mint = append(mint, strv)
	}
	myIPMask := net.IPv4Mask(byte(mint[0]), byte(mint[1]), byte(mint[2]), byte(mint[3]))
	ones, _ := myIPMask.Size()
	return strconv.Itoa(ones)
}

// IPMaskCIDRToString ...
func IPMaskCIDRToString(one string) string {
	oneInt, _ := strconv.Atoi(one)
	mIPmask := net.CIDRMask(oneInt, 32)
	var maskstring []string
	for _, v := range mIPmask {
		maskstring = append(maskstring, strconv.Itoa(int(v)))
	}
	return strings.Join(maskstring, ".")
}

// networkRange ... 计算第一个IP和最后一个IP在 IPNet
func networkRange(network *net.IPNet) (net.IP, net.IP) {
	netIP := network.IP.To4()
	firstIP := netIP.Mask(network.Mask)
	lastIP := net.IPv4(0, 0, 0, 0).To4()
	for i := 0; i < len(lastIP); i++ {
		lastIP[i] = netIP[i] | ^network.Mask[i]
	}
	return firstIP, lastIP
}

// networkSize ... 给一个网管来计算可以用的IP地址
func networkSize(mask net.IPMask) int32 {
	m := net.IPv4Mask(0, 0, 0, 0)
	for i := 0; i < net.IPv4len; i++ {
		m[i] = ^mask[i]
	}
	return int32(binary.BigEndian.Uint32(m)) + 1
}

// ipToInt ...  将4字节IP转换为32位
func ipToInt(ip net.IP) int32 {
	return int32(binary.BigEndian.Uint32(ip.To4()))
}

// intToIp ... 将32位数转换成4字节的IP地址
func intToIP(n int32) net.IP {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(n))
	return net.IP(b)
}

// connect ... 连接主机
func connect(user, password, host, key string, port int, cipherList []string) (*ssh.Session, error) {
	var (
		auth         []ssh.AuthMethod
		addr         string
		clientConfig *ssh.ClientConfig
		client       *ssh.Client
		config       ssh.Config
		session      *ssh.Session
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

	// create session
	if session, err = client.NewSession(); err != nil {
		return nil, err
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		return nil, err
	}

	return session, nil
}

// Dossh ...
func Dossh(username, password, host, key string, cmdlist []string, port, timeout int, cipherList []string, linuxMode bool, ch chan SSHResult) {
	chSSH := make(chan SSHResult)
	if linuxMode {
		go dosshRun(username, password, host, key, cmdlist, port, cipherList, chSSH)
	} else {
		go dosshSession(username, password, host, key, cmdlist, port, cipherList, chSSH)
	}
	var res SSHResult

	select {
	case <-time.After(time.Duration(timeout) * time.Second):
		res.Host = host
		res.Success = false
		res.Result = ("SSH run timeout：" + strconv.Itoa(timeout) + " second.")
		ch <- res
	case res = <-chSSH:
		ch <- res
	}
	return
}

// dosshSession ...
func dosshSession(username, password, host, key string, cmdlist []string, port int, cipherList []string, ch chan SSHResult) {
	session, err := connect(username, password, host, key, port, cipherList)
	var sshResult SSHResult
	sshResult.Host = host

	if err != nil {
		sshResult.Success = false
		sshResult.Result = fmt.Sprintf("<%s>", err.Error())
		ch <- sshResult
		return
	}
	defer session.Close()

	cmdlist = append(cmdlist, "exit")

	stdinBuf, _ := session.StdinPipe()

	var outbt, errbt bytes.Buffer
	session.Stdout = &outbt

	session.Stderr = &errbt
	err = session.Shell()
	if err != nil {
		sshResult.Success = false
		sshResult.Result = fmt.Sprintf("<%s>", err.Error())
		ch <- sshResult
		return
	}
	for _, c := range cmdlist {
		c = c + "\n"
		stdinBuf.Write([]byte(c))
	}
	session.Wait()
	if errbt.String() != "" {
		sshResult.Success = false
		sshResult.Result = errbt.String()
		ch <- sshResult
	} else {
		sshResult.Success = true
		sshResult.Result = outbt.String()
		ch <- sshResult
	}

	return
}

// dosshRun ...
func dosshRun(username, password, host, key string, cmdlist []string, port int, cipherList []string, ch chan SSHResult) {
	session, err := connect(username, password, host, key, port, cipherList)
	var sshResult SSHResult
	sshResult.Host = host

	if err != nil {
		sshResult.Success = false
		sshResult.Result = fmt.Sprintf("<%s>", err.Error())
		ch <- sshResult
		return
	}
	defer session.Close()

	cmdlist = append(cmdlist, "exit")
	newcmd := strings.Join(cmdlist, "&&")

	var outbt, errbt bytes.Buffer
	session.Stdout = &outbt

	session.Stderr = &errbt
	err = session.Run(newcmd)
	if err != nil {
		sshResult.Success = false
		sshResult.Result = fmt.Sprintf("<%s>", err.Error())
		ch <- sshResult
		return
	}

	if errbt.String() != "" {
		sshResult.Success = false
		sshResult.Result = errbt.String()
		ch <- sshResult
	} else {
		sshResult.Success = true
		sshResult.Result = outbt.String()
		ch <- sshResult
	}

	return
}
