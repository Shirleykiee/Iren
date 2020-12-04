package config

import (
	"flag"
	"os"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type Config struct {
	Mysql Dns
}

var C Config

func Viper(path ...string) error {
	var config string
	if len(path) == 0 {
		flag.StringVar(&config, "c", "", "choose config file.")
		flag.Parse()
		if config == "" {
			if configEnv := os.Getenv("Iren"); configEnv == "" {
				config = "config.yaml"
				logrus.Printf("您正在使用config的默认值,config的路径为%v", "config.yaml")
			} else {
				config = configEnv
				logrus.Printf("您正在使用GVA_CONFIG环境变量,config的路径为%v", config)
			}
		} else {
			logrus.Printf("您正在使用命令行的-c参数传递的值,config的路径为%v", config)
		}
	} else {
		config = path[0]
		logrus.Printf("您正在使用func Viper()传递的值,config的路径为%v", config)
	}

	// 加载配置文件
	v := viper.New()
	v.SetConfigFile(config)
	err := v.ReadInConfig()
	if err != nil {
		logrus.Printf("Fatal error config file: %s", err)
		return err

		os.Exit(0)
	}

	// 监控并重新读取配置文件
	v.WatchConfig()

	v.OnConfigChange(func(e fsnotify.Event) {
		logrus.Println("config file changed:", e.Name)
		if err := v.Unmarshal(&C); err != nil {
			logrus.Println("v.:Unamrshal:", err)
		}
	})

	// 数据解析到配置文件
	if err := v.Unmarshal(&C); err != nil {
		logrus.Println("v.:Unamrshal:", err)
	}
	return nil
}
