package database

import (
	"Iren/config"
	"os"

	"github.com/sirupsen/logrus"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB

func GormDns() *gorm.DB {
	m := config.C.Mysql
	dsn := m.Username + ":" + m.Password + "@tcp(" + m.IP + ":" + m.Port + ")/" + m.Dbname + "?" + "charset=utf8"
	mysqlConfig := mysql.Config{
		DSN:                       dsn,   // DSN data source name
		DefaultStringSize:         191,   // string 类型字段的默认长度
		DisableDatetimePrecision:  true,  // 禁用 datetime 精度，MySQL 5.6 之前的数据库不支持
		DontSupportRenameIndex:    true,  // 重命名索引时采用删除并新建的方式，MySQL 5.7 之前的数据库和 MariaDB 不支持重命名索引
		DontSupportRenameColumn:   true,  // 用 `change` 重命名列，MySQL 8 之前的数据库和 MariaDB 不支持重命名列
		SkipInitializeWithVersion: false, // 根据版本自动配置
	}
	if DB, err := gorm.Open(mysql.New(mysqlConfig), &gorm.Config{}); err != nil {
		logrus.Printf("gorm.Open: %v", err)
		os.Exit(0)
		return nil
	} else {
		sqlDB, _ := DB.DB()
		sqlDB.SetMaxIdleConns(m.Max_idle_conns)
		sqlDB.SetMaxOpenConns(m.Max_open_conns)
		return DB
	}
}
