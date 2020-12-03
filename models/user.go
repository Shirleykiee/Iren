package models

import (
	"Iren/database"
	"Iren/utils"
	"errors"

	"github.com/jinzhu/gorm"
	"github.com/sirupsen/logrus"
)

// User ...
type User struct {
	ID       int    `gorm:"primary_key"`
	Username string `gorm:"type:varchar(100);not null;"`
	Password string `gorm:"type:varchar(100);not null;"`
}

// Register ...
func Register(u User) (err error, person User) {
	var user User
	err = database.DB.Where("username = ?", u.Username).First(&user).Error
	logrus.Println("Register.database.DB.Where: ", err)
	if !gorm.IsRecordNotFoundError(err) {
		return errors.New("用户名已经存在"), person
	}
	//if !errors.Is(database.DB.Where("username = ?", u.Username).First(&user).Error, gorm.ErrRecordNotFound) {
	//	return errors.New("用户名已经注册"), person
	//}

	u.Password = utils.MD5V([]byte(u.Password))
	err = database.DB.Create(&u).Error
	if err != nil {
		logrus.Printf("database.DB.Create: %v", err)
		return err, person
	}

	return nil, u
}

// Loginer ...
func Loginer(u *User) (pass bool, err error, person *User) {
	var user User
	u.Password = utils.MD5V([]byte(u.Password))
	err = database.DB.Where("username = ? And password = ?", u.Username, u.Password).First(&user).Error
	if err != nil {
		logrus.Printf("Loginer.database.DB.Where: %v", err)
		return false, err, person
	}

	return true, nil, u
}

// ChangePassword ...
func ChangePassword(u *User, changePassword string) (err error, person *User) {
	var user User
	u.Password = utils.MD5V([]byte(u.Password))
	err = database.DB.Where("username = ? And password = ?", u.Username, u.Password).First(&user).Update("password", utils.MD5V([]byte(changePassword))).Error
	if err != nil {
		logrus.Printf("ChangePassword.database.DB.Where: %v", err)
		return err, person
	}

	return nil, u
}

// DeleteUser ...
func DeleteUser(username string) (err error) {
	var user User
	err = database.DB.Where("username = ?", username).Delete(&user).Error
	if err != nil {
		logrus.Printf("DeleteUser.database.DB.Where: %v", err)
		return err
	}

	return nil
}
