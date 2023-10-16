package models

import (
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

type Users struct {
	gorm.Model
	ID        int    `gorm:"primaryKey;autoIncrement"`
	Name      string `gorm:"size:255" binding:"required"`
	Email     string `gorm:"size:255;unique" binding:"required"`
	Password  string `gorm:"size:255" binding:"required"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type UserAuth struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type Login struct {
	Email    string `form:"email" json:"email" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

type UserViews struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GiveName      string `json:"give_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
}

func SchemaPublic(tableName string) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Table(tableName)
	}
}

type UserModels interface {
	CreateUser(user Users) (Users, error)
	GetUserRows(user Users) ([]Users, error)
	GetUserRow(user Users) (Users, error)
	UpdateUser(id int, fields Users) (int, error)
	DeleteUser(id int) (bool, error)
}

type connection struct {
	db *gorm.DB
}

func NewUserModels(dbg *gorm.DB) UserModels {
	return &connection{
		db: dbg,
	}
}

func (con *connection) CreateUser(data Users) (Users, error) {
	err := con.db.Scopes(SchemaPublic("users")).Create(&data).Error
	if err != nil {
		fmt.Println(err)
		return Users{}, err
	}
	return data, nil
}

func (con *connection) GetUserRows(fields Users) ([]Users, error) {

	var data []Users
	err := con.db.Find(&data).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	return data, err
}

func (con *connection) GetUserRow(fields Users) (Users, error) {

	var data Users
	err := con.db.Where(fields).First(&data).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return Users{}, nil
	}

	if err != nil {
		return Users{}, err
	}

	return data, err
}

func (con *connection) UpdateUser(userID int, fields Users) (int, error) {

	err := con.db.Scopes(SchemaPublic("users")).Where("id = ?", userID).Updates(fields).Error
	if err != nil {
		fmt.Println(err)
		return 0, err
	}

	return userID, nil
}

func (con *connection) DeleteUser(id int) (bool, error) {
	var data Users
	err := con.db.Scopes(SchemaPublic("users")).Where("id = ?", id).Delete(&data).Error
	if err != nil {
		return false, err
	}

	return true, err
}
