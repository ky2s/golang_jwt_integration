package models

import (
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

type Tasks struct {
	gorm.Model
	ID          int    `gorm:"primaryKey;autoIncrement"`
	UsersID     int    `binding:"required"`
	Title       string `gorm:"size:255" binding:"required"`
	Description string `gorm:"text"`
	Status      string `gorm:"size:255;default:pending"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type TaskViews struct {
	ID          int       `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

type TaskModels interface {
	CreateTask(task Tasks) (Tasks, error)
	GetTaskRows(task Tasks) ([]Tasks, error)
	GetTaskRow(task Tasks) (Tasks, error)
	UpdateTask(id int, fields Tasks) (int, error)
	DeleteTask(id int) (bool, error)
}

// type connection struct {
// 	db *gorm.DB
// }

func NewTaskModels(dbg *gorm.DB) TaskModels {
	return &connection{
		db: dbg,
	}
}

func (con *connection) CreateTask(data Tasks) (Tasks, error) {
	err := con.db.Scopes(SchemaPublic("tasks")).Create(&data).Error
	if err != nil {
		fmt.Println(err)
		return Tasks{}, err
	}
	return data, nil
}

func (con *connection) GetTaskRows(fields Tasks) ([]Tasks, error) {

	var data []Tasks
	err := con.db.Find(&data).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	return data, err
}

func (con *connection) GetTaskRow(fields Tasks) (Tasks, error) {

	var data Tasks
	err := con.db.Where(fields).First(&data).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return Tasks{}, nil
	}

	if err != nil {
		return Tasks{}, err
	}

	return data, err
}

func (con *connection) UpdateTask(id int, fields Tasks) (int, error) {

	err := con.db.Scopes(SchemaPublic("tasks")).Where("id = ?", id).Updates(fields).Error
	if err != nil {
		fmt.Println(err)
		return 0, err
	}

	return id, nil
}

func (con *connection) DeleteTask(id int) (bool, error) {
	var data Tasks
	err := con.db.Scopes(SchemaPublic("tasks")).Where("id = ?", id).Delete(&data).Error
	if err != nil {
		return false, err
	}

	return true, err
}
