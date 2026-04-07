package main

import (
	"fmt"
	"time"
)

type Password struct {
	Name         string    `json:"name"`
	Value        string    `json:"value"`
	Category     string    `json:"category"`
	CreatedAt    time.Time `json:"created_at"`
	LastModified time.Time `json:"last_modified"`
}

func NewPassword(name, value, category string) Password {
	return Password{
		Name:         name,
		Value:        value,
		Category:     category,
		CreatedAt:    time.Now(),
		LastModified: time.Now(),
	}
}

type PasswordManager struct {
	Passwords     map[string]Password `json:"passwords"`
	Key           string              `json:"key"`
	MasterKey     []byte              `json:"-"`
	FilePath      string              `json:"-"`
	IsInitialized bool                `json:"-"`
}

func NewPasswordManager(filePath string) *PasswordManager {
	return &PasswordManager{
		Passwords:     make(map[string]Password),
		FilePath:      filePath,
		IsInitialized: false,
	}
}

func main() {
	fmt.Println("Happy coding!!!")

	password := NewPassword("github.com", "superSecretPassword123", "development")
	fmt.Println(password)
}
