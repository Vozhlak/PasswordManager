package main

import (
	"errors"
	"fmt"
	"time"
)

const (
	ErrLessThanEightCharacters       = "password is too weak"
	ErrPasswordManagerNotInitialized = "password manager not initialized"
	ErrPasswordAlreadyExists         = "password already exists"
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
	passwords     map[string]Password `json:"passwords"`
	masterKey     []byte              `json:"-"`
	filePath      string              `json:"-"`
	isInitialized bool                `json:"-"`
}

func NewPasswordManager(filePath string) *PasswordManager {
	return &PasswordManager{
		passwords:     make(map[string]Password),
		filePath:      filePath,
		isInitialized: false,
	}
}

func (pm *PasswordManager) SetMasterPassword(masterPassword string) error {
	if len(masterPassword) < 8 {
		return errors.New(ErrLessThanEightCharacters)
	}

	buffKey := make([]byte, 32)

	copy(buffKey, []byte(masterPassword))

	pm.masterKey = buffKey
	pm.isInitialized = true

	return nil
}

func (pm *PasswordManager) SavePassword(name, value, category string) error {
	if !pm.isInitialized {
		return errors.New(ErrPasswordManagerNotInitialized)
	}

	_, exists := pm.passwords[name]
	if exists {
		return errors.New(ErrPasswordAlreadyExists)
	}

	createdPassword := NewPassword(name, value, category)

	pm.passwords[name] = createdPassword

	return nil
}

func main() {
	fmt.Println("Happy coding!!!")
}
