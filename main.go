package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"time"
)

const (
	ErrLessThanEightCharacters       = "password is too weak"
	ErrPasswordManagerNotInitialized = "password manager not initialized"
	ErrPasswordAlreadyExists         = "password already exists"
	ErrPasswordNotFound              = "password not found"
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

func (pm *PasswordManager) GetPassword(name string) (Password, error) {
	if !pm.isInitialized {
		return Password{}, errors.New(ErrPasswordManagerNotInitialized)
	}

	password, exists := pm.passwords[name]
	if !exists {
		return Password{}, errors.New(ErrPasswordNotFound)
	}

	return password, nil
}

func (pm *PasswordManager) ListPasswords() []Password {
	passwords := make([]Password, 0, len(pm.passwords))

	for _, password := range pm.passwords {
		passwords = append(passwords, password)
	}

	return passwords
}

func (pm *PasswordManager) GeneratePassword(length int) (string, error) {
	if length < 8 {
		return "", errors.New(ErrLessThanEightCharacters)
	}

	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+{}|;:'\",.<>?`~"
	randomBytes := make([]byte, length)

	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	password := make([]byte, length)
	charsetLen := byte(len(charset))

	for i := 0; i < length; i++ {
		password[i] = charset[randomBytes[i]%charsetLen]
	}

	return string(password), nil
}

func main() {
	fmt.Println("Happy coding!!!")
}
