package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode"
)

const (
	ErrLessThanEightCharacters       = "password is too weak"
	ErrPasswordManagerNotInitialized = "password manager not initialized"
	ErrPasswordAlreadyExists         = "password already exists"
	ErrPasswordNotFound              = "password not found"
)

type PasswordValidationError struct {
	Missing []string
}

func (e *PasswordValidationError) Error() string {
	return fmt.Sprintf("password validation failed: missing %s", strings.Join(e.Missing, ", "))
}

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

func (pm *PasswordManager) SaveToFile() error {
	if !pm.isInitialized {
		return errors.New(ErrPasswordManagerNotInitialized)
	}

	data, err := json.Marshal(pm.passwords)
	if err != nil {
		return fmt.Errorf("error encode data: %w", err)
	}

	block, err := aes.NewCipher(pm.masterKey)
	if err != nil {
		return fmt.Errorf("error create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("error create gcm: %w", err)
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("error readFull nonce: %w", err)
	}

	cipherText := aesgcm.Seal(nil, nonce, data, nil)

	file, err := os.Create(pm.filePath)
	if err != nil {
		return fmt.Errorf("error create file: %w", err)
	}
	defer file.Close()

	_, err = file.Write(nonce)
	if err != nil {
		return fmt.Errorf("error write nonce: %w", err)
	}

	_, err = file.Write(cipherText)
	if err != nil {
		return fmt.Errorf("error write cipherText: %w", err)
	}

	return nil
}

func (pm *PasswordManager) LoadFromFile() error {
	if !pm.isInitialized {
		return errors.New(ErrPasswordManagerNotInitialized)
	}

	file, err := os.Open(pm.filePath)
	if err != nil {
		return fmt.Errorf("error open file: %w", err)
	}
	defer file.Close()

	block, err := aes.NewCipher(pm.masterKey)
	if err != nil {
		return fmt.Errorf("error create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("error create gcm: %w", err)
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err = io.ReadFull(file, nonce); err != nil {
		return fmt.Errorf("error read nonce: %w", err)
	}

	encryptedData, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("error read encrypted data: %w", err)
	}

	decryptedData, err := aesgcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt: invalid key or corrupted data: %w", err)
	}

	pm.passwords = make(map[string]Password)

	if err = json.Unmarshal(decryptedData, &pm.passwords); err != nil {
		return fmt.Errorf("error unmarshal decrypted data: %w", err)
	}

	return nil
}

func (pm *PasswordManager) CheckPasswordStrength(password string) error {
	if len([]rune(password)) < 8 {
		return errors.New(ErrLessThanEightCharacters)
	}

	hasUpper, hasLower, hasDigit, hasSpecials := false, false, false, false
	specials := "!@#$%^&*"

	for _, r := range strings.Trim(password, " ") {
		switch {
		case unicode.IsSpace(r):
			return errors.New("password must not contain spaces")
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case strings.ContainsRune(specials, r):
			hasSpecials = true
		}
	}

	if !hasUpper && !hasLower && !hasDigit && !hasSpecials {
		return nil
	}

	var missing []string
	if !hasUpper {
		missing = append(missing, "uppercase letter")
	}
	if !hasLower {
		missing = append(missing, "lowercase letter")
	}
	if !hasDigit {
		missing = append(missing, "digit")
	}
	if !hasSpecials {
		missing = append(missing, "special symbol")
	}

	if len(missing) > 0 {
		return &PasswordValidationError{Missing: missing}
	}

	return nil
}

func main() {
	fmt.Println("Happy coding!!!")
}
