package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"

	"golang.org/x/term"
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

func (pm *PasswordManager) GetPasswordsByCategory(category string) []Password {
	passwords := make([]Password, 0)

	for _, p := range pm.passwords {
		if p.Category == category {
			passwords = append(passwords, p)
		}
	}

	return passwords
}

func (pm *PasswordManager) FindDuplicatePasswords() map[string][]string {
	duplicatedPasswords := make(map[string][]string)

	for _, p := range pm.passwords {
		duplicatedPasswords[p.Value] = append(duplicatedPasswords[p.Value], p.Name)
	}

	for key, services := range duplicatedPasswords {
		if len(services) <= 1 {
			delete(duplicatedPasswords, key)
		}
	}

	return duplicatedPasswords
}

func (pm *PasswordManager) UpdatePassword(name, newValue string) error {
	if !pm.isInitialized {
		return errors.New(ErrPasswordManagerNotInitialized)
	}

	password, err := pm.GetPassword(name)
	if err != nil {
		return err
	}

	if err = pm.CheckPasswordStrength(newValue); err != nil {
		return err
	}

	password.Value = newValue
	password.LastModified = time.Now()

	pm.passwords[name] = password

	return nil
}

func (pm *PasswordManager) DeletePassword(name string) error {
	if !pm.isInitialized {
		return errors.New(ErrPasswordManagerNotInitialized)
	}

	_, err := pm.GetPassword(name)
	if err != nil {
		return err
	}

	delete(pm.passwords, name)

	return nil
}

func (pm *PasswordManager) ListCategories() []string {
	set := make(map[string]bool)

	for _, p := range pm.passwords {
		set[p.Category] = true
	}

	categories := make([]string, 0, len(set))
	for key := range set {
		categories = append(categories, key)
	}

	sort.Strings(categories)
	return categories
}

func (pm *PasswordManager) GetPasswordStats() map[string]interface{} {
	stats := make(map[string]interface{})
	stats["total"] = len(pm.passwords)

	if len(pm.passwords) == 0 {
		stats["categoryCount"] = map[string]int{}
		stats["oldest"] = nil
		stats["newest"] = nil
		return stats
	}

	categoryCount := make(map[string]int)
	var oldest, newest time.Time
	first := true

	for _, p := range pm.passwords {
		categoryCount[p.Category]++

		if first {
			oldest, newest = p.CreatedAt, p.CreatedAt
			first = false
			continue
		}
		if p.CreatedAt.Before(oldest) {
			oldest = p.CreatedAt
		}
		if p.CreatedAt.After(newest) {
			newest = p.CreatedAt
		}
	}

	stats["categoryCount"] = categoryCount
	stats["oldest"] = oldest
	stats["newest"] = newest

	return stats
}

const (
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorReset  = "\033[0m"
)

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

func showSuccess(message string) {
	fmt.Printf("%s✓ Success: %s%s\n", colorGreen, message, colorReset)
}

func showError(message string) {
	fmt.Printf("%s✗ Error: %s%s\n", colorRed, message, colorReset)
}

func showInfo(message string) {
	fmt.Printf("%s→ Info: %s%s\n", colorYellow, message, colorReset)
}

func waitForEnter() {
	fmt.Print("\nНажмите Enter для продолжения...")

	_, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		fmt.Printf("failed to read input: %w", err)
		return
	}
}

func ReadUserInput(prompt string) string {
	fmt.Printf("%s: ", prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		fmt.Printf("⚠️  input error, please try again: %v\n", err)

		return ""
	}

	return strings.TrimSpace(line)
}

func readPassword() (string, error) {
	fmt.Printf("Enter password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}

	return string(password), nil
}

func ShowMainMenu() {
	clearScreen()

	separator := strings.Repeat("=", 50)
	fmt.Println(separator)
	fmt.Printf("%30s\n", "Password Manager")
	fmt.Println(separator)

	commands := []string{
		"Generate new password",
		"Add new password",
		"Get password",
		"List all passwords",
		"Update password",
		"Delete password",
		"List categories",
		"Show password statistics",
		"Find duplicate passwords",
	}

	for i, cmd := range commands {
		fmt.Printf("%d. %s\n", i+1, cmd)
	}

	fmt.Println("0. Exit")

	fmt.Println(separator)
}

func PrintPasswordList(passwords []Password) {
	fmt.Println("=== Password list ===")

	if len(passwords) == 0 {
		fmt.Println("ℹ️  No passwords found. Add one to get started!")
		return
	}

	fmt.Printf("%-25s %-15s %-12s %-12s\n", "Name", "Category", "Created", "Last Modified")
	fmt.Println(strings.Repeat("-", 70))

	for _, p := range passwords {
		fmt.Printf("%-25s %-15s %-12s %-12s\n",
			p.Name,
			p.Category,
			p.CreatedAt.Format(time.DateOnly),
			p.LastModified.Format(time.DateOnly),
		)
	}
}

func ShowPasswordDetails(password Password) {
	fmt.Println("=== Password details ===")
	fmt.Println("Service:", password.Name)
	fmt.Println("Category:", password.Category)
	fmt.Println("Password:", password.Value)
	fmt.Println("Created:", password.CreatedAt.Format(time.DateTime))
	fmt.Println("Last Modified:", password.LastModified.Format(time.DateTime))
}

func main() {
	fmt.Println("Happy coding!!!")
}
