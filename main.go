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
	"strconv"
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

func readLine(scanner *bufio.Scanner, prompt string) (string, error) {
	if prompt != "" {
		fmt.Print(prompt)
	}
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("stdin read error: %w", err)
		}

		return "", io.EOF
	}
	return strings.TrimSpace(scanner.Text()), nil
}

// failWithUI отображает ошибку через showError, ждёт ввода и возвращает ошибку.
// Если err == nil, используется только сообщение msg.
func failWithUI(err error, msg string) error {
	if err != nil {
		msg = fmt.Sprintf("%s: %v", msg, err)
	}
	showError(msg)
	waitForEnter()

	if err != nil {
		return err
	}

	return errors.New(msg)
}

func HandlePasswordGeneration(pm *PasswordManager) error {
	clearScreen()

	fmt.Println("=== Password Generation ===")

	scanner := bufio.NewScanner(os.Stdin)

	line, err := readLine(scanner, "Enter password length (min 8): ")
	if err != nil {
		return failWithUI(err, "input error")
	}
	if line == "" {
		return failWithUI(nil, "the field is empty")
	}

	val, err := strconv.Atoi(line)
	if err != nil {
		return failWithUI(err, "invalid number format")
	}

	generatedPassword, err := pm.GeneratePassword(val)
	if err != nil {
		return failWithUI(err, "password generation failed")
	}

	showSuccess("Password generated successfully")
	fmt.Println("Generated password: ", generatedPassword)
	waitForEnter()

	return nil
}

func HandlePasswordAdd(pm *PasswordManager) error {
	clearScreen()
	password := ""

	fmt.Println("=== Add New Password ===")

	scanner := bufio.NewScanner(os.Stdin)

	serviceName, err := readLine(scanner, "Enter service name: ")
	if err != nil {
		return failWithUI(err, "input error")
	}
	if serviceName == "" {
		return failWithUI(nil, "service name cannot be empty")
	}

	enteredPassword, err := readLine(scanner, "Enter password (or press Enter to generate): ")
	if err != nil {
		return failWithUI(err, "input error")
	}
	if enteredPassword == "" {
		generatedPassword, err := pm.GeneratePassword(16)
		if err != nil {
			return failWithUI(err, "generate password error")
		}

		password = generatedPassword
		showInfo(fmt.Sprintf("Generated password: %s", password))
	} else {
		if err := pm.CheckPasswordStrength(enteredPassword); err != nil {
			return failWithUI(err, "check password error")
		}
		password = enteredPassword
	}

	category, err := readLine(scanner, "Enter category: ")
	if err != nil {
		return failWithUI(err, "input error")
	}
	if category == "" {
		return failWithUI(nil, "field category cannot be empty")
	}

	if err = pm.SavePassword(serviceName, password, category); err != nil {
		return failWithUI(err, "save password error")
	}

	showSuccess("Password saved successfully")

	waitForEnter()

	return nil
}

func HandlePasswordSearch(pm *PasswordManager) error {
	clearScreen()

	fmt.Println("=== Search Password ===")

	scanner := bufio.NewScanner(os.Stdin)

	serviceName, err := readLine(scanner, "Enter service name: ")
	if err != nil {
		return failWithUI(err, "input error")
	}
	if serviceName == "" {
		return failWithUI(nil, "service name cannot be empty")
	}

	password, err := pm.GetPassword(serviceName)
	if err != nil {
		return failWithUI(err, "search error")
	}

	fmt.Println()
	ShowPasswordDetails(password)
	showSuccess("Password found and displayed")

	waitForEnter()

	return nil
}

func HandlePasswordUpdate(pm *PasswordManager) error {
	clearScreen()

	fmt.Println("=== Update Password ===")

	scanner := bufio.NewScanner(os.Stdin)

	serviceName, err := readLine(scanner, "Enter service name: ")
	if err != nil {
		return failWithUI(err, "input error")
	}
	if serviceName == "" {
		return failWithUI(nil, "service name cannot be empty")
	}

	newPassword, err := readLine(scanner, "Enter new password: ")
	if err != nil {
		return failWithUI(err, "input error")
	}
	if newPassword == "" {
		return failWithUI(nil, "new password cannot be empty")
	}

	if err = pm.UpdatePassword(serviceName, newPassword); err != nil {
		return failWithUI(err, "update password error")
	}

	showSuccess("Password updated successfully")

	waitForEnter()

	return nil
}

func HandleExitAndSave(pm *PasswordManager) error {
	clearScreen()

	fmt.Println("=== Saving and Exiting ===")
	fmt.Println("Saving changes...")

	if err := pm.SaveToFile(); err != nil {
		return fmt.Errorf("error saving data: %w", err)
	}

	showSuccess("Changes saved successfully!")
	showSuccess("Goodbye!")
	return nil
}

// handleLoadError обрабатывает ошибки загрузки файла и показывает понятное сообщение пользователю.
// Возвращает true, если можно продолжить работу с пустым хранилищем.
func handleLoadError(err error) bool {
	if errors.Is(err, os.ErrNotExist) {
		// Первый запуск — это нормально
		showInfo("New profile created — password store is empty")
		return true
	}

	// Анализируем тип ошибки для понятного сообщения
	errMsg := err.Error()

	switch {
	case strings.Contains(errMsg, "message authentication failed"):
		// ❗ Самая частая: неверный мастер-пароль
		showError("Incorrect master password")
		fmt.Printf("%sSaved data cannot be decrypted with this password.%s\n", colorYellow, colorReset)
		fmt.Printf("%sTips:%s\n", colorYellow, colorReset)
		fmt.Printf("  • Check if Caps Lock is on\n")
		fmt.Printf("  • Try your previous master password\n")
		fmt.Printf("  • If you forgot it, saved passwords cannot be recovered\n")
		showInfo("Starting with empty password store. Use correct password next time to access saved data.")
		return true

	case strings.Contains(errMsg, "corrupted") || strings.Contains(errMsg, "invalid cipher"):
		// Файл повреждён
		showError("Password file is corrupted")
		fmt.Printf("%sThe data file may be damaged or modified.%s\n", colorYellow, colorReset)
		showInfo("Starting with empty password store. Restore from backup if available.")
		return true

	case strings.Contains(errMsg, "permission denied"):
		// Нет прав доступа
		showError("Cannot access password file")
		fmt.Printf("%sCheck file permissions or disk space.%s\n", colorYellow, colorReset)
		return false // Нельзя продолжить

	default:
		// Неизвестная ошибка — показываем техническую деталь для отладки
		_ = failWithUI(err, "failed to load saved passwords")
		return true // Продолжаем с пустым хранилищем
	}
}

func main() {
	fmt.Println("=== Password Manager Initialization ===")
	masterPassword, err := readPassword()
	if err != nil {
		_ = failWithUI(err, "failed to read master password")
		return
	}
	if masterPassword == "" {
		_ = failWithUI(nil, "master password cannot be empty")
		return
	}

	pm := NewPasswordManager("passwords.dat")
	if err = pm.SetMasterPassword(masterPassword); err != nil {
		_ = failWithUI(err, "failed to set master password")
		return
	}

	if err = pm.LoadFromFile(); err != nil {
		if !handleLoadError(err) {
			return
		}
	}

	showSuccess("Password manager initialized successfully")
	waitForEnter()

	for {
		ShowMainMenu()

		choice := ReadUserInput("Enter your choice")

		switch choice {
		case "1":
			err = HandlePasswordGeneration(pm)
		case "2":
			err = HandlePasswordAdd(pm)
		case "3":
			err = HandlePasswordSearch(pm)
		case "4":
			clearScreen()
			PrintPasswordList(pm.ListPasswords())
			waitForEnter()
		case "5":
			err = HandlePasswordUpdate(pm)
		case "6":
			name := ReadUserInput("Enter password name to delete")
			if name != "" {
				if err = pm.DeletePassword(name); err != nil {
					_ = failWithUI(err, "delete password error")
				} else {
					showSuccess("Password deleted successfully")
					waitForEnter()
				}
			}
		case "7":
			categories := pm.ListCategories()
			clearScreen()

			fmt.Println("=== Categories ===")
			for _, c := range categories {
				fmt.Printf("• %s\n", c)
			}
			waitForEnter()
		case "8":
			clearScreen()
			fmt.Println("=== Password Statistics ===")

			stats := pm.GetPasswordStats()
			total, _ := stats["total"].(int)

			if total == 0 {
				fmt.Println("ℹ️  No passwords saved yet. Statistics will appear here once you add some.")
			} else {
				fmt.Printf("%sTotal passwords:%s %d\n\n", colorGreen, colorReset, total)

				if catMap, ok := stats["categoryCount"].(map[string]int); ok && len(catMap) > 0 {
					fmt.Printf("%sPasswords by category:%s\n", colorYellow, colorReset)

					var categories []string
					for cat := range catMap {
						categories = append(categories, cat)
					}
					sort.Strings(categories)

					for _, cat := range categories {
						count := catMap[cat]
						fmt.Printf("  • %-15s %d\n", cat, count)
					}
					fmt.Println()
				}

				oldest, _ := stats["oldest"].(time.Time)
				newest, _ := stats["newest"].(time.Time)

				if !oldest.IsZero() || !newest.IsZero() {
					fmt.Printf("%sActivity timeline:%s\n", colorYellow, colorReset)
					fmt.Printf("  First added:  %s\n", oldest.Format(time.DateTime))
					fmt.Printf("  Last added:   %s\n", newest.Format(time.DateTime))
				}
			}

			waitForEnter()
		case "9":
			duplicates := pm.FindDuplicatePasswords()
			clearScreen()
			if len(duplicates) == 0 {
				fmt.Println("No duplicate passwords found")
			} else {
				fmt.Println("=== Duplicate passwords ===")
				for pwd, services := range duplicates {
					fmt.Printf("Password '%s' used in: %v\n", pwd, services)
				}
			}
			waitForEnter()
		case "0":
			if err = HandleExitAndSave(pm); err != nil {
				showError(fmt.Sprintf("Failed to save: %v", err))
			}
			return
		default:
			showError("Invalid command, please try again")
			waitForEnter()
			continue
		}
	}
}
