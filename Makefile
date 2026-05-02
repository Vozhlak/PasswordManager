APP_NAME := pm
BUILD_DIR := ./build
GO_FILES := $(shell find . -name '*.go' -type f)

.DEFAULT_GOAL := help

.PHONY: help build run test test-cover clean lint fmt install

help: ## 📖 Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## 🔨 Build the binary
	@mkdir -p $(BUILD_DIR)
	go build -ldflags="-s -w" -o $(BUILD_DIR)/$(APP_NAME) main.go
	@echo "✅ Build successful: $(BUILD_DIR)/$(APP_NAME)"

run: ## 🚀 Run the application
	go run main.go

test: ## 🧪 Run tests
	go test -v -race ./...

test-cover: ## 📊 Run tests with coverage report
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "📈 Coverage report: coverage.html"

clean: ## 🧹 Remove build artifacts and caches
	rm -rf $(BUILD_DIR) coverage.out coverage.html *.test
	go clean -cache -testcache
	@echo "🧹 Cleaned up"

lint: ## 🔍 Format and vet code
	go fmt ./...
	go vet ./...
	@echo "✅ Code formatted and vetted"

fmt: ## ✨ Format Go source code
	go fmt ./...
	@echo "✨ Code formatted"

install: ## 📦 Install binary to $GOPATH/bin or $GOBIN
	go install .
	@echo "📦 Installed $(APP_NAME) to $(shell go env GOPATH)/bin"