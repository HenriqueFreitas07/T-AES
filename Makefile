# Compiler and flags
CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2
DEBUGFLAGS := -g -O0
LDFLAGS := -lssl -lcrypto

# Directories
SRC_DIR := src
BUILD_DIR := build
BIN_DIR := bin
INCLUDE_DIR := include

# Target executable
TARGET := $(BIN_DIR)/program

# Source and object files
SRCS := $(wildcard $(SRC_DIR)/*.cpp)
OBJS := $(SRCS:$(SRC_DIR)/%.cpp=$(BUILD_DIR)/%.o)

# Include directories
INCLUDES := -I$(INCLUDE_DIR)

# Default target
all: $(TARGET)

# Encrypt program target
encrypt: $(BIN_DIR)/encrypt

$(BIN_DIR)/encrypt: $(BUILD_DIR)/encrypt.o
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "Encrypt program built: $(BIN_DIR)/encrypt"

# Decrypt program target
decrypt: $(BIN_DIR)/decrypt

$(BIN_DIR)/decrypt: $(BUILD_DIR)/decrypt.o
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "Decrypt program built: $(BIN_DIR)/decrypt"

# Verify AES program target
verify: $(BIN_DIR)/verify_aes

$(BIN_DIR)/verify_aes: $(BUILD_DIR)/verify_aes.o
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "Verify program built: $(BIN_DIR)/verify_aes"

# Link object files to create executable
$(TARGET): $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $(TARGET) $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

# Compile source files to object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# Debug build
debug: CXXFLAGS := -std=c++17 -Wall -Wextra $(DEBUGFLAGS)
debug: clean $(TARGET)

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
	@echo "Clean complete"

# Run the program
run: $(TARGET)
	./$(TARGET)

# Phony targets
.PHONY: all clean debug run

