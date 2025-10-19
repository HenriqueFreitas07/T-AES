# Compiler and flags
CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2
DEBUGFLAGS := -g -O0

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

$(BIN_DIR)/encrypt: $(BUILD_DIR)/encrypt.o $(BUILD_DIR)/utils.o $(BUILD_DIR)/AES.o
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $^ -o $@
	@echo "Encrypt program built: $(BIN_DIR)/encrypt"

# Link object files to create executable
$(TARGET): $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $(TARGET)
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

