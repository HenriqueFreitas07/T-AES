# Compiler and flags
CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2
CXXFLAGS_AESNI := -std=c++17 -Wall -Wextra -O2 -maes -msse4.1
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

# Default target - build all individual programs
all: encrypt decrypt encrypt_aesni decrypt_aesni verify speed stat speed_2 speed_3

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

# Encrypt AESNI program target (hardware-accelerated)
encrypt_aesni: $(BIN_DIR)/encrypt_aesni

$(BIN_DIR)/encrypt_aesni: $(BUILD_DIR)/encrypt_aesni.o
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS_AESNI) $^ -o $@ $(LDFLAGS)
	@echo "Encrypt AESNI program built: $(BIN_DIR)/encrypt_aesni"

# Decrypt AESNI program target (hardware-accelerated)
decrypt_aesni: $(BIN_DIR)/decrypt_aesni

$(BIN_DIR)/decrypt_aesni: $(BUILD_DIR)/decrypt_aesni.o
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS_AESNI) $^ -o $@ $(LDFLAGS)
	@echo "Decrypt AESNI program built: $(BIN_DIR)/decrypt_aesni"

# Verify AES program target
verify: $(BIN_DIR)/verify_aes

$(BIN_DIR)/verify_aes: $(BUILD_DIR)/verify_aes.o
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "Verify program built: $(BIN_DIR)/verify_aes"

# Speed benchmark program target (with AES-NI)
speed: $(BIN_DIR)/speed

$(BIN_DIR)/speed: $(BUILD_DIR)/speed.o
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS_AESNI) $^ -o $@ $(LDFLAGS)
	@echo "Speed benchmark program built: $(BIN_DIR)/speed"

# Statistical analysis program target
stat: $(BIN_DIR)/stat

$(BIN_DIR)/stat: $(BUILD_DIR)/stat.o
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "Statistical analysis program built: $(BIN_DIR)/stat"

# Speed benchmark v2 (excludes key expansion from timing)
speed_2: $(BIN_DIR)/speed_2

$(BIN_DIR)/speed_2: $(BUILD_DIR)/speed_2.o
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS_AESNI) $^ -o $@ $(LDFLAGS)
	@echo "Speed benchmark v2 program built: $(BIN_DIR)/speed_2"

# Speed benchmark v3 (T-AES vs OpenSSL XTS comparison)
speed_3: $(BIN_DIR)/speed_3

$(BIN_DIR)/speed_3: $(BUILD_DIR)/speed_3.o
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS_AESNI) $^ -o $@ $(LDFLAGS)
	@echo "Speed benchmark v3 program built: $(BIN_DIR)/speed_3"

# Link object files to create executable
$(TARGET): $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $(TARGET) $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

# Compile source files to object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# Compile AESNI source files with AES-NI and SSE4.1 flags
$(BUILD_DIR)/encrypt_aesni.o: $(SRC_DIR)/encrypt_aesni.cpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS_AESNI) $(INCLUDES) -c $< -o $@

$(BUILD_DIR)/decrypt_aesni.o: $(SRC_DIR)/decrypt_aesni.cpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS_AESNI) $(INCLUDES) -c $< -o $@

# Compile speed.o with AES-NI flags
$(BUILD_DIR)/speed.o: $(SRC_DIR)/speed.cpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS_AESNI) $(INCLUDES) -c $< -o $@

# Compile speed_2.o with AES-NI flags
$(BUILD_DIR)/speed_2.o: $(SRC_DIR)/speed_2.cpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS_AESNI) $(INCLUDES) -c $< -o $@

# Compile speed_3.o with AES-NI flags
$(BUILD_DIR)/speed_3.o: $(SRC_DIR)/speed_3.cpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS_AESNI) $(INCLUDES) -c $< -o $@

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
.PHONY: all clean debug run encrypt decrypt encrypt_aesni decrypt_aesni verify speed stat speed_2 speed_3

