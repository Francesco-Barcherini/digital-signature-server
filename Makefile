CC = g++
CFLAGS = -lcrypto -Wall -Wextra -I./src/common -I./src/client -I./src/server

OUT_DIR = out
BUILD_DIR = build

# Sources
COMMON_SRC = src/common/common.cpp
SERVER_SRC = src/server/server.cpp
CLIENT_SRC = src/client/client.cpp

# Object files (in build directory)
COMMON_OBJ = $(BUILD_DIR)/common.o
SERVER_OBJ = $(BUILD_DIR)/server.o
CLIENT_OBJ = $(BUILD_DIR)/client.o

# Targets
SERVER_BIN = $(OUT_DIR)/server
CLIENT_BIN = $(OUT_DIR)/client

.PHONY: all clean

all: $(SERVER_BIN) $(CLIENT_BIN)

# Ensure output directories exist
$(OUT_DIR) $(BUILD_DIR):
	mkdir -p $@

# Compile object files
$(COMMON_OBJ): $(COMMON_SRC) src/common/common.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(SERVER_OBJ): $(SERVER_SRC) src/server/server.h src/common/common.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(CLIENT_OBJ): $(CLIENT_SRC) src/client/client.h src/common/common.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Link binaries
$(SERVER_BIN): $(COMMON_OBJ) $(SERVER_OBJ) | $(OUT_DIR)
	$(CC) $(CFLAGS) $^ -o $@

$(CLIENT_BIN): $(COMMON_OBJ) $(CLIENT_OBJ) | $(OUT_DIR)
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -rf $(OUT_DIR) $(BUILD_DIR)
