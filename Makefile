CC = g++
CFLAGS = -Wall -Wextra -MMD -MP -g -I./src/common -I./src/client -I./src/server
LDFLAGS = -lcrypto

OUT_DIR = out
BUILD_DIR = build

# Automatically collect source files
COMMON_SRC = $(wildcard src/common/*.cpp)
CLIENT_SRC = $(wildcard src/client/*.cpp)
SERVER_SRC = $(wildcard src/server/*.cpp)

# Object files
COMMON_OBJ = $(patsubst src/common/%.cpp, $(BUILD_DIR)/common_%.o, $(COMMON_SRC))
CLIENT_OBJ = $(patsubst src/client/%.cpp, $(BUILD_DIR)/client_%.o, $(CLIENT_SRC))
SERVER_OBJ = $(patsubst src/server/%.cpp, $(BUILD_DIR)/server_%.o, $(SERVER_SRC))

# Targets
SERVER_BIN = $(OUT_DIR)/server
CLIENT_BIN = $(OUT_DIR)/client

.PHONY: all clean

all: $(SERVER_BIN) $(CLIENT_BIN)
	@echo "Build complete"

# Ensure output directories exist
$(OUT_DIR) $(BUILD_DIR):
	mkdir -p $@

# Compile common
$(BUILD_DIR)/common_%.o: src/common/%.cpp | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Compile client
$(BUILD_DIR)/client_%.o: src/client/%.cpp | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Compile server
$(BUILD_DIR)/server_%.o: src/server/%.cpp | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Link binaries
$(SERVER_BIN): $(COMMON_OBJ) $(SERVER_OBJ) | $(OUT_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(CLIENT_BIN): $(COMMON_OBJ) $(CLIENT_OBJ) | $(OUT_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Include dependency files if they exist
-include $(COMMON_OBJ:.o=.d) $(CLIENT_OBJ:.o=.d) $(SERVER_OBJ:.o=.d)


clean:
	rm -rf $(OUT_DIR) $(BUILD_DIR)

