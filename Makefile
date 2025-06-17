CC = g++
CFLAGS = -lcrypto -Wall  -Wextra -I./main/common -I./main/client -I./main/server
OUT_DIR = out

# Sources
COMMON_SRC = main/common/common.cpp
SERVER_SRC = main/server/server.cpp
CLIENT_SRC = main/client/client.cpp

# Objects
COMMON_OBJ = main/common/common.o
SERVER_OBJ = main/server/server.o
CLIENT_OBJ = main/client/client.o

# Targets
SERVER_BIN = $(OUT_DIR)/server
CLIENT_BIN = $(OUT_DIR)/client

.PHONY: all clean

all: $(SERVER_BIN) $(CLIENT_BIN)

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

# Compile object files - rely on implicit rule (gcc -c)
# just ensure directories exist
$(COMMON_OBJ): $(COMMON_SRC) main/common/common.h | $(OUT_DIR)
$(SERVER_OBJ): $(SERVER_SRC) main/server/server.h main/common/common.h | $(OUT_DIR)
$(CLIENT_OBJ): $(CLIENT_SRC) main/client/client.h main/common/common.h | $(OUT_DIR)

# Link server binary
$(SERVER_BIN): $(COMMON_OBJ) $(SERVER_OBJ) | $(OUT_DIR)
	$(CC) $(CFLAGS) $^ -o $@

# Link client binary
$(CLIENT_BIN): $(COMMON_OBJ) $(CLIENT_OBJ) | $(OUT_DIR)
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -rf $(OUT_DIR) main/common/*.o main/server/*.o main/client/*.o
