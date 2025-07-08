# Include configuración externa (compilador, flags, etc.)
include ./Makefile.inc

# === Fuente por ubicación ===
SERVER_SOURCES = $(wildcard src/server/*.c)
ADMIN_SERVER_SOURCES = $(wildcard src/admin_server/*.c)
CLIENT_SOURCES = $(wildcard src/admin_client/*.c)
SHARED_SOURCES = $(wildcard src/shared/*.c)
ROOT_SOURCES   = $(wildcard src/*.c)

# === Objetos generados ===
OBJECTS_FOLDER = ./obj
OUTPUT_FOLDER  = ./bin

SERVER_OBJECTS = $(SERVER_SOURCES:src/%.c=$(OBJECTS_FOLDER)/%.o)
ADMIN_SERVER_OBJECTS = $(ADMIN_SERVER_SOURCES:src/%.c=$(OBJECTS_FOLDER)/%.o)
CLIENT_OBJECTS = $(CLIENT_SOURCES:src/%.c=$(OBJECTS_FOLDER)/%.o)
SHARED_OBJECTS = $(SHARED_SOURCES:src/%.c=$(OBJECTS_FOLDER)/%.o)
ROOT_OBJECTS   = $(ROOT_SOURCES:src/%.c=$(OBJECTS_FOLDER)/%.o)

# === Binarios resultantes ===
SERVER_OUTPUT_FILE = $(OUTPUT_FOLDER)/socks5
CLIENT_OUTPUT_FILE = $(OUTPUT_FOLDER)/client

# === Targets principales ===
all: server client

server: $(SERVER_OUTPUT_FILE)
client: $(CLIENT_OUTPUT_FILE)

# === Reglas de enlace ===
$(SERVER_OUTPUT_FILE): $(SERVER_OBJECTS) $(SHARED_OBJECTS) $(ROOT_OBJECTS) $(ADMIN_SERVER_OBJECTS)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILERFLAGS) $(LDFLAGS) $^ -o $@

$(CLIENT_OUTPUT_FILE): $(CLIENT_OBJECTS) $(ADMIN_SERVER_OBJECTS) $(SHARED_OBJECTS) $(ROOT_OBJECTS)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILERFLAGS) $(LDFLAGS) $^ -o $@

# === Reglas de compilación por archivo fuente ===
$(OBJECTS_FOLDER)/%.o: src/%.c
	mkdir -p $(dir $@)
	$(COMPILER) $(COMPILERFLAGS) -c $< -o $@

# === Limpieza ===
clean:
	rm -rf $(OUTPUT_FOLDER)
	rm -rf $(OBJECTS_FOLDER)

.PHONY: all server client clean