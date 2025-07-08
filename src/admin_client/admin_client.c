#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include "../shared/logger.h"
#include "../admin_server/admin_protocol.h"

#define ADMIN_CLIENT_BUFFER_SIZE 2048
#define MAX_INPUT 256

struct admin_client {
    int sock;
    uint8_t buffer[ADMIN_CLIENT_BUFFER_SIZE];
};

static void print_menu(void);
static void handle_list_users(int sock);
static void handle_add_user(int sock, const char *user, const char *pass);
static void handle_del_user(int sock, const char *user);
static void handle_get_metrics(int sock);
static void handle_set_log_level(int sock, int level);
static void handle_set_max_connections(int sock, int max);

static int admin_client_connect(const char *host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("Error creando socket: %s\n", strerror(errno));
        return -1;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        printf("Dirección IP inválida: %s\n", host);
        close(sock);
        return -1;
    }
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        printf("Error conectando: %s\n", strerror(errno));
        close(sock);
        return -1;
    }
    
    return sock;
}

static int admin_client_authenticate(int sock, const char *token) {
    uint8_t auth_msg[256];
    uint8_t token_len = strlen(token);
    
    auth_msg[0] = ADMIN_VERSION;
    auth_msg[1] = token_len;
    memcpy(auth_msg + 2, token, token_len);
    
    if (send(sock, auth_msg, 2 + token_len, 0) < 0) {
        printf("Error enviando autenticación: %s\n", strerror(errno));
        return -1;
    }
    
    // Leer rta
    uint8_t response[4];
    if (recv(sock, response, 2, 0) < 2) {
        printf("Error recibiendo respuesta de autenticación\n");
        return -1;
    }
    
    if (response[0] != ADMIN_VERSION || response[1] != ADMIN_REP_SUCCESS) {
        printf("Autenticación fallida: código %d\n", response[1]);
        return -1;
    }
    
    printf("Autenticación exitosa\n");
    return 0;
}

static int admin_client_send_command(int sock, uint8_t command, const uint8_t *data, uint16_t data_len) {
    uint8_t cmd_msg[1024];
    uint16_t offset = 0;
    
    cmd_msg[offset++] = ADMIN_VERSION;
    cmd_msg[offset++] = command;
    
    if (data_len > 0) {
        cmd_msg[offset++] = (data_len >> 8) & 0xFF;
        cmd_msg[offset++] = data_len & 0xFF;
        memcpy(cmd_msg + offset, data, data_len);
        offset += data_len;
    }
    
    if (send(sock, cmd_msg, offset, 0) < 0) {
        printf("Error enviando comando: %s\n", strerror(errno));
        return -1;
    }
    
    return 0;
}

static int admin_client_receive_response(int sock, uint8_t *response_code, uint8_t *data, uint16_t *data_len) {
    uint8_t header[4];
    
    if (recv(sock, header, 2, 0) < 2) {
        printf("Error recibiendo respuesta\n");
        return -1;
    }
    
    if (header[0] != ADMIN_VERSION) {
        printf("Versión de respuesta inválida: %d\n", header[0]);
        return -1;
    }
    
    *response_code = header[1];
    *data_len = 0;
    
    // Verificar si hay datos extra
    if (*response_code == ADMIN_REP_SUCCESS) {
        // Intentar leer longitud de datos
        if (recv(sock, header + 2, 2, MSG_DONTWAIT) == 2) {
            *data_len = (header[2] << 8) | header[3];
            if (*data_len > 0) {
                if (recv(sock, data, *data_len, 0) < *data_len) {
                    printf("Error recibiendo datos de respuesta\n");
                    return -1;
                }
            }
        }
    }
    
    return 0;
}


static void handle_list_users(int sock) {
    printf("\n--- Listando usuarios ---\n");
    
    if (admin_client_send_command(sock, ADMIN_CMD_LIST_USERS, NULL, 0) < 0) {
        return;
    }
    
    uint8_t response_code;
    uint8_t data[1024];
    uint16_t data_len;
    
    if (admin_client_receive_response(sock, &response_code, data, &data_len) < 0) {
        return;
    }
    
    if (response_code != ADMIN_REP_SUCCESS) {
        printf("Error: código de respuesta %d\n", response_code);
        return;
    }
    
    if (data_len < 2) {
        printf("No hay usuarios\n");
        return;
    }
    
    uint16_t count = (data[0] << 8) | data[1];
    uint16_t offset = 2;
    
    printf("Usuarios encontrados: %d\n", count);
    
    for (uint16_t i = 0; i < count && offset < data_len; i++) {
        uint8_t username_len = data[offset++];
        if (offset + username_len >= data_len) break;
        
        char username[256];
        memcpy(username, data + offset, username_len);
        username[username_len] = '\0';
        offset += username_len;
        
        uint8_t active = data[offset++];
        
        printf("- %s (%s)\n", username, active ? "activo" : "inactivo");
    }

    printf("\n");
}

void handle_add_user(int sock, const char *username, const char *password) {
    uint8_t data[512];
    uint16_t offset = 0;

    uint8_t username_len = strlen(username);
    uint8_t password_len = strlen(password);

    if (username_len == 0 || password_len == 0 || username_len > 255 || password_len > 255) {
        printf("Los argumentos son invalidos\n");
        return;
    }

    data[offset++] = username_len;
    memcpy(data + offset, username, username_len);
    offset += username_len;

    data[offset++] = password_len;
    memcpy(data + offset, password, password_len);
    offset += password_len;

    if (admin_client_send_command(sock, ADMIN_CMD_ADD_USER, data, offset) < 0) return;

    uint8_t response_code;
    uint8_t response_data[1024];
    uint16_t response_len;

    if (admin_client_receive_response(sock, &response_code, response_data, &response_len) < 0) return;

    if (response_code == ADMIN_REP_SUCCESS) {
        printf("\nUsuario '%s' agregado exitosamente\n\n", username);
    } else {
        printf("\nError agregando usuario: codigo %d\n\n", response_code);
    }
}

void handle_del_user(int sock, const char *username) {
    uint8_t data[256];
    uint8_t username_len = strlen(username);

    if (username_len == 0 || username_len > 255) {
        printf("\nNombre de usuario invalido\n\n");
        return;
    }

    data[0] = username_len;
    memcpy(data + 1, username, username_len);

    if (admin_client_send_command(sock, ADMIN_CMD_DEL_USER, data, 1 + username_len) < 0) return;

    uint8_t response_code;
    uint8_t response_data[1024];
    uint16_t response_len;

    if (admin_client_receive_response(sock, &response_code, response_data, &response_len) < 0) return;

    if (response_code == ADMIN_REP_SUCCESS) {
        printf("\nUsuario '%s' eliminado exitosamente\n\n", username);
    } else {
        printf("\nError eliminando usuario: codigo %d\n\n", response_code);
    }
}

static void handle_get_metrics(int sock) {
    printf("\n--- Obteniendo metricas ---\n");
    
    if (admin_client_send_command(sock, ADMIN_CMD_GET_METRICS, NULL, 0) < 0) {
        return;
    }
    
    uint8_t response_code;
    uint8_t data[1024];
    uint16_t data_len;
    
    if (admin_client_receive_response(sock, &response_code, data, &data_len) < 0) {
        return;
    }
    
    if (response_code != ADMIN_REP_SUCCESS) {
        printf("\nError obteniendo metricas: codigo %d\n\n", response_code);
        return;
    }
    
    if (data_len < 40) {
        printf("\nDatos de metricas insuficientes\n\n");
        return;
    }
    
    // metricas
    uint64_t total_conn = 0, current_conn = 0, total_bytes = 0;
    uint64_t successful_conn = 0, failed_conn = 0;
    
    for (int i = 0; i < 8; i++) {
        total_conn = (total_conn << 8) | data[i];
    }
    
    for (int i = 0; i < 8; i++) {
        current_conn = (current_conn << 8) | data[8 + i];
    }
    
    for (int i = 0; i < 8; i++) {
        total_bytes = (total_bytes << 8) | data[16 + i];
    }
    
    for (int i = 0; i < 8; i++) {
        successful_conn = (successful_conn << 8) | data[24 + i];
    }
    
    for (int i = 0; i < 8; i++) {
        failed_conn = (failed_conn << 8) | data[32 + i];
    }
    
    printf("Conexiones totales: %lu\n", total_conn);
    printf("Conexiones actuales: %lu\n", current_conn);
    printf("Bytes transferidos: %lu\n", total_bytes);
    printf("Conexiones exitosas: %lu\n", successful_conn);
    printf("Conexiones fallidas: %lu\n", failed_conn);

    printf("\n");
}

void handle_set_log_level(int sock, int level) {
    if (level < 0 || level > 3) {
        printf("\nNivel invalido. Valores permitidos: 0 (DEBUG), 1 (INFO), 2 (ERROR), 3 (FATAL)\n\n");
        return;
    }

    uint8_t data = (uint8_t)level;

    if (admin_client_send_command(sock, ADMIN_CMD_SET_LOG_LEVEL, &data, 1) < 0) return;

    uint8_t response_code;
    uint8_t response_data[1024];
    uint16_t response_len;

    if (admin_client_receive_response(sock, &response_code, response_data, &response_len) < 0) return;

    if (response_code == ADMIN_REP_SUCCESS) {
        printf("\nNivel de log cambiado exitosamente a %d\n\n", level);
    } else {
        printf("\nError cambiando nivel de log: codigo %d\n\n", response_code);
    }
}

void handle_set_max_connections(int sock, int max_conn) {
    if (max_conn < 1 || max_conn > 10000) {
        printf("\nCantidad invalida. Debe estar entre 1 y 10000.\n\n");
        return;
    }

    uint8_t data[4];
    data[0] = (max_conn >> 24) & 0xFF;
    data[1] = (max_conn >> 16) & 0xFF;
    data[2] = (max_conn >> 8) & 0xFF;
    data[3] = max_conn & 0xFF;

    if (admin_client_send_command(sock, ADMIN_CMD_SET_MAX_CONNECTIONS, data, 4) < 0) return;

    uint8_t response_code;
    uint8_t response_data[1024];
    uint16_t response_len;

    if (admin_client_receive_response(sock, &response_code, response_data, &response_len) < 0) return;

    if (response_code == ADMIN_REP_SUCCESS) {
        printf("\nMaximo de conexiones actualizado a %d\n\n", max_conn);
    } else {
        printf("\nError cambiando maximo de conexiones: codigo %d\n\n", response_code);
    }
}

// struct para comandos
typedef void (*command_handler)(int sock, const char *args);

typedef struct {
    const char *name;
    command_handler handler;
} command_entry;

void print_menu(void) {
    printf("\n=== COMANDOS DISPONIBLES ===\n");
    printf("help / menu               - Mostrar este menu\n");
    printf("list-users                - Listar usuarios\n");
    printf("add <user> <pass>         - Agregar usuario\n");
    printf("del <user>                - Eliminar usuario\n");
    printf("metrics                   - Ver metricas del sistema\n");
    printf("set-log <nivel>           - Cambiar nivel de log (1-4) [0-DEBUG 1-INFO 2-ERROR 3-FATAL]\n");
    printf("set-max <num>             - Cambiar max conexiones\n");
    printf("clear                     - Limpiar pantalla\n");
    printf("quit / exit               - Salir\n");
    printf("\n");
}

static void dispatch_help(int sock, const char *args) { 
    print_menu(); 
}

static void dispatch_quit(int sock, const char *args) {
    printf("\nSaliendo...\n\n");
    admin_client_send_command(sock, ADMIN_CMD_QUIT, NULL, 0);
    close(sock);
    exit(0);
}

static void dispatch_clear(int sock, const char *args) {
    printf("\033[2J\033[H");
}

static void dispatch_list_users(int sock, const char *args) {
    handle_list_users(sock);
}
static void dispatch_add_user(int sock, const char *args) {
    char user[64], pass[64];
    if (sscanf(args, "%63s %63s", user, pass) == 2) {
        handle_add_user(sock, user, pass);
    } else {
        printf("\nUso: add <user> <password>\n\n");
    }
}
static void dispatch_del_user(int sock, const char *args) {
    char user[64];
    if (sscanf(args, "%63s", user) == 1) {
        handle_del_user(sock, user);
    } else {
        printf("\nUso: del <usuario>\n\n");
    }
}
static void dispatch_set_log(int sock, const char *args) {
    int level;
    if (sscanf(args, "%d", &level) == 1 && level >= 0 && level <= 3) {
        handle_set_log_level(sock, level);
    } else {
        printf("\nUso: set-log <nivel> (0-3)\n\n");
    }
}
static void dispatch_set_max(int sock, const char *args) {
    int max;
    if (sscanf(args, "%d", &max) == 1 && max > 0) {
        handle_set_max_connections(sock, max);
    } else {
        printf("\nUso: set-max <num>\n\n");
    }
}
static void dispatch_metrics(int sock, const char *args) {
    handle_get_metrics(sock);
}

// tabla de comandos
static const command_entry commands[] = {
    {"help", dispatch_help},
    {"menu", dispatch_help},
    {"quit", dispatch_quit},
    {"exit", dispatch_quit},
    {"clear", dispatch_clear},
    {"list-users", dispatch_list_users},
    {"add", dispatch_add_user},
    {"del", dispatch_del_user},
    {"set-log", dispatch_set_log},
    {"set-max", dispatch_set_max},
    {"metrics", dispatch_metrics},
};

#define NUM_COMMANDS (sizeof(commands)/sizeof(commands[0]))

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Uso: %s <host> <puerto>\n", argv[0]);
        printf("Ejemplo: %s 127.0.0.1 8080\n", argv[0]);
        return 1;
    }

    const char *host = argv[1];
    int port = atoi(argv[2]);

    if (port <= 0 || port > 65535) {
        printf("Puerto invalido: %d\n", port);
        return 1;
    }

    printf("Conectando a %s:%d...\n", host, port);

    int sock = admin_client_connect(host, port);
    if (sock < 0) {
        return 1;
    }

    printf("Conectado exitosamente\n");

    if (admin_client_authenticate(sock, ADMIN_TOKEN) < 0) {
        close(sock);
        return 1;
    }

    printf("\nBienvenido al cliente de administraci\xC3\xB3n. Escriba 'menu' para ver los comandos.\n");

    char input[MAX_INPUT];

    while (1) {
        printf("> ");
        if (fgets(input, sizeof(input), stdin) == NULL) {
            printf("\nFin de la entrada detectado (Ctrl+D). Saliendo...\n");
            admin_client_send_command(sock, ADMIN_CMD_QUIT, NULL, 0);
            close(sock);
            return 0;
        }

        input[strcspn(input, "\n")] = 0;

        char cmd[64], args[MAX_INPUT];
        int matched = sscanf(input, "%63s %[^\n]", cmd, args);

        if (matched >= 1) {
            bool found = false;
            for (size_t i = 0; i < NUM_COMMANDS; i++) {
                if (strcmp(cmd, commands[i].name) == 0) {
                    commands[i].handler(sock, matched == 2 ? args : "");
                    found = true;
                    break;
                }
            }
            if (!found) {
                printf("Comando invalido. Escriba 'help' o 'menu' para ver opciones.\n");
            }
        }
    }

    close(sock);
    return 0;
}