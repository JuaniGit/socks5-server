#ifndef ADMIN_PROTOCOL_H
#define ADMIN_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/time.h>
#include "../selector.h"
#include "../stm.h"
#include "../buffer.h"

// Constantes del protocolo
#define ADMIN_VERSION 0x01
#define ADMIN_TOKEN "admin123"  // Token simple para autenticación
#define ADMIN_PORT 8080

// Estados del protocolo
enum admin_state {
    ST_ADMIN_AUTH = 0,
    ST_ADMIN_COMMAND,
    ST_ADMIN_RESPONSE,
    ST_ADMIN_DONE,
};

// Códigos de comando
enum admin_command {
    ADMIN_CMD_LIST_USERS = 0x01,
    ADMIN_CMD_ADD_USER = 0x02,
    ADMIN_CMD_DEL_USER = 0x03,
    ADMIN_CMD_GET_METRICS = 0x04,
    ADMIN_CMD_SET_LOG_LEVEL = 0x05,
    ADMIN_CMD_SET_MAX_CONNECTIONS = 0x06,
    ADMIN_CMD_SET_BUFFER_SIZE = 0x07,
    ADMIN_CMD_SET_TIMEOUT = 0x08,
    ADMIN_CMD_QUIT = 0xFF,
};

// Códigos de respuesta
enum admin_response {
    ADMIN_REP_SUCCESS = 0x00,
    ADMIN_REP_GENERAL_FAILURE = 0x01,
    ADMIN_REP_AUTH_FAILURE = 0x02,
    ADMIN_REP_COMMAND_NOT_SUPPORTED = 0x03,
    ADMIN_REP_INVALID_ARGS = 0x04,
};

// Estructura para comandos con datos
struct admin_command_data {
    uint8_t command;
    uint16_t data_length;
    uint8_t data[512];  // Buffer para datos del comando
};

// Estructura para respuestas con datos
struct admin_response_data {
    uint8_t response;
    uint16_t data_length;
    uint8_t data[1024];  // Buffer para datos de respuesta
};

// Estructura de conexión de administración
struct admin_connection {
    int client_fd;
    bool authenticated;
    bool destroying;
    
    // Máquina de estados
    struct state_machine stm;
    
    // Buffers
    buffer read_buf;
    buffer write_buf;
    
    // Comando actual
    struct admin_command_data current_cmd;
    struct admin_response_data current_resp;
    
    // Timestamp para logging
    struct timeval start_time;
    
    // Dirección del cliente
    char client_address[128];
};

// Funciones principales
struct admin_connection *admin_connection_new(int client_fd);
void admin_connection_destroy(struct admin_connection *conn);

// Handler para el selector
extern const struct fd_handler admin_handler;

// Funciones de procesamiento
int admin_process_auth(struct admin_connection *conn);
int admin_process_command(struct admin_connection *conn);
int admin_send_response(struct admin_connection *conn, uint8_t response_code, 
                       const uint8_t *data, uint16_t data_len);

// Funciones de comandos específicos
int admin_handle_list_users(struct admin_connection *conn);
int admin_handle_add_user(struct admin_connection *conn, const uint8_t *data, uint16_t len);
int admin_handle_del_user(struct admin_connection *conn, const uint8_t *data, uint16_t len);
int admin_handle_get_metrics(struct admin_connection *conn);
int admin_handle_set_log_level(struct admin_connection *conn, const uint8_t *data, uint16_t len);
int admin_handle_set_max_connections(struct admin_connection *conn, const uint8_t *data, uint16_t len);
int admin_handle_set_buffer_size(struct admin_connection *conn, const uint8_t *data, uint16_t len);
int admin_handle_set_timeout(struct admin_connection *conn, const uint8_t *data, uint16_t len);

#endif
