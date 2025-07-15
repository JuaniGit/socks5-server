#define _POSIX_C_SOURCE 200112L
#include "admin_protocol.h"
#include "../shared/users.h"
#include "../shared/metrics.h"
#include "admin_config.h"
#include "../shared/logger.h"
#include "../shared/util.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/time.h>

static unsigned on_admin_auth_read(struct selector_key *key);
static unsigned on_admin_command_read(struct selector_key *key);
static unsigned on_admin_response_write(struct selector_key *key);
static void on_admin_done_arrival(unsigned state, struct selector_key *key);

// Definición de estados
static const struct state_definition admin_states[] = {
    [ST_ADMIN_AUTH] = {
        .state = ST_ADMIN_AUTH,
        .on_read_ready = on_admin_auth_read,
    },
    [ST_ADMIN_COMMAND] = {
        .state = ST_ADMIN_COMMAND,
        .on_read_ready = on_admin_command_read,
    },
    [ST_ADMIN_RESPONSE] = {
        .state = ST_ADMIN_RESPONSE,
        .on_write_ready = on_admin_response_write,
    },
    [ST_ADMIN_DONE] = {
        .state = ST_ADMIN_DONE,
        .on_arrival = on_admin_done_arrival,
    }
};

// ========================================
// Funciones de creación y destrucción
// ========================================

struct admin_connection *admin_connection_new(int client_fd) {
    struct admin_connection *conn = calloc(1, sizeof(*conn));
    if (!conn) {
        log(ERROR, "%s", "Error alocando memoria para conexión admin");
        return NULL;
    }
    
    conn->client_fd = client_fd;
    conn->authenticated = false;
    conn->destroying = false;
    
    gettimeofday(&conn->start_time, NULL);
    
    uint8_t *read_buf_data = malloc(2048);
    uint8_t *write_buf_data = malloc(2048);
    
    if (!read_buf_data || !write_buf_data) {
        log(ERROR, "%s", "Error alocando memoria para buffers admin");
        free(read_buf_data);
        free(write_buf_data);
        free(conn);
        return NULL;
    }
    
    buffer_init(&conn->read_buf, 2048, read_buf_data);
    buffer_init(&conn->write_buf, 2048, write_buf_data);
    
    // máquina de estados
    conn->stm.initial = ST_ADMIN_AUTH;
    conn->stm.max_state = ST_ADMIN_DONE;
    conn->stm.states = admin_states;
    stm_init(&conn->stm);
    
    log(INFO, "Conexión admin creada exitosamente (fd=%d)", client_fd);
    return conn;
}

void admin_connection_destroy(struct admin_connection *conn) {
    if (!conn || conn->destroying) return;
    
    conn->destroying = true;
    log(INFO, "Destruyendo conexión admin (fd=%d)", conn->client_fd);
    
    if (conn->client_fd != -1) {
        close(conn->client_fd);
        conn->client_fd = -1;
    }
    
    if (conn->read_buf.data) {
        free(conn->read_buf.data);
        conn->read_buf.data = NULL;
    }
    if (conn->write_buf.data) {
        free(conn->write_buf.data);
        conn->write_buf.data = NULL;
    }
    
    free(conn);
    log(DEBUG, "%s", "Conexión admin destruida");
}

// ========================================
// Handlers para el selector
// ========================================

static void admin_read_handler(struct selector_key *key) {
    struct admin_connection *conn = key->data;
    if (conn->destroying) return;
    stm_handler_read_admin(&conn->stm, key);
}

static void admin_write_handler(struct selector_key *key) {
    struct admin_connection *conn = key->data;
    if (conn->destroying) return;
    stm_handler_write(&conn->stm, key);
}

static void admin_close_handler(struct selector_key *key) {
    struct admin_connection *conn = key->data;
    if (!conn || conn->destroying) return;
    
    log(INFO, "Cerrando conexión admin (fd=%d)", key->fd);
    admin_connection_destroy(conn);
    key->data = NULL;
}

const struct fd_handler admin_handler = {
    .handle_read = admin_read_handler,
    .handle_write = admin_write_handler,
    .handle_block = NULL,
    .handle_close = admin_close_handler,
};

// ========================================
// Funciones de estado
// ========================================

static unsigned on_admin_auth_read(struct selector_key *key) {
    struct admin_connection *conn = key->data;
    if (conn->destroying) return ST_ADMIN_DONE;
    
    selector_set_interest_key(key, OP_READ);
    buffer *b = &conn->read_buf;
    
    size_t space;
    uint8_t *ptr = buffer_write_ptr(b, &space);
    
    ssize_t n = recv(key->fd, ptr, space, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return ST_ADMIN_AUTH;
        }
        log(ERROR, "Error en recv() admin auth: %s", strerror(errno));
        return ST_ADMIN_DONE;
    } else if (n == 0) {
        log(INFO, "%s", "Conexión cerrada por cliente admin durante auth");
        return ST_ADMIN_DONE;
    }
    
    buffer_write_adv(b, n);
    
    int result = admin_process_auth(conn);
    if (result < 0) {
        log(INFO, "%s", "Autenticación admin fallida");
        return ST_ADMIN_DONE;
    }
    if (result == 0) {
        return ST_ADMIN_AUTH; 
    }
    
    log(INFO, "Cliente admin autenticado exitosamente desde %s", conn->client_address);
    log(DEBUG, "%s", "Transición: ST_ADMIN_AUTH -> ST_ADMIN_COMMAND");
    return ST_ADMIN_COMMAND;
}

static unsigned on_admin_command_read(struct selector_key *key) {
    struct admin_connection *conn = key->data;
    if (conn->destroying) return ST_ADMIN_DONE;
    
    log(DEBUG, "%s", "Procesando comando en estado ST_ADMIN_COMMAND");
    
    selector_set_interest_key(key, OP_READ);
    buffer *b = &conn->read_buf;
    
    size_t space;
    uint8_t *ptr = buffer_write_ptr(b, &space);
    
    ssize_t n = recv(key->fd, ptr, space, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return ST_ADMIN_COMMAND;
        }
        log(ERROR, "Error en recv() admin command: %s", strerror(errno));
        return ST_ADMIN_DONE;
    } else if (n == 0) {
        log(INFO, "%s", "Conexión cerrada por cliente admin durante command");
        return ST_ADMIN_DONE;
    }
    
    buffer_write_adv(b, n);
    
    int result = admin_process_command(conn);
    if (result < 0) {
        log(ERROR, "%s", "Error procesando comando admin");
        return ST_ADMIN_DONE;
    }
    if (result == 0) {
        return ST_ADMIN_COMMAND;
    }
    
    return ST_ADMIN_COMMAND;
}

static unsigned on_admin_response_write(struct selector_key *key) {
    struct admin_connection *conn = key->data;
    if (conn->destroying) return ST_ADMIN_DONE;
    
    selector_set_interest_key(key, OP_WRITE);
    buffer *b = &conn->write_buf;
    
    size_t available;
    uint8_t *data = buffer_read_ptr(b, &available);
    
    if (available == 0) {
        selector_set_interest_key(key, OP_READ);
        return ST_ADMIN_COMMAND;
    }
    
    ssize_t sent = send(key->fd, data, available, MSG_NOSIGNAL);
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return ST_ADMIN_RESPONSE;
        }
        log(ERROR, "Error en send() admin response: %s", strerror(errno));
        return ST_ADMIN_DONE;
    }
    
    buffer_read_adv(b, sent);
    
    buffer_read_ptr(b, &available);
    if (available == 0) {
        selector_set_interest_key(key, OP_READ);
        return ST_ADMIN_COMMAND;
    }
    
    return ST_ADMIN_RESPONSE;
}

static void on_admin_done_arrival(unsigned state, struct selector_key *key) {
    struct admin_connection *conn = key->data;
    log(DEBUG, "%s", "Entrando en estado ADMIN_DONE");
    
    selector_unregister_fd(key->s, conn->client_fd);
    
    // La destrucción la maneja el close_handler
}

// ========================================
// Funciones de procesamiento
// ========================================

int admin_process_auth(struct admin_connection *conn) {
    buffer *b = &conn->read_buf;
    size_t available;
    uint8_t *ptr = buffer_read_ptr(b, &available);
    
    // Necesitamos al menos VER + ALEN
    if (available < 2) {
        return 0;
    }
    
    uint8_t version = ptr[0];
    uint8_t token_len = ptr[1];
    
    if (version != ADMIN_VERSION) {
        log(ERROR, "Versión admin inválida: %d", version);
        admin_send_response(conn, ADMIN_REP_AUTH_FAILURE, NULL, 0);
        return -1;
    }
    
    if (available < 2 + token_len) {
        return 0;
    }
    
    char token[256];
    memcpy(token, ptr + 2, token_len);
    token[token_len] = '\0';
    
    if (strcmp(token, ADMIN_TOKEN) != 0) {
        log(ERROR, "Token admin inválido: %s", token);
        admin_send_response(conn, ADMIN_REP_AUTH_FAILURE, NULL, 0);
        return -1;
    }
    
    buffer_read_adv(b, 2 + token_len);
    
    conn->authenticated = true;
    admin_send_response(conn, ADMIN_REP_SUCCESS, NULL, 0);
    
    log(INFO, "%s", "Cliente admin autenticado exitosamente");
    return 1;
}

int admin_process_command(struct admin_connection *conn) {
    if (!conn->authenticated) {
        log(ERROR, "%s", "Cliente admin no autenticado intentando ejecutar comando");
        admin_send_response(conn, ADMIN_REP_AUTH_FAILURE, NULL, 0);
        return -1;
    }
    
    buffer *b = &conn->read_buf;
    size_t available;
    uint8_t *ptr = buffer_read_ptr(b, &available);
    
    // Necesitamos al menos VER + CMD
    if (available < 2) {
        return 0;
    }
    
    uint8_t version = ptr[0];
    uint8_t command = ptr[1];
    
    if (version != ADMIN_VERSION) {
        log(ERROR, "Versión admin inválida en comando: %d", version);
        admin_send_response(conn, ADMIN_REP_GENERAL_FAILURE, NULL, 0);
        return -1;
    }
    
    uint16_t data_len = 0;
    uint8_t *data_ptr = NULL;
    
    if (command == ADMIN_CMD_ADD_USER || command == ADMIN_CMD_DEL_USER || 
        command == ADMIN_CMD_SET_LOG_LEVEL || command == ADMIN_CMD_SET_MAX_CONNECTIONS ||
        command == ADMIN_CMD_SET_BUFFER_SIZE || command == ADMIN_CMD_SET_TIMEOUT) {
        
        if (available < 4) {
            return 0;
        }
        
        data_len = (ptr[2] << 8) | ptr[3];
        
        if (available < 4 + data_len) {
            return 0;
        }
        
        data_ptr = ptr + 4;
    }
    
    int result = 0;
    switch (command) {
        case ADMIN_CMD_LIST_USERS:
            result = admin_handle_list_users(conn);
            break;
        case ADMIN_CMD_ADD_USER:
            result = admin_handle_add_user(conn, data_ptr, data_len);
            break;
        case ADMIN_CMD_DEL_USER:
            result = admin_handle_del_user(conn, data_ptr, data_len);
            break;
        case ADMIN_CMD_GET_METRICS:
            result = admin_handle_get_metrics(conn);
            break;
        case ADMIN_CMD_SET_LOG_LEVEL:
            result = admin_handle_set_log_level(conn, data_ptr, data_len);
            break;
        case ADMIN_CMD_SET_MAX_CONNECTIONS:
            result = admin_handle_set_max_connections(conn, data_ptr, data_len);
            break;
        case ADMIN_CMD_QUIT:
            log(INFO, "%s", "Cliente admin solicitó desconexión");
            admin_send_response(conn, ADMIN_REP_SUCCESS, NULL, 0);
            return -1; 
        default:
            log(ERROR, "Comando admin no soportado: %d", command);
            admin_send_response(conn, ADMIN_REP_COMMAND_NOT_SUPPORTED, NULL, 0);
            result = -1;
            break;
    }
    
    buffer_read_adv(b, 2 + (data_len > 0 ? 2 + data_len : 0));
    
    return result;
}

int admin_send_response(struct admin_connection *conn, uint8_t response_code, 
                       const uint8_t *data, uint16_t data_len) {
    
    uint8_t response[1024];
    uint16_t offset = 0;
    
    response[offset++] = ADMIN_VERSION;
    response[offset++] = response_code;
    
    if (data_len > 0 && data) {
        response[offset++] = (data_len >> 8) & 0xFF;
        response[offset++] = data_len & 0xFF;
        memcpy(response + offset, data, data_len);
        offset += data_len;
    }
    
    ssize_t sent = send(conn->client_fd, response, offset, MSG_NOSIGNAL);
    if (sent != offset) {
        log(ERROR, "Error enviando respuesta admin: %s", strerror(errno));
        return -1;
    }
    
    log(DEBUG, "Respuesta admin enviada: código=%d, data_len=%d, bytes_sent=%zd", 
        response_code, data_len, sent);
    return 0;
}

// ========================================
// Handlers de comandos específicos
// ========================================

int admin_handle_list_users(struct admin_connection *conn) {
    log(INFO, "%s", "Ejecutando comando LIST_USERS");
    
    struct user_credentials users[MAX_USERS];
    size_t count = users_list(users, MAX_USERS);
    
    uint8_t response_data[1024];
    uint16_t offset = 0;
    
    response_data[offset++] = (count >> 8) & 0xFF;
    response_data[offset++] = count & 0xFF;
    
    for (size_t i = 0; i < count && offset < sizeof(response_data) - 256; i++) {
        uint8_t username_len = strlen(users[i].username);
        response_data[offset++] = username_len;
        memcpy(response_data + offset, users[i].username, username_len);
        offset += username_len;
        response_data[offset++] = users[i].active ? 1 : 0;
    }
    
    return admin_send_response(conn, ADMIN_REP_SUCCESS, response_data, offset);
}

int admin_handle_add_user(struct admin_connection *conn, const uint8_t *data, uint16_t len) {
    log(INFO, "%s", "Ejecutando comando ADD_USER");
    
    if (len < 2) {
        log(ERROR, "%s", "Datos insuficientes para ADD_USER");
        return admin_send_response(conn, ADMIN_REP_INVALID_ARGS, NULL, 0);
    }
    
    uint8_t username_len = data[0];
    if (len < 1 + username_len + 1) {
        log(ERROR, "%s", "Datos insuficientes para ADD_USER");
        return admin_send_response(conn, ADMIN_REP_INVALID_ARGS, NULL, 0);
    }
    
    uint8_t password_len = data[1 + username_len];
    if (len < 1 + username_len + 1 + password_len) {
        log(ERROR, "%s", "Datos insuficientes para ADD_USER");
        return admin_send_response(conn, ADMIN_REP_INVALID_ARGS, NULL, 0);
    }
    
    char username[256], password[256];
    memcpy(username, data + 1, username_len);
    username[username_len] = '\0';
    memcpy(password, data + 1 + username_len + 1, password_len);
    password[password_len] = '\0';
    
    bool success = users_add(username, password);
    
    if (success) {
        log(INFO, "Usuario '%s' agregado exitosamente por admin", username);
        return admin_send_response(conn, ADMIN_REP_SUCCESS, NULL, 0);
    } else {
        log(ERROR, "Error agregando usuario '%s'", username);
        return admin_send_response(conn, ADMIN_REP_GENERAL_FAILURE, NULL, 0);
    }
}

int admin_handle_del_user(struct admin_connection *conn, const uint8_t *data, uint16_t len) {
    log(INFO, "%s", "Ejecutando comando DEL_USER");
    
    if (len < 1) {
        log(ERROR, "%s", "Datos insuficientes para DEL_USER");
        return admin_send_response(conn, ADMIN_REP_INVALID_ARGS, NULL, 0);
    }
    
    uint8_t username_len = data[0];
    if (len < 1 + username_len) {
        log(ERROR, "%s", "Datos insuficientes para DEL_USER");
        return admin_send_response(conn, ADMIN_REP_INVALID_ARGS, NULL, 0);
    }
    
    char username[256];
    memcpy(username, data + 1, username_len);
    username[username_len] = '\0';
    
    bool success = users_remove(username);
    
    if (success) {
        log(INFO, "Usuario '%s' eliminado exitosamente por admin", username);
        return admin_send_response(conn, ADMIN_REP_SUCCESS, NULL, 0);
    } else {
        log(ERROR, "Error eliminando usuario '%s'", username);
        return admin_send_response(conn, ADMIN_REP_GENERAL_FAILURE, NULL, 0);
    }
}

int admin_handle_get_metrics(struct admin_connection *conn) {
    log(INFO, "%s", "Ejecutando comando GET_METRICS");
    
    struct socks5_metrics metrics = metrics_get_snapshot();
    
    uint8_t response_data[512];
    uint16_t offset = 0;
    
    uint64_t total_conn = metrics.connections.total_connections;
    for (int i = 7; i >= 0; i--) {
        response_data[offset++] = (total_conn >> (i * 8)) & 0xFF;
    }
    
    uint64_t current_conn = metrics.connections.current_connections;
    for (int i = 7; i >= 0; i--) {
        response_data[offset++] = (current_conn >> (i * 8)) & 0xFF;
    }
    
    uint64_t total_bytes = metrics.transfers.total_bytes_transferred;
    for (int i = 7; i >= 0; i--) {
        response_data[offset++] = (total_bytes >> (i * 8)) & 0xFF;
    }
    
    uint64_t successful_conn = metrics.connections.successful_connections;
    for (int i = 7; i >= 0; i--) {
        response_data[offset++] = (successful_conn >> (i * 8)) & 0xFF;
    }
    
    uint64_t failed_conn = metrics.connections.failed_connections;
    for (int i = 7; i >= 0; i--) {
        response_data[offset++] = (failed_conn >> (i * 8)) & 0xFF;
    }
    
    return admin_send_response(conn, ADMIN_REP_SUCCESS, response_data, offset);
}

int admin_handle_set_log_level(struct admin_connection *conn, const uint8_t *data, uint16_t len) {
    log(INFO, "%s", "Ejecutando comando SET_LOG_LEVEL");
    
    if (len < 1) {
        log(ERROR, "%s", "Datos insuficientes para SET_LOG_LEVEL");
        return admin_send_response(conn, ADMIN_REP_INVALID_ARGS, NULL, 0);
    }
    
    uint8_t level = data[0];
    
    if (level > FATAL) {
        log(ERROR, "Nivel de log inválido: %d", level);
        return admin_send_response(conn, ADMIN_REP_INVALID_ARGS, NULL, 0);
    }
    
    LOG_LEVEL old_level = current_level;
    setLogLevel((LOG_LEVEL)level);
    
    log(INFO, "Nivel de log cambiado de %d a %d por admin", old_level, level);
    return admin_send_response(conn, ADMIN_REP_SUCCESS, NULL, 0);
}

int admin_handle_set_max_connections(struct admin_connection *conn, const uint8_t *data, uint16_t len) {
    log(INFO, "%s", "Ejecutando comando SET_MAX_CONNECTIONS");
    
    if (len < 4) {
        log(ERROR, "%s", "Datos insuficientes para SET_MAX_CONNECTIONS");
        return admin_send_response(conn, ADMIN_REP_INVALID_ARGS, NULL, 0);
    }
    
    uint32_t max_conn = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    
    if (max_conn < 1 || max_conn > 500) {
        log(ERROR, "Valor inválido para máximo de conexiones: %u", max_conn);
        return admin_send_response(conn, ADMIN_REP_INVALID_ARGS, NULL, 0);
    }
    
    admin_config_set_max_connections(max_conn);
    
    log(INFO, "Máximo de conexiones cambiado a %u por admin", max_conn);
    return admin_send_response(conn, ADMIN_REP_SUCCESS, NULL, 0);
}