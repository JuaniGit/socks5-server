#define _POSIX_C_SOURCE 200112L
#include "connection.h"
#include "../shared/logger.h"
// #include "socks5_protocol.h"  // logica de handshake/request/connect
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "socks5.h"

// Prototipos de funciones por estado
static unsigned on_auth_read(struct selector_key *key);
static unsigned on_request_read(struct selector_key *key);
static unsigned on_resolving_block(struct selector_key *key);
static unsigned on_connect_block(struct selector_key *key);
static unsigned on_stream_read(struct selector_key *key);
static unsigned on_stream_write(struct selector_key *key);
static void     on_done_arrival(unsigned state, struct selector_key *key);

// =====================
// Definición de estados
// =====================
static const struct state_definition socks5_states[] = {
    [ST_AUTH] = {
        .state = ST_AUTH,
        .on_read_ready = on_auth_read,
    },
    [ST_REQUEST] = {
        .state = ST_REQUEST,
        .on_read_ready = on_request_read,
    },
    [ST_RESOLVING] = {
        .state = ST_RESOLVING,
        .on_block_ready = on_resolving_block,
    },
    [ST_CONNECTING] = {
        .state = ST_CONNECTING,
        .on_block_ready = on_connect_block,
    },
    [ST_STREAM] = {
        .state = ST_STREAM,
        .on_read_ready = on_stream_read,
        .on_write_ready = on_stream_write,
    },
    [ST_DONE] = {
        .state = ST_DONE,
        .on_arrival = on_done_arrival,
    }
};

// ==============================
// Creación y destrucción
// ==============================

struct socks5_connection *socks5_connection_new(int client_fd) {
    struct socks5_connection *conn = calloc(1, sizeof(*conn));
    if (!conn) return NULL;

    conn->client_fd = client_fd;
    conn->remote_fd = -1;
    buffer_init(&conn->read_buf_client, 4096, malloc(4096));
    buffer_init(&conn->write_buf_client, 4096, malloc(4096));
    buffer_init(&conn->read_buf_remote, 4096, malloc(4096));
    buffer_init(&conn->write_buf_remote, 4096, malloc(4096));
    
    conn->stm.initial = ST_AUTH;
    conn->stm.max_state = ST_DONE;
    conn->stm.states = socks5_states;
    stm_init(&conn->stm);
    
    return conn;
}

void socks5_connection_destroy(struct socks5_connection *conn) {
    if (!conn) return;

    if (conn->client_fd != -1) close(conn->client_fd);
    if (conn->remote_fd != -1) close(conn->remote_fd);

    if (conn->addr_list) freeaddrinfo(conn->addr_list);

    free(conn->read_buf_client.data);
    free(conn->write_buf_client.data);
    free(conn->read_buf_remote.data);
    free(conn->write_buf_remote.data);

    free(conn);
}

// ==============================
// fd_handler para el selector
// ==============================

static void socks5_read_handler(struct selector_key *key) {
    struct socks5_connection *conn = key->data;
    stm_handler_read(&conn->stm, key);
}

static void socks5_write_handler(struct selector_key *key) {
    struct socks5_connection *conn = key->data;
    stm_handler_write(&conn->stm, key);
}

static void socks5_block_handler(struct selector_key *key) {
    struct socks5_connection *conn = key->data;
    stm_handler_block(&conn->stm, key);
}

static void socks5_close_handler(struct selector_key *key) {
    struct socks5_connection *conn = key->data;
    stm_handler_close(&conn->stm, key);
    socks5_connection_destroy(conn);
}

const struct fd_handler socks5_handler = {
    .handle_read = socks5_read_handler,
    .handle_write = socks5_write_handler,
    .handle_block = socks5_block_handler,
    .handle_close = socks5_close_handler,
};

// ==============================
// Callbacks de estado
// ==============================

static unsigned on_auth_read(struct selector_key *key) {
    struct socks5_connection *conn = key->data;
    selector_set_interest_key(key, OP_READ);
    buffer *b = &conn->read_buf_client;

    size_t space;
    uint8_t *ptr = buffer_write_ptr(b, &space);

    ssize_t n = recv(key->fd, ptr, space, 0);
    if (n < 0) {
        log(ERROR, "recv() falló");
        return ST_DONE;
    } else if (n == 0) {
        log(INFO, "Conexión cerrada por el cliente");
        return ST_DONE;
    }

    buffer_write_adv(b, n);  // avanzar el cursor de escritura

    int res = socks5_auth_negotiate(conn);
    log(INFO, "res = %d", res);
    if (res < 0) return ST_DONE;     // error, cerrar conexión
    if (res == 0) return ST_AUTH;    // sigue esperando más datos
    // res == 1 significa negociación OK
    log(INFO, "DONE AUTH READ");
    return ST_REQUEST;
}

static unsigned on_request_read(struct selector_key *key) {
    struct socks5_connection *conn = key->data;
    selector_set_interest_key(key, OP_READ);
    
    buffer *b = &conn->read_buf_client;
    size_t available;
    buffer_read_ptr(b, &available);
    
    // If no data available, try to read more
    if (available == 0) {
        size_t space;
        uint8_t *ptr = buffer_write_ptr(b, &space);
        
        ssize_t n = recv(key->fd, ptr, space, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return ST_REQUEST; // No data available, stay in same state
            }
            log(ERROR, "recv() falló en request: %s", strerror(errno));
            return ST_DONE;
        } else if (n == 0) {
            log(INFO, "Conexión cerrada por el cliente durante request");
            return ST_DONE;
        }
        
        buffer_write_adv(b, n);
    }
    
    log(DEBUG, "Procesando request SOCKS5");
    int res = socks5_process_request(conn);

    if (res < 0) return ST_DONE;     // error, cerrar conexión
    if (res == 0) return ST_REQUEST; // sigue esperando más datos
    
    log(INFO, "Request procesado exitosamente, conectando a %s:%d", conn->target_host, conn->target_port);
    
    // Conectar directamente aquí en lugar de cambiar de estado
    if (socks5_finish_connection(conn) < 0) {
        log(ERROR, "Error conectando al servidor remoto");
        socks5_send_request_response(conn, SOCKS5_REP_HOST_UNREACHABLE);
        return ST_DONE;
    }

    // Enviar respuesta exitosa al cliente
    if (socks5_send_request_response(conn, SOCKS5_REP_SUCCESS) < 0) {
        log(ERROR, "Error enviando respuesta de éxito");
        return ST_DONE;
    }

    // Registrar el fd remoto en el selector
    selector_status s = selector_register(key->s, conn->remote_fd, &socks5_handler, OP_READ, conn);
    if (s != SELECTOR_SUCCESS) {
        log(ERROR, "Error registrando fd remoto: %s", selector_error(s));
        return ST_DONE;
    }

    log(INFO, "Conexión establecida exitosamente con %s:%d", conn->target_host, conn->target_port);
    return ST_STREAM;
}

static unsigned on_resolving_block(struct selector_key *key) {
    // struct socks5_connection *conn = key->data;
    // return ST_CONNECTING;
}

static unsigned on_connect_block(struct selector_key *key) {
    // Esta función ya no se usa, la conexión se hace directamente en on_request_read
    return ST_STREAM;
}

static unsigned on_stream_read(struct selector_key *key) {
    struct socks5_connection *conn = key->data;
    
    int from_fd = key->fd;
    int to_fd;
    buffer *from_buf, *to_buf;
    
    // Determinar dirección del flujo de datos
    if (from_fd == conn->client_fd) {
        // Cliente -> Servidor remoto
        to_fd = conn->remote_fd;
        from_buf = &conn->read_buf_client;
        to_buf = &conn->write_buf_remote;
    } else {
        // Servidor remoto -> Cliente
        to_fd = conn->client_fd;
        from_buf = &conn->read_buf_remote;
        to_buf = &conn->write_buf_client;
    }
    
    // Leer datos del socket origen
    size_t space;
    uint8_t *ptr = buffer_write_ptr(from_buf, &space);
    
    if (space == 0) {
        // Buffer lleno, pausar lectura y activar escritura
        selector_set_interest_key(key, OP_NOOP);
        selector_set_interest(key->s, to_fd, OP_WRITE);
        return ST_STREAM;
    }
    
    ssize_t n = recv(from_fd, ptr, space, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return ST_STREAM; // No hay datos disponibles
        }
        log(ERROR, "Error en recv(): %s", strerror(errno));
        return ST_DONE;
    } else if (n == 0) {
        // Conexión cerrada por el peer
        log(INFO, "Conexión cerrada por %s", (from_fd == conn->client_fd) ? "cliente" : "servidor remoto");
        return ST_DONE;
    }
    
    buffer_write_adv(from_buf, n);
    
    // Intentar escribir inmediatamente al destino
    size_t available;
    uint8_t *data = buffer_read_ptr(from_buf, &available);
    
    if (available > 0) {
        ssize_t sent = send(to_fd, data, available, MSG_NOSIGNAL);
        if (sent > 0) {
            buffer_read_adv(from_buf, sent);
            // Actualizar estadísticas
            // TODO: agregar contador de bytes transferidos
        } else if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            log(ERROR, "Error en send(): %s", strerror(errno));
            return ST_DONE;
        }
        
        // Si no se pudo enviar todo, activar escritura en destino
        buffer_read_ptr(from_buf, &available);
        if (available > 0) {
            selector_set_interest(key->s, to_fd, OP_READ | OP_WRITE);
        }
    }
    
    return ST_STREAM;
}

static unsigned on_stream_write(struct selector_key *key) {
    struct socks5_connection *conn = key->data;
    
    int to_fd = key->fd;
    buffer *buf;
    int from_fd;
    
    // Determinar qué buffer usar
    if (to_fd == conn->client_fd) {
        buf = &conn->write_buf_client;
        from_fd = conn->remote_fd;
    } else {
        buf = &conn->write_buf_remote;
        from_fd = conn->client_fd;
    }
    
    // Escribir datos pendientes
    size_t available;
    uint8_t *data = buffer_read_ptr(buf, &available);
    
    if (available == 0) {
        // No hay datos para escribir, desactivar escritura
        selector_set_interest_key(key, OP_READ);
        return ST_STREAM;
    }
    
    ssize_t sent = send(to_fd, data, available, MSG_NOSIGNAL);
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return ST_STREAM; // Socket no listo para escritura
        }
        log(ERROR, "Error en send(): %s", strerror(errno));
        return ST_DONE;
    }
    
    buffer_read_adv(buf, sent);
    
    // Verificar si se escribió todo
    buffer_read_ptr(buf, &available);
    if (available == 0) {
        // Buffer vacío, reactivar lectura del origen
        selector_set_interest_key(key, OP_READ);
        selector_set_interest(key->s, from_fd, OP_READ);
    }
    
    return ST_STREAM;
}

static void on_done_arrival(unsigned state, struct selector_key *key) {
    struct socks5_connection *conn = key->data;
    selector_unregister_fd(key->s, conn->client_fd);
    if (conn->remote_fd != -1) {
        selector_unregister_fd(key->s, conn->remote_fd);
    }
}
