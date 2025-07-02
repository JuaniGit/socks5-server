#define _POSIX_C_SOURCE 200112L
#include "connection.h"
#include "../shared/logger.h"
// #include "socks5_protocol.h"  // logica de handshake/request/connect
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
    int res = socks5_auth_negotiate(conn);
    if (res < 0) return ST_DONE;     // error, cerrar conexión
    if (res == 0) return ST_AUTH;    // sigue esperando más datos
    // res == 1 significa negociación OK
    return ST_REQUEST;
}

static unsigned on_request_read(struct selector_key *key) {
    // struct socks5_connection *conn = key->data;
    // if (socks5_process_request(conn) < 0) return ST_DONE;

    // // lanzar resolución async (ej: con hilo o pool)
    // start_resolve_async(conn);  // luego llamará a selector_notify_block()
    // return ST_RESOLVING;
}

static unsigned on_resolving_block(struct selector_key *key) {
    // struct socks5_connection *conn = key->data;
    // return ST_CONNECTING;
}

static unsigned on_connect_block(struct selector_key *key) {
    // struct socks5_connection *conn = key->data;

    // if (socks5_finish_connection(conn) < 0) return ST_DONE;

    // // registrar remote_fd si no lo estaba
    // selector_register(key->s, conn->remote_fd, &socks5_handler, OP_READ, conn);
    // return ST_STREAM;
}

static unsigned on_stream_read(struct selector_key *key) {
    // struct socks5_connection *conn = key->data;

    // int from = key->fd;
    // int to = (from == conn->client_fd) ? conn->remote_fd : conn->client_fd;

    // char buf[4096];
    // ssize_t n = recv(from, buf, sizeof(buf), 0);
    // if (n <= 0) return ST_DONE;

    // send(to, buf, n, 0);
    // return ST_STREAM;
}

static unsigned on_stream_write(struct selector_key *key) {
    // Si implementás buffering y control fino de escritura
    // return ST_STREAM;
}

static void on_done_arrival(unsigned state, struct selector_key *key) {
    // struct socks5_connection *conn = key->data;
    // selector_unregister_fd(key->s, conn->client_fd);
    // if (conn->remote_fd != -1) {
    //     selector_unregister_fd(key->s, conn->remote_fd);
    // }
}
