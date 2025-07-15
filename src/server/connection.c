#define _POSIX_C_SOURCE 200112L
#include "connection.h"
#include "../shared/logger.h"
#include "../shared/access_logger.h"
#include "../shared/util.h"
#include "socks5.h"
#include "../shared/metrics.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 65536

// Prototipos de funciones por estado
static unsigned on_auth_read(struct selector_key *key);
static unsigned on_auth_userpass_read(struct selector_key *key);
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
    [ST_AUTH_USERPASS] = {
        .state = ST_AUTH_USERPASS,
        .on_read_ready = on_auth_userpass_read,
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
// Funciones auxiliares
// ==============================

static double get_time_diff_ms(struct timeval *start, struct timeval *end) {
    return (end->tv_sec - start->tv_sec) * 1000.0 + (end->tv_usec - start->tv_usec) / 1000.0;
}

// ==============================
// Creación y destrucción
// ==============================

struct socks5_connection *socks5_connection_new(int client_fd, const struct sockaddr *client_addr) {
    struct socks5_connection *conn = calloc(1, sizeof(*conn));
    if (!conn) {
        log(ERROR, "%s", "Error alocando memoria para conexión SOCKS5");
        return NULL;
    }

    conn->client_fd = client_fd;
    conn->remote_fd = -1;
    conn->dns_job = NULL;
    conn->client_closed = false;
    conn->remote_closed = false;
    conn->destroying = false;
    
    gettimeofday(&conn->start_time, NULL);

    // Guardar IP y puerto del cliente
    if (client_addr->sa_family == AF_INET) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)client_addr;
        inet_ntop(AF_INET, &(ipv4->sin_addr), conn->client_ip, sizeof(conn->client_ip));
        conn->client_port = ntohs(ipv4->sin_port);
    } else if (client_addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)client_addr;
        inet_ntop(AF_INET6, &(ipv6->sin6_addr), conn->client_ip, sizeof(conn->client_ip));
        conn->client_port = ntohs(ipv6->sin6_port);
    } else {
        strncpy(conn->client_ip, "UNKNOWN", sizeof(conn->client_ip));
        conn->client_port = 0;
    }
    conn->socks5_reply_code = SOCKS5_REP_GENERAL_FAILURE;
    
    uint8_t *read_client_buf = malloc(BUFFER_SIZE);
    uint8_t *write_client_buf = malloc(BUFFER_SIZE);
    uint8_t *read_remote_buf = malloc(BUFFER_SIZE);
    uint8_t *write_remote_buf = malloc(BUFFER_SIZE);
    
    if (!read_client_buf || !write_client_buf || !read_remote_buf || !write_remote_buf) {
        log(ERROR, "%s", "Error alocando memoria para buffers");
        free(read_client_buf);
        free(write_client_buf);
        free(read_remote_buf);
        free(write_remote_buf);
        free(conn);
        return NULL;
    }
    
    buffer_init(&conn->read_buf_client, BUFFER_SIZE, read_client_buf);
    buffer_init(&conn->write_buf_client, BUFFER_SIZE, write_client_buf);
    buffer_init(&conn->read_buf_remote, BUFFER_SIZE, read_remote_buf);
    buffer_init(&conn->write_buf_remote, BUFFER_SIZE, write_remote_buf);
    
    log(DEBUG, "%s", "Inicializando parser híbrido de autenticación usuario/contraseña");

    struct parser_definition *userpass_def = userpass_parser_definition();

    if (!userpass_def || userpass_def->states_count == 0 || !userpass_def->states || !userpass_def->states_n) {
        log(ERROR, "%s", "Definición de parser inválida");
        socks5_connection_destroy(conn);
        return NULL;
    }

    conn->userpass_parser = parser_init(parser_no_classes(), userpass_def);
    if (!conn->userpass_parser) {
        log(ERROR, "%s", "Error inicializando parser híbrido de autenticación usuario/contraseña");
        socks5_connection_destroy(conn);
        return NULL;
    }
    
    userpass_parser_data_init(&conn->userpass_data);
    log(DEBUG, "%s", "Parser híbrido inicializado correctamente");
    
    conn->stm.initial = ST_AUTH;
    conn->stm.max_state = ST_DONE;
    conn->stm.states = socks5_states;
    stm_init(&conn->stm);
    
    log(DEBUG, "Conexión SOCKS5 creada exitosamente (client_fd=%d)", client_fd);
    return conn;
}

void socks5_connection_destroy(struct socks5_connection *conn) {
    if (!conn || conn->destroying) return;
    
    conn->destroying = true;
    log(DEBUG, "Destruyendo conexión SOCKS5 (client_fd=%d, remote_fd=%d)", conn->client_fd, conn->remote_fd);

    struct timeval end_time;
    gettimeofday(&end_time, NULL);
    double connection_time_ms = get_time_diff_ms(&conn->start_time, &end_time);
    
    bool successful = conn->authenticated && (conn->remote_fd != -1);
    metrics_connection_ended(successful, connection_time_ms);

    // Cerrar file descriptors solo si no están cerrados
    if (conn->client_fd != -1) {
        close(conn->client_fd);
        conn->client_fd = -1;
    }
    if (conn->remote_fd != -1) {
        close(conn->remote_fd);
        conn->remote_fd = -1;
    }

    if (conn->addr_list) {
        freeaddrinfo(conn->addr_list);
        conn->addr_list = NULL;
    }
    
    if (conn->dns_job) {
        if (conn->dns_job->result && conn->dns_job->result != conn->addr_list) {
            freeaddrinfo(conn->dns_job->result);
        }
        free(conn->dns_job);
        conn->dns_job = NULL;
    }

    if (conn->userpass_parser) {
        log(DEBUG, "%s", "Destruyendo parser híbrido");
        parser_destroy(conn->userpass_parser);
        conn->userpass_parser = NULL;
    }

    if (conn->read_buf_client.data) {
        free(conn->read_buf_client.data);
        conn->read_buf_client.data = NULL;
    }
    if (conn->write_buf_client.data) {
        free(conn->write_buf_client.data);
        conn->write_buf_client.data = NULL;
    }
    if (conn->read_buf_remote.data) {
        free(conn->read_buf_remote.data);
        conn->read_buf_remote.data = NULL;
    }
    if (conn->write_buf_remote.data) {
        free(conn->write_buf_remote.data);
        conn->write_buf_remote.data = NULL;
    }
    
    log(DEBUG, "%s", "Conexión SOCKS5 destruida");
    //free(conn);
}

// ==============================
// fd_handler para el selector
// ==============================

static void socks5_read_handler(struct selector_key *key) {
    struct socks5_connection *conn = key->data;
    if (conn->destroying) return;
    stm_handler_read(&conn->stm, key);
}

static void socks5_write_handler(struct selector_key *key) {
    struct socks5_connection *conn = key->data;
    if (conn->destroying) return;
    stm_handler_write(&conn->stm, key);
}

static void socks5_block_handler(struct selector_key *key) {
    struct socks5_connection *conn = key->data;
    if (conn->destroying) return;
    stm_handler_block(&conn->stm, key);
}

static void socks5_close_handler(struct selector_key *key) {
    struct socks5_connection *conn = key->data;
    if (!conn || conn->destroying) return;

    log(DEBUG, "Close handler llamado para fd=%d", key->fd);

    // Marcar que extremo se cerro
    if (key->fd == conn->client_fd) {
        conn->client_closed = true;
        log(DEBUG, "%s", "Cliente cerró la conexión");
    } else if (key->fd == conn->remote_fd) {
        conn->remote_closed = true;
        log(DEBUG, "%s", "Servidor remoto cerró la conexión");
    }

    // Desregistrar el otro fd si no esta cerrado
    if (!conn->client_closed && conn->client_fd != -1) {
        selector_unregister_fd(key->s, conn->client_fd);
        conn->client_closed = true;
    }

    if (!conn->remote_closed && conn->remote_fd != -1) {
        selector_unregister_fd(key->s, conn->remote_fd);
        conn->remote_closed = true;
    }

    // Cerrar si los dos extremos estan cerrados
    if (conn->client_closed && conn->remote_closed) {
        log(DEBUG, "%s", "Ambos extremos cerrados. Liberando conexión");
        socks5_connection_destroy(conn);
    }

    // free(conn);
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
    if (conn->destroying) return ST_DONE;
    
    selector_set_interest_key(key, OP_READ);
    buffer *b = &conn->read_buf_client;

    size_t space;
    uint8_t *ptr = buffer_write_ptr(b, &space);

    ssize_t n = recv(key->fd, ptr, space, 0);
    if (n < 0) {
        log(ERROR, "%s", "recv() falló");
        return ST_DONE;
    } else if (n == 0) {
        log(DEBUG, "%s", "Conexión cerrada por el cliente");
        return ST_DONE;
    }

    buffer_write_adv(b, n);  

    int res = socks5_auth_negotiate(conn);
    if (res < 0) return ST_DONE;  
    if (res == 0) return ST_AUTH;    
    
    log(DEBUG, "Autenticación negociada, método: 0x%02x", conn->auth_method);
    
    metrics_auth_method_used(conn->auth_method, true, NULL);
    
    if (conn->auth_method == SOCKS5_AUTH_USERPASS) {
        log(DEBUG, "%s", "Esperando credenciales de usuario/contraseña");
        return ST_AUTH_USERPASS;
    } else {
        log(DEBUG, "%s", "Sin autenticación requerida, pasando a REQUEST");
        return ST_REQUEST;
    }
}

static unsigned on_auth_userpass_read(struct selector_key *key) {
    struct socks5_connection *conn = key->data;
    if (conn->destroying) return ST_DONE;
    
    if (!conn->userpass_parser) {
        log(ERROR, "%s", "Parser híbrido no inicializado");
        return ST_DONE;
    }
    
    selector_set_interest_key(key, OP_READ);
    buffer *b = &conn->read_buf_client;

    size_t space;
    uint8_t *ptr = buffer_write_ptr(b, &space);

    ssize_t n = recv(key->fd, ptr, space, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return ST_AUTH_USERPASS;
        }
        log(ERROR, "recv() falló en auth userpass: %s", strerror(errno));
        return ST_DONE;
    } else if (n == 0) {
        log(DEBUG, "%s", "Conexión cerrada por el cliente durante auth userpass");
        return ST_DONE;
    }

    buffer_write_adv(b, n);

    int res = socks5_userpass_auth(conn);
    if (res < 0) {
        metrics_auth_method_used(SOCKS5_AUTH_USERPASS, false, NULL);
        return ST_DONE;        
    }
    if (res == 0) return ST_AUTH_USERPASS;
    
    log(DEBUG, "Usuario autenticado exitosamente: %s", conn->auth_username);
    
    metrics_auth_method_used(SOCKS5_AUTH_USERPASS, true, conn->auth_username);
    
    return ST_REQUEST;
}

static unsigned on_request_read(struct selector_key *key) {
    struct socks5_connection *conn = key->data;
    if (conn->destroying) return ST_DONE;
    
    selector_set_interest_key(key, OP_READ);
    
    buffer *b = &conn->read_buf_client;
    size_t available;
    buffer_read_ptr(b, &available);
    
    if (available == 0) {
        size_t space;
        uint8_t *ptr = buffer_write_ptr(b, &space);
        
        ssize_t n = recv(key->fd, ptr, space, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return ST_REQUEST; 
            }
            log(ERROR, "recv() falló en request: %s", strerror(errno));
            return ST_DONE;
        } else if (n == 0) {
            log(DEBUG, "%s", "Conexión cerrada por el cliente durante request");
            return ST_DONE;
        }
        
        buffer_write_adv(b, n);
    }
    
    log(DEBUG, "%s", "Procesando request SOCKS5");
    int res = socks5_process_request(conn);

    if (res < 0) return ST_DONE;     
    if (res == 0) return ST_REQUEST;
    
    log(DEBUG, "Request procesado exitosamente, conectando a %s:%d", conn->target_host, conn->target_port);
    
    metrics_request_type(conn->target_atyp);
    
    if (conn->target_atyp == SOCKS5_ATYP_DOMAINNAME) {
        log(DEBUG, "Iniciando resolución DNS asíncrona para %s", conn->target_host);
        start_resolve_async(conn, key->s);
        return ST_RESOLVING;
    } else {
        // Es una IP, podemos conectar directamente
        // Crear una addrinfo fake para la IP
        struct addrinfo *addr = calloc(1, sizeof(*addr));
        if (!addr) {
            log(ERROR, "%s", "Error alocando memoria para addrinfo");
            return ST_DONE;
        }
        
        if (conn->target_atyp == SOCKS5_ATYP_IPV4) {
            struct sockaddr_in *sin = calloc(1, sizeof(*sin));
            sin->sin_family = AF_INET;
            sin->sin_port = htons(conn->target_port);
            inet_pton(AF_INET, conn->target_host, &sin->sin_addr);
            
            addr->ai_family = AF_INET;
            addr->ai_socktype = SOCK_STREAM;
            addr->ai_protocol = IPPROTO_TCP;
            addr->ai_addr = (struct sockaddr*)sin;
            addr->ai_addrlen = sizeof(*sin);
        } else if (conn->target_atyp == SOCKS5_ATYP_IPV6) {
            struct sockaddr_in6 *sin6 = calloc(1, sizeof(*sin6));
            sin6->sin6_family = AF_INET6;
            sin6->sin6_port = htons(conn->target_port);
            inet_pton(AF_INET6, conn->target_host, &sin6->sin6_addr);
            
            addr->ai_family = AF_INET6;
            addr->ai_socktype = SOCK_STREAM;
            addr->ai_protocol = IPPROTO_TCP;
            addr->ai_addr = (struct sockaddr*)sin6;
            addr->ai_addrlen = sizeof(*sin6);
        }
        
        conn->addr_list = addr;
        
        if (socks5_finish_connection(conn) < 0) {
            log(ERROR, "%s", "Error conectando al servidor remoto");
            metrics_error_occurred(METRICS_ERROR_CONNECTION_REFUSED);
            socks5_send_request_response(conn, SOCKS5_REP_HOST_UNREACHABLE);
            return ST_DONE;
        }

        if (socks5_send_request_response(conn, SOCKS5_REP_SUCCESS) < 0) {
            log(ERROR, "%s", "Error enviando respuesta de éxito");
            return ST_DONE;
        }

        selector_status s = selector_register(key->s, conn->remote_fd, &socks5_handler, OP_READ, conn);
        if (s != SELECTOR_SUCCESS) {
            log(ERROR, "Error registrando fd remoto: %s", selector_error(s));
            return ST_DONE;
        }

        log(DEBUG, "Conexión establecida exitosamente con %s:%d", conn->target_host, conn->target_port);
        conn->socks5_reply_code = SOCKS5_REP_SUCCESS;
        return ST_STREAM;
    }
}

static unsigned on_resolving_block(struct selector_key *key) {
    struct socks5_connection *conn = key->data;
    if (conn->destroying) return ST_DONE;
    
    if (!conn->dns_job) {
        log(ERROR, "%s", "on_resolving_block llamado sin job DNS");
        return ST_DONE;
    }
    
    if (conn->dns_job->error_code != 0) {
        log(ERROR, "Error en resolución DNS: %s", gai_strerror(conn->dns_job->error_code));
        metrics_error_occurred(METRICS_ERROR_DNS_RESOLUTION);
        socks5_send_request_response(conn, SOCKS5_REP_HOST_UNREACHABLE);
        return ST_DONE;
    }
    
    conn->addr_list = conn->dns_job->result;
    conn->dns_job->result = NULL; // imp!! para evitar double free
    
    log(DEBUG, "Resolución DNS completada para %s, procediendo a conectar", conn->target_host);
    
    if (socks5_finish_connection(conn) < 0) {
        log(ERROR, "%s", "Error conectando al servidor remoto");
        metrics_error_occurred(METRICS_ERROR_CONNECTION_REFUSED);
        socks5_send_request_response(conn, SOCKS5_REP_HOST_UNREACHABLE);
        return ST_DONE;
    }

    if (socks5_send_request_response(conn, SOCKS5_REP_SUCCESS) < 0) {
        log(ERROR, "%s", "Error enviando respuesta de éxito");
        return ST_DONE;
    }

    selector_status s = selector_register(key->s, conn->remote_fd, &socks5_handler, OP_READ, conn);
    if (s != SELECTOR_SUCCESS) {
        log(ERROR, "Error registrando fd remoto: %s", selector_error(s));
        return ST_DONE;
    }

    log(DEBUG, "Conexión establecida exitosamente con %s:%d", conn->target_host, conn->target_port);
    conn->socks5_reply_code = SOCKS5_REP_SUCCESS;
    return ST_STREAM;
}

static unsigned on_connect_block(struct selector_key *key) {
    struct socks5_connection *conn = key->data;
    if (conn->destroying) return ST_DONE;
    
    if (socks5_finish_connection(conn) < 0) {
        log(ERROR, "%s", "Error conectando al servidor remoto");
        metrics_error_occurred(METRICS_ERROR_CONNECTION_REFUSED);
        socks5_send_request_response(conn, SOCKS5_REP_HOST_UNREACHABLE);
        return ST_DONE;
    }

    if (socks5_send_request_response(conn, SOCKS5_REP_SUCCESS) < 0) {
        log(ERROR, "%s", "Error enviando respuesta de éxito");
        return ST_DONE;
    }

    selector_status s = selector_register(key->s, conn->remote_fd, &socks5_handler, OP_READ, conn);
    if (s != SELECTOR_SUCCESS) {
        log(ERROR, "Error registrando fd remoto: %s", selector_error(s));
        return ST_DONE;
    }

    log(DEBUG, "Conexión establecida exitosamente con %s:%d", conn->target_host, conn->target_port);
    conn->socks5_reply_code = SOCKS5_REP_SUCCESS;
    return ST_STREAM;
}

static unsigned on_stream_read(struct selector_key *key) {
    struct socks5_connection *conn = key->data;
    if (conn->destroying) return ST_DONE;
    
    int from_fd = key->fd;
    int to_fd;
    buffer *from_buf;
    
    if (from_fd == conn->client_fd) {
        // Cliente -> Servidor remoto
        to_fd = conn->remote_fd;
        from_buf = &conn->read_buf_client;
    } else {
        // Servidor remoto -> Cliente
        to_fd = conn->client_fd;
        from_buf = &conn->read_buf_remote;
    }
    
    size_t space;
    uint8_t *ptr = buffer_write_ptr(from_buf, &space);
    
    if (space == 0) {
        selector_set_interest_key(key, OP_NOOP);
        selector_set_interest(key->s, to_fd, OP_WRITE);
        return ST_STREAM;
    }
    
    ssize_t n = recv(from_fd, ptr, space, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return ST_STREAM; 
        }
        log(ERROR, "Error en recv(): %s", strerror(errno));
        return ST_DONE;
    } else if (n == 0) {
        log(DEBUG, "Conexión cerrada por %s", (from_fd == conn->client_fd) ? "cliente" : "servidor remoto");
        return ST_DONE;
    }
    
    buffer_write_adv(from_buf, n);
    
    size_t available;
    uint8_t *data = buffer_read_ptr(from_buf, &available);
    
    if (available > 0) {
        ssize_t sent = send(to_fd, data, available, MSG_NOSIGNAL);
        if (sent > 0) {
            buffer_read_adv(from_buf, sent);
            
            if (from_fd == conn->client_fd) {
                // Cliente -> Remoto
                metrics_bytes_transferred(n, 0, 0, sent);
            } else {
                // Remoto -> Cliente
                metrics_bytes_transferred(0, sent, n, 0);
            }
        } else if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            log(ERROR, "Error en send(): %s", strerror(errno));
            return ST_DONE;
        }
        
        buffer_read_ptr(from_buf, &available);
        if (available > 0) {
            selector_set_interest(key->s, to_fd, OP_READ | OP_WRITE);
        }
    }
    
    return ST_STREAM;
}

static unsigned on_stream_write(struct selector_key *key) {
    struct socks5_connection *conn = key->data;
    if (conn->destroying) return ST_DONE;
    
    int to_fd = key->fd;
    buffer *buf;
    int from_fd;
    
    if (to_fd == conn->client_fd) {
        buf = &conn->write_buf_client;
        from_fd = conn->remote_fd;
    } else {
        buf = &conn->write_buf_remote;
        from_fd = conn->client_fd;
    }
    
    size_t available;
    uint8_t *data = buffer_read_ptr(buf, &available);
    
    if (available == 0) {
        selector_set_interest_key(key, OP_READ);
        return ST_STREAM;
    }
    
    ssize_t sent = send(to_fd, data, available, MSG_NOSIGNAL);
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return ST_STREAM;
        }
        log(ERROR, "Error en send(): %s", strerror(errno));
        return ST_DONE;
    }
    
    buffer_read_adv(buf, sent);
    
    if (to_fd == conn->client_fd) {
        // Remoto -> Cliente
        metrics_bytes_transferred(0, sent, 0, 0);
    } else {
        // Cliente -> Remoto
        metrics_bytes_transferred(0, 0, 0, sent);
    }
    
    buffer_read_ptr(buf, &available);
    if (available == 0) {
        selector_set_interest_key(key, OP_READ);
        selector_set_interest(key->s, from_fd, OP_READ);
    }
    
    return ST_STREAM;
}

static void on_done_arrival(unsigned state, struct selector_key *key) {
    struct socks5_connection *conn = key->data;
    log(DEBUG, "%s", "Entrando en estado DONE");

    struct access_log_info log_info;
    memset(&log_info, 0, sizeof(log_info));

    log_info.timestamp = time(NULL);
    strncpy(log_info.username, conn->auth_username, sizeof(log_info.username) - 1);
    strncpy(log_info.client_ip, conn->client_ip, sizeof(log_info.client_ip) - 1);
    log_info.client_port = conn->client_port;
    strncpy(log_info.target_host, conn->target_host, sizeof(log_info.target_host) - 1);
    log_info.target_port = conn->target_port;

    if (conn->authenticated && conn->remote_fd != -1) {
        snprintf(log_info.status, sizeof(log_info.status), "%u", SOCKS5_REP_SUCCESS);
    } else {
        if (!conn->authenticated && conn->socks5_reply_code == SOCKS5_REP_GENERAL_FAILURE) {
            strncpy(log_info.status, "AUTH_FAILED", sizeof(log_info.status) - 1);
        } else {
            snprintf(log_info.status, sizeof(log_info.status), "%u", conn->socks5_reply_code);
        }
    }
    access_log(&log_info);

    if (!conn->client_closed && conn->client_fd != -1) {
        selector_unregister_fd(key->s, conn->client_fd);
        conn->client_closed = true;
    }

    if (!conn->remote_closed && conn->remote_fd != -1) {
        selector_unregister_fd(key->s, conn->remote_fd);
        conn->remote_closed = true;
    }

    // El destroy lo maneja el close_handler cuando ambos extremos estén cerrados.
}
