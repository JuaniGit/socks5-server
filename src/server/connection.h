#ifndef CONNECTION_H
#define CONNECTION_H

#define _POSIX_C_SOURCE 200112L
#include <netdb.h>
#include "../selector.h"
#include "../stm.h"
#include "../buffer.h"

enum socks5_state {
    ST_AUTH = 0,
    ST_REQUEST,
    ST_RESOLVING,
    ST_CONNECTING,
    ST_STREAM,
    ST_DONE,
};

// Encapsula toda la información de una conexión cliente SOCKS5
struct socks5_connection {
    int client_fd;
    int remote_fd;

    uint8_t auth_method;
    
    // Información del destino
    uint8_t target_atyp;
    char target_host[256];
    uint16_t target_port;

    struct addrinfo *addr_list;

    struct state_machine stm;

    buffer read_buf_client;
    buffer write_buf_client;
    buffer read_buf_remote;
    buffer write_buf_remote;

    // Flags de control
    bool client_closed;
    bool remote_closed;

    // Direcciones y buffers temporales
    char client_address_str[128];

    // TODO: despues se van a agregar más flags y etc
};

// Crea una nueva conexión SOCKS5 asociada a un fd
struct socks5_connection *socks5_connection_new(int client_fd);

// Libera todos los recursos asociados a una conexión SOCKS5
void socks5_connection_destroy(struct socks5_connection *conn);

// fd_handler para registrar en el selector
extern const struct fd_handler socks5_handler;

#endif
