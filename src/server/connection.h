#ifndef CONNECTION_H
#define CONNECTION_H

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif

#include <netdb.h>
#include <pthread.h>
#include <sys/time.h>
#include <stdbool.h>
#include "../selector.h"
#include "../stm.h"
#include "../buffer.h"
#include "../parser.h"
#include "userpass_parser.h"

enum socks5_state {
    ST_AUTH = 0,
    ST_AUTH_USERPASS,
    ST_REQUEST,
    ST_RESOLVING,
    ST_CONNECTING,
    ST_STREAM,
    ST_DONE,
};

// para pasarle info al thread de dns
struct dns_resolution_job {
    struct socks5_connection *conn;
    fd_selector selector;
    char hostname[256];
    uint16_t port;
    struct addrinfo *result;
    int error_code;
    pthread_t thread_id;
};

// conexión cliente SOCKS5
struct socks5_connection {
    int client_fd;
    int remote_fd;

    uint8_t auth_method;

    char auth_username[256];
    char auth_password[256];
    bool authenticated;
    
    struct parser *userpass_parser;
    struct userpass_parser_data userpass_data;
    
    uint8_t target_atyp;
    char target_host[256];
    uint16_t target_port;

    struct addrinfo *addr_list;
    struct dns_resolution_job *dns_job;

    struct state_machine stm;

    buffer read_buf_client;
    buffer write_buf_client;
    buffer read_buf_remote;
    buffer write_buf_remote;

    bool client_closed;
    bool remote_closed;
    bool destroying;  // para evitar double cleanup

    char client_address_str[128];
    char client_ip[46];
    int client_port;
    uint8_t socks5_reply_code;
    
    struct timeval start_time;
};

void socks5_connection_destroy_all();
struct socks5_connection *socks5_connection_new(int client_fd, const struct sockaddr *client_addr);
void socks5_connection_destroy(struct socks5_connection *conn, fd_selector s);
void socks5_set_shutdown_mode(bool shutting_down);
extern const struct fd_handler socks5_handler;

#endif
