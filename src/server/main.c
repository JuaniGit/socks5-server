// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#define _POSIX_C_SOURCE 200112L
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "connection.h"
#include "../shared/util.h"
#include "../shared/logger.h"
#include "../selector.h"

#define MAX_PENDING_CONNECTION_REQUESTS 20
#define SOURCE_PORT 1080
#define MAX_CONNECTIONS 1024

// Variables globales para estadísticas
static size_t total_connections = 0;
static size_t current_connections = 0;
static size_t total_bytes_transferred = 0;

/**
 * Handler para nuevas conexiones entrantes
 */
static void accept_handler(struct selector_key* key) {
    struct sockaddr_storage client_addr;
    socklen_t client_len = sizeof(client_addr);

    int client_fd = accept(key->fd, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            log(ERROR, "Error en accept(): %s", strerror(errno));
        }
        return;
    }

    // Hacer no bloqueante
    if (selector_fd_set_nio(client_fd) < 0) {
        log(ERROR, "No se pudo poner en modo no bloqueante: %s", strerror(errno));
        close(client_fd);
        return;
    }

    // Crear la conexión SOCKS5
    struct socks5_connection *conn = socks5_connection_new(client_fd);
    if (conn == NULL) {
        log(ERROR, "No se pudo crear conexión SOCKS5");
        close(client_fd);
        return;
    }

    // Registrar en el selector con el handler global
    selector_status s = selector_register(key->s, client_fd, &socks5_handler, OP_READ, conn);
    if (s != SELECTOR_SUCCESS) {
        log(ERROR, "Error al registrar cliente: %s", selector_error(s));
        socks5_connection_destroy(conn);
        close(client_fd);
        return;
    }

    total_connections++;
    current_connections++;

    char client_addr_str[128];
    printSocketAddress((struct sockaddr*)&client_addr, client_addr_str);
    log(INFO, "Nueva conexión desde %s (fd=%d). Conexiones activas: %zu", client_addr_str, client_fd, current_connections);
}

/**
 * Inicializa socket servidor
 */
static int setup_server_socket(int port) {
    int server_fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (server_fd < 0) {
        log(FATAL, "Error creando socket: %s", strerror(errno));
        return -1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    int ipv6only = 0;
    setsockopt(server_fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, sizeof(ipv6only));

    struct sockaddr_in6 addr = {0};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    addr.sin6_addr = in6addr_any;

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log(FATAL, "Error en bind(): %s", strerror(errno));
        close(server_fd);
        return -1;
    }

    if (listen(server_fd, MAX_PENDING_CONNECTION_REQUESTS) < 0) {
        log(FATAL, "Error en listen(): %s", strerror(errno));
        close(server_fd);
        return -1;
    }

    if (selector_fd_set_nio(server_fd) < 0) {
        log(FATAL, "No se pudo poner el socket en no bloqueante: %s", strerror(errno));
        close(server_fd);
        return -1;
    }

    char addr_str[128];
    printSocketAddress((struct sockaddr*)&addr, addr_str);
    log(INFO, "Servidor escuchando en %s", addr_str);

    return server_fd;
}

/**
 * Estadísticas
 */
static void print_stats(void) {
    log(INFO, "=== Estadísticas del Servidor ===");
    log(INFO, "Conexiones totales: %zu", total_connections);
    log(INFO, "Conexiones activas: %zu", current_connections);
    log(INFO, "Bytes transferidos: %zu", total_bytes_transferred);
    log(INFO, "=================================");
}

/**
 * Señales
 */
static volatile int running = 1;

static void signal_handler(int sig) {
    log(INFO, "Recibida señal %d. Finalizando...", sig);
    running = 0;
}

/**
 * Main
 */
int main(int argc, const char* argv[]) {
    setLogLevel(DEBUG);
    log(INFO, "Inicializando servidor SOCKS5...");

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    // Inicializar selector
    struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = { .tv_sec = 10, .tv_nsec = 0 }
    };

    if (selector_init(&conf) != SELECTOR_SUCCESS) {
        log(FATAL, "No se pudo inicializar el selector");
        return EXIT_FAILURE;
    }

    fd_selector selector = selector_new(MAX_CONNECTIONS);
    if (selector == NULL) {
        log(FATAL, "No se pudo crear el selector");
        return EXIT_FAILURE;
    }

    int server_fd = setup_server_socket(SOURCE_PORT);
    if (server_fd < 0) {
		if (selector != NULL) {
			selector_destroy(selector);
			selector_close();
		}
        return EXIT_FAILURE;
    }

    fd_handler server_handler = {
        .handle_read = accept_handler,
        .handle_write = NULL,
        .handle_block = NULL,
        .handle_close = NULL,
    };

    if (selector_register(selector, server_fd, &server_handler, OP_READ, NULL) != SELECTOR_SUCCESS) {
        log(FATAL, "Error registrando socket servidor");
        close(server_fd);
        selector_destroy(selector);
        selector_close();
        return EXIT_FAILURE;
    }

    log(INFO, "Servidor SOCKS5 iniciado correctamente");
    log(INFO, "Esperando conexiones...");

    time_t last_stats = time(NULL);    
    
    // while (selector_select(selector) == SELECTOR_SUCCESS) {
    //     ;
    // }


    while (running) {
        selector_status s = selector_select(selector);
        if (s != SELECTOR_SUCCESS && !(s == SELECTOR_IO && (errno == EINTR || errno == EAGAIN))) {
            log(ERROR, "Error en selector_select: %s", selector_error(s));
            break;
        }

        time_t now = time(NULL);
        if (now - last_stats >= 60) {
            print_stats();
            last_stats = now;
        }
    }

    log(INFO, "Servidor finalizando...");
    print_stats();

    close(server_fd);
    selector_destroy(selector);
    selector_close();
    log(INFO, "Recursos liberados. Hasta luego.");
    return EXIT_SUCCESS;
}
