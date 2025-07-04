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
#include "users.h"
#include "metrics.h"
#include "../shared/util.h"
#include "../shared/logger.h"
#include "../selector.h"

#define MAX_PENDING_CONNECTION_REQUESTS 20
#define SOURCE_PORT 1080
#define MAX_CONNECTIONS 1024

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

    log(INFO, "Nueva conexión aceptada (fd=%d)", client_fd);

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

    log(INFO, "Conexión SOCKS5 creada para fd=%d", client_fd);

    // Registrar en el selector con el handler global
    selector_status s = selector_register(key->s, client_fd, &socks5_handler, OP_READ, conn);
    if (s != SELECTOR_SUCCESS) {
        log(ERROR, "Error al registrar cliente: %s", selector_error(s));
        socks5_connection_destroy(conn);
        close(client_fd);
        return;
    }

    // Registrar métricas
    metrics_connection_started();

    char client_addr_str[128];
    printSocketAddress((struct sockaddr*)&client_addr, client_addr_str);
    log(INFO, "Cliente registrado desde %s (fd=%d). Conexiones activas: %lu", 
        client_addr_str, client_fd, metrics_get_current_connections());
}

/**
 * Inicializa socket servidor
 */
static int setup_server_socket(int port) {
    // crea el socket con ipv6
    int server_fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (server_fd < 0) {
        log(FATAL, "Error creando socket: %s", strerror(errno));
        return -1;
    }

    // permite reutilizar la direccion (evita "address already in use")
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // configura el socket default ipv6 pero acepta ipv4 al estar en 0 ipv6only
    int ipv6only = 0;
    setsockopt(server_fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, sizeof(ipv6only));

    // configura el puerto y la dirección
    struct sockaddr_in6 addr = {0};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    addr.sin6_addr = in6addr_any;

    // conecta al socket con esa dirección y puerto
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log(FATAL, "Error en bind(): %s", strerror(errno));
        close(server_fd);
        return -1;
    }

    // poner al socket en modo escucha
    if (listen(server_fd, MAX_PENDING_CONNECTION_REQUESTS) < 0) {
        log(FATAL, "Error en listen(): %s", strerror(errno));
        close(server_fd);
        return -1;
    }

    // hacemos al socket no bloqueante
    if (selector_fd_set_nio(server_fd) < 0) {
        log(FATAL, "No se pudo poner el socket en no bloqueante: %s", strerror(errno));
        close(server_fd);
        return -1;
    }

    // retorno la dirección del socket
    char addr_str[128];
    printSocketAddress((struct sockaddr*)&addr, addr_str);
    log(INFO, "Servidor escuchando en %s", addr_str);

    return server_fd;
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

    // Inicializar sistema de métricas
    if (!metrics_init()) {
        log(FATAL, "Error inicializando sistema de métricas");
        return EXIT_FAILURE;
    }

    // Inicializar sistema de usuarios
    if (!users_init(NULL)) {
        log(FATAL, "Error inicializando sistema de usuarios");
        metrics_destroy();
        return EXIT_FAILURE;
    }

    // Mostrar mensaje de bienvenida
    log(INFO, "Sistema de usuarios inicializado");
    printf("%s\n", users_get_welcome_message());

    // Inicializar selector
    struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = { .tv_sec = 10, .tv_nsec = 0 }
    };

    if (selector_init(&conf) != SELECTOR_SUCCESS) {
        log(FATAL, "No se pudo inicializar el selector");
        metrics_destroy();
        return EXIT_FAILURE;
    }

    fd_selector selector = selector_new(MAX_CONNECTIONS);
    if (selector == NULL) {
        log(FATAL, "No se pudo crear el selector");
        metrics_destroy();
        return EXIT_FAILURE;
    }

    int server_fd = setup_server_socket(SOURCE_PORT);
    if (server_fd < 0) {
        if (selector != NULL) {
            selector_destroy(selector);
            selector_close();
        }
        metrics_destroy();
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
        metrics_destroy();
        return EXIT_FAILURE;
    }

    log(INFO, "Servidor SOCKS5 iniciado correctamente");
    log(INFO, "Esperando conexiones...");

    time_t last_stats = time(NULL);    

    while (running) {
        selector_status s = selector_select(selector);
        if (s == SELECTOR_IO && errno == EBADF) {
            log(ERROR, "Descriptor inválido detectado. Probablemente un cliente cerró la conexión sin desregistrarse.");
            // Continúa, no se cae el servidor
            continue;
        } else if (s != SELECTOR_SUCCESS && !(errno == EINTR || errno == EAGAIN)) {
            log(ERROR, "Error en selector_select: %s", selector_error(s));
            break;  // Solo cortás por errores graves
        }

        time_t now = time(NULL);
        if (now - last_stats >= 60) {
            metrics_print_summary();
            last_stats = now;
        }
    }

    log(INFO, "Servidor finalizando...");
    metrics_print_summary();

    close(server_fd);
    selector_destroy(selector);
    selector_close();
    metrics_destroy();
    log(INFO, "Recursos liberados. Hasta luego.");
    return EXIT_SUCCESS;
}
