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
#include "../shared/users.h"
#include "../shared/metrics.h"
#include "../shared/util.h"
#include "../shared/logger.h"
#include "../selector.h"
#include "../admin_server/admin_protocol.h"
#include "../admin_server/admin_config.h"
#include "config.h"

#define MAX_PENDING_CONNECTION_REQUESTS 20
#define MAX_CONNECTIONS 1024

// Configuración global
static struct server_config global_config;

/**
 * Handler para nuevas conexiones de administración
 */
static void admin_accept_handler_func(struct selector_key* key) {
    struct sockaddr_storage client_addr;
    socklen_t client_len = sizeof(client_addr);

    int client_fd = accept(key->fd, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            log(ERROR, "Error en accept() admin: %s", strerror(errno));
        }
        return;
    }

    log(INFO, "Nueva conexión admin aceptada (fd=%d)", client_fd);

    // Hacer no bloqueante
    if (selector_fd_set_nio(client_fd) < 0) {
        log(ERROR, "No se pudo poner conexión admin en modo no bloqueante: %s", strerror(errno));
        close(client_fd);
        return;
    }

    // Crear la conexión admin
    struct admin_connection *conn = admin_connection_new(client_fd);
    if (conn == NULL) {
        log(ERROR, "No se pudo crear conexión admin");
        close(client_fd);
        return;
    }

    // Guardar dirección del cliente
    printSocketAddress((struct sockaddr*)&client_addr, conn->client_address);

    // Registrar en el selector
    selector_status s = selector_register(key->s, client_fd, &admin_handler, OP_READ, conn);
    if (s != SELECTOR_SUCCESS) {
        log(ERROR, "Error al registrar cliente admin: %s", selector_error(s));
        admin_connection_destroy(conn);
        close(client_fd);
        return;
    }

    log(INFO, "Cliente admin registrado desde %s (fd=%d)", conn->client_address, client_fd);
}

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
 * Inicializa socket servidor con dirección específica
 */
static int setup_server_socket(const char *address, int port) {
    int server_fd;
    
    // Determinar si es IPv4 o IPv6
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
    struct sockaddr *addr;
    socklen_t addr_len;
    
    if (inet_pton(AF_INET, address, &addr4.sin_addr) == 1) {
        // IPv4
        server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (server_fd < 0) {
            log(ERROR, "Error creando socket IPv4: %s", strerror(errno));
            return -1;
        }
        
        memset(&addr4, 0, sizeof(addr4));
        addr4.sin_family = AF_INET;
        addr4.sin_port = htons(port);
        // addr4.sin_addr ya está configurado por inet_pton
        
        addr = (struct sockaddr*)&addr4;
        addr_len = sizeof(addr4);
        
    } else if (inet_pton(AF_INET6, address, &addr6.sin6_addr) == 1) {
        // IPv6
        server_fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (server_fd < 0) {
            log(ERROR, "Error creando socket IPv6: %s", strerror(errno));
            return -1;
        }
        
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(port);
        // addr6.sin6_addr ya está configurado por inet_pton
        
        addr = (struct sockaddr*)&addr6;
        addr_len = sizeof(addr6);
        
    } else if (strcmp(address, "0.0.0.0") == 0) {
        // IPv4 todas las interfaces
        server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (server_fd < 0) {
            log(ERROR, "Error creando socket IPv4: %s", strerror(errno));
            return -1;
        }
        
        memset(&addr4, 0, sizeof(addr4));
        addr4.sin_family = AF_INET;
        addr4.sin_port = htons(port);
        addr4.sin_addr.s_addr = INADDR_ANY;
        
        addr = (struct sockaddr*)&addr4;
        addr_len = sizeof(addr4);
        
    } else if (strcmp(address, "::") == 0) {
        // IPv6 todas las interfaces
        server_fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (server_fd < 0) {
            log(ERROR, "Error creando socket IPv6: %s", strerror(errno));
            return -1;
        }
        
        // Configurar para aceptar IPv4 también
        int ipv6only = 0;
        setsockopt(server_fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, sizeof(ipv6only));
        
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(port);
        addr6.sin6_addr = in6addr_any;
        
        addr = (struct sockaddr*)&addr6;
        addr_len = sizeof(addr6);
        
    } else {
        log(ERROR, "Dirección inválida: %s", address);
        return -1;
    }

    // Permitir reutilizar la dirección
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Bind
    if (bind(server_fd, addr, addr_len) < 0) {
        log(ERROR, "Error en bind() para %s:%d: %s", address, port, strerror(errno));
        close(server_fd);
        return -1;
    }

    // Listen
    if (listen(server_fd, MAX_PENDING_CONNECTION_REQUESTS) < 0) {
        log(ERROR, "Error en listen(): %s", strerror(errno));
        close(server_fd);
        return -1;
    }

    // Hacer no bloqueante
    if (selector_fd_set_nio(server_fd) < 0) {
        log(ERROR, "No se pudo poner el socket en no bloqueante: %s", strerror(errno));
        close(server_fd);
        return -1;
    }

    log(INFO, "Servidor escuchando en %s:%d", address, port);
    return server_fd;
}

/**
 * Cargar usuarios desde línea de comandos
 */
static void load_cli_users(struct server_config *config) {
    for (int i = 0; i < config->cli_users_count; i++) {
        if (config->cli_users[i].used) {
            bool success = users_add(config->cli_users[i].username, 
                                   config->cli_users[i].password);
            if (success) {
                log(INFO, "Usuario cargado desde CLI: %s", config->cli_users[i].username);
            } else {
                log(ERROR, "Error cargando usuario desde CLI: %s", config->cli_users[i].username);
            }
        }
    }
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
int main(int argc, char* argv[]) {
    // Inicializar configuración
    config_init(&global_config);
    
    // Parsear argumentos de línea de comandos
    if (config_parse_args(&global_config, argc, argv) < 0) {
        config_show_help(argv[0]);
        return EXIT_FAILURE;
    }
    
    // Manejar flags especiales
    if (global_config.show_help) {
        config_show_help(argv[0]);
        return EXIT_SUCCESS;
    }
    
    if (global_config.show_version) {
        config_show_version();
        return EXIT_SUCCESS;
    }
    
    setLogLevel(DEBUG);
    log(INFO, "Inicializando servidor SOCKS5...");
    log(INFO, "Configuración:");
    log(INFO, "  - Puerto SOCKS: %d", global_config.socks_port);
    log(INFO, "  - Dirección SOCKS: %s", global_config.socks_address);
    log(INFO, "  - Puerto Management: %d", global_config.management_port);
    log(INFO, "  - Dirección Management: %s", global_config.management_address);
    log(INFO, "  - Usuarios CLI: %d", global_config.cli_users_count);

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
    
    // Cargar usuarios desde línea de comandos
    load_cli_users(&global_config);

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

    // Crear servidor SOCKS
    int server_fd = setup_server_socket(global_config.socks_address, global_config.socks_port);
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

    // Inicializar configuración de administración
    admin_config_init();

    // Configurar servidor de administración
    int admin_fd = setup_server_socket(global_config.management_address, global_config.management_port);
    if (admin_fd < 0) {
        log(ERROR, "No se pudo crear servidor de administración en %s:%d", 
            global_config.management_address, global_config.management_port);
    } else {
        fd_handler admin_accept_handler = {
            .handle_read = admin_accept_handler_func,
            .handle_write = NULL,
            .handle_block = NULL,
            .handle_close = NULL,
        };

        if (selector_register(selector, admin_fd, &admin_accept_handler, OP_READ, NULL) != SELECTOR_SUCCESS) {
            log(ERROR, "Error registrando servidor de administración");
            close(admin_fd);
            admin_fd = -1;
        } else {
            log(INFO, "Servidor de administración iniciado en %s:%d", global_config.management_address, global_config.management_port);
        }
    }

    log(INFO, "Esperando conexiones...");

    time_t last_stats = time(NULL);    

    while (running) {
        selector_status s = selector_select(selector);
        if (s == SELECTOR_IO && errno == EBADF) {
            log(ERROR, "Descriptor inválido detectado. Probablemente un cliente cerró la conexión sin desregistrarse.");
            continue;
        } else if (s != SELECTOR_SUCCESS && !(errno == EINTR || errno == EAGAIN)) {
            log(ERROR, "Error en selector_select: %s", selector_error(s));
            break;
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
    if (admin_fd >= 0) {
        close(admin_fd);
    }
    selector_destroy(selector);
    selector_close();
    metrics_destroy();
    log(INFO, "Recursos liberados. Hasta luego.");
    return EXIT_SUCCESS;
}