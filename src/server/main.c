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
#include "../shared/access_logger.h"
#include "../selector.h"
#include "../admin_server/admin_protocol.h"
#include "../admin_server/admin_config.h"
#include "config.h"

#define MAX_PENDING_CONNECTION_REQUESTS 20
#define MAX_CONNECTIONS 500

// Configuración global
static struct server_config global_config;
extern admin_server_config admin_global_config;

// Variables globales para cleanup
fd_selector global_selector = NULL;
static int server_fd = -1;
static int admin_fd = -1;
static volatile int running = 1;

extern size_t active_count;

/**
 * Función de limpieza de recursos
 */
static void cleanup_resources(void) {
    log(INFO, "%s", "Iniciando limpieza de recursos...");
    
    // Activar modo shutdown para que las conexiones se limpien correctamente
    socks5_set_shutdown_mode(true);
    
    // Cerrar sockets servidor primero para evitar nuevas conexiones
    if (server_fd >= 0) {
        log(INFO, "Cerrando socket servidor SOCKS5 (fd=%d)", server_fd);
        close(server_fd);
        server_fd = -1;
    }
    
    if (admin_fd >= 0) {
        log(INFO, "Cerrando socket servidor admin (fd=%d)", admin_fd);
        close(admin_fd);
        admin_fd = -1;
    }
    
    // Destruir selector (esto cierra todas las conexiones activas)
    if (global_selector) {
        log(INFO, "%s", "Destruyendo selector y conexiones activas");
        socks5_connection_destroy_all();
        selector_destroy(global_selector);
        log(INFO, "%s", "Selector destruido");
        global_selector = NULL;
    }
    
    // Cerrar subsistema de selector
    log(INFO, "%s", "Cerrando subsistema de selector");
    selector_close();
    log(INFO, "%s", "Subsistema de selector cerrado");
    
    // Cerrar subsistemas
    log(INFO, "%s", "Cerrando access logger");
    access_logger_close();
    log(INFO, "%s", "Access logger cerrado");
    
    log(INFO, "%s", "Destruyendo métricas");
    metrics_destroy();
    log(INFO, "%s", "Métricas destruidas");
    
    log(INFO, "%s", "Limpieza de recursos completada");
}

/**
 * Manejador de señales
 */
static void signal_handler(int sig) {
    log(INFO, "Recibida señal %d (%s). Finalizando servidor...", 
        sig, (sig == SIGINT) ? "SIGINT" : (sig == SIGTERM) ? "SIGTERM" : "UNKNOWN");
    running = 0;
}

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
        log(ERROR, "%s", "No se pudo crear conexión admin");
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

    if (active_count >= admin_global_config.max_connections) {
        log(DEBUG, "Rechazando conexión, máximo de conexiones alcanzado (%zu)", active_count);
        close(client_fd);
        return;
    }

    char client_addr_str[128];
    printSocketAddress((struct sockaddr*)&client_addr, client_addr_str);

    // Crear la conexión SOCKS5
    struct socks5_connection *conn = socks5_connection_new(client_fd, (struct sockaddr*)&client_addr);
    if (conn == NULL) {
        log(ERROR, "%s", "No se pudo crear conexión SOCKS5");
        close(client_fd);
        return;
    }

    // Registrar en el selector con el handler global
    selector_status s = selector_register(key->s, client_fd, &socks5_handler, OP_READ, conn);
    if (s != SELECTOR_SUCCESS) {
        log(ERROR, "Error al registrar cliente: %s", selector_error(s));
        socks5_connection_destroy(conn, key->s);
        close(client_fd);
        return;
    }

    // Registrar métricas
    metrics_connection_started();

    log(DEBUG, "Cliente registrado desde %s (fd=%d). Conexiones activas: %lu", 
        client_addr_str, client_fd, metrics_get_current_connections());
}

/**
 * Inicializa socket servidor con dirección específica
 */
static int setup_server_socket(const char *address, int port) {
    int server_socket;
    
    // Determinar si es IPv4 o IPv6
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
    struct sockaddr *addr;
    socklen_t addr_len;
    
    if (inet_pton(AF_INET, address, &addr4.sin_addr) == 1) {
        // IPv4
        server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (server_socket < 0) {
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
        server_socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (server_socket < 0) {
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
        server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (server_socket < 0) {
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
        server_socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (server_socket < 0) {
            log(ERROR, "Error creando socket IPv6: %s", strerror(errno));
            return -1;
        }
        
        // Configurar para aceptar IPv4 también
        int ipv6only = 0;
        setsockopt(server_socket, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, sizeof(ipv6only));
        
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
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Bind
    if (bind(server_socket, addr, addr_len) < 0) {
        log(ERROR, "Error en bind() para %s:%d: %s", address, port, strerror(errno));
        close(server_socket);
        return -1;
    }

    // Listen
    if (listen(server_socket, MAX_PENDING_CONNECTION_REQUESTS) < 0) {
        log(ERROR, "Error en listen(): %s", strerror(errno));
        close(server_socket);
        return -1;
    }

    // Hacer no bloqueante
    if (selector_fd_set_nio(server_socket) < 0) {
        log(ERROR, "No se pudo poner el socket en no bloqueante: %s", strerror(errno));
        close(server_socket);
        return -1;
    }

    log(INFO, "Servidor escuchando en %s:%d", address, port);
    return server_socket;
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
 * Main
 */
int main(int argc, char* argv[]) {
    // Registrar función de limpieza
    atexit(cleanup_resources);
    
    // Configurar manejadores de señales
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    if (sigaction(SIGINT, &sa, NULL) < 0) {
        log(ERROR, "Error configurando manejador SIGINT: %s", strerror(errno));
        return EXIT_FAILURE;
    }
    
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        log(ERROR, "Error configurando manejador SIGTERM: %s", strerror(errno));
        return EXIT_FAILURE;
    }
    
    // Ignorar SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    
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
    
    setLogLevel(INFO);
    log(INFO, "%s", "Inicializando servidor SOCKS5...");
    log(INFO, "%s", "Configuración:");
    log(INFO, "  - Puerto SOCKS: %d", global_config.socks_port);
    log(INFO, "  - Dirección SOCKS: %s", global_config.socks_address);
    log(INFO, "  - Puerto Management: %d", global_config.management_port);
    log(INFO, "  - Dirección Management: %s", global_config.management_address);
    log(INFO, "  - Usuarios CLI: %d", global_config.cli_users_count);
    log(INFO, "  - Access Log Habilitado: %s", global_config.access_log_enabled ? "Si" : "No");
    if (global_config.access_log_enabled) {
        log(INFO, "  - Archivo de Access Log: %s", strlen(global_config.access_log_file) > 0 ? global_config.access_log_file : "stdout");
    }

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    // Inicializar sistema de métricas
    if (!metrics_init()) {
        log(FATAL, "%s", "Error inicializando sistema de métricas");
        return EXIT_FAILURE;
    }

    // Inicializar sistema de usuarios
    users_init();

    // Inicializar Access Logger
    if (global_config.access_log_enabled) {
        if (!access_logger_init(strlen(global_config.access_log_file) > 0 ? global_config.access_log_file : NULL)) {
            log(FATAL, "Error inicializando access logger en %s", strlen(global_config.access_log_file) > 0 ? global_config.access_log_file : "stdout");
            return EXIT_FAILURE;
        }
    }
    
    // Cargar usuarios desde línea de comandos
    load_cli_users(&global_config);

    // Mostrar mensaje de bienvenida
    log(INFO, "%s", "Sistema de usuarios inicializado");

    // Inicializar selector
    struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = { .tv_sec = 10, .tv_nsec = 0 }
    };

    if (selector_init(&conf) != SELECTOR_SUCCESS) {
        log(FATAL, "%s", "No se pudo inicializar el selector");
        return EXIT_FAILURE;
    }

    global_selector = selector_new(MAX_CONNECTIONS);
    if (global_selector == NULL) {
        log(FATAL, "%s", "No se pudo crear el selector");
        return EXIT_FAILURE;
    }

    // Crear servidor SOCKS
    server_fd = setup_server_socket(global_config.socks_address, global_config.socks_port);
    if (server_fd < 0) {
        return EXIT_FAILURE;
    }

    fd_handler server_handler = {
        .handle_read = accept_handler,
        .handle_write = NULL,
        .handle_block = NULL,
        .handle_close = NULL,
    };

    if (selector_register(global_selector, server_fd, &server_handler, OP_READ, NULL) != SELECTOR_SUCCESS) {
        log(FATAL, "%s", "Error registrando socket servidor");
        return EXIT_FAILURE;
    }

    log(INFO, "%s", "Servidor SOCKS5 iniciado correctamente");

    // Inicializar configuración de administración
    admin_config_init();

    // Configurar servidor de administración
    admin_fd = setup_server_socket(global_config.management_address, global_config.management_port);
    if (admin_fd < 0) {
        log(ERROR, "No se pudo crear servidor de administración en %s:%d", 
            global_config.management_address, global_config.management_port);
    } else {
        static fd_handler admin_accept_handler = {
            .handle_read = admin_accept_handler_func,
            .handle_write = NULL,
            .handle_block = NULL,
            .handle_close = NULL,
        };

        if (selector_register(global_selector, admin_fd, &admin_accept_handler, OP_READ, NULL) != SELECTOR_SUCCESS) {
            log(ERROR, "%s", "Error registrando servidor de administración");
            close(admin_fd);
            admin_fd = -1;
        } else {
            log(INFO, "Servidor de administración iniciado en %s:%d", global_config.management_address, global_config.management_port);
        }
    }

    log(INFO, "%s", "Esperando conexiones...");

    time_t last_stats = time(NULL);    

    while (running) {
        selector_status s = selector_select(global_selector);
        if (s == SELECTOR_IO && errno == EBADF) {
            log(DEBUG, "%s", "Descriptor inválido detectado. Probablemente un cliente cerró la conexión sin desregistrarse.");
            continue;
        } else if (s != SELECTOR_SUCCESS && !(errno == EINTR || errno == EAGAIN)) {
            log(ERROR, "Error en selector_select: %s", selector_error(s));
            break;
        }
    }

    log(INFO, "%s", "Señal recibida, saliendo del bucle principal");

    log(INFO, "%s", "Servidor finalizando...");
    metrics_print_summary();

    log(INFO, "%s", "Hasta luego.");
    
    // La limpieza se hace automáticamente via atexit()
    return EXIT_SUCCESS;
}
