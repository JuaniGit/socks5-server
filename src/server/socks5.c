#define _POSIX_C_SOURCE 200112L
#include "socks5.h"
#include "../shared/users.h"
#include "../shared/util.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "../shared/logger.h"
#include "../buffer.h"
#include "../selector.h"

#define SOCKS5_VERSION 0x05
#define NO_AUTH 0x00

// --------------------------
// Resolución DNS asíncrona
// --------------------------

static void* dns_resolution_thread(void* arg) {
    struct dns_resolution_job *job = (struct dns_resolution_job*)arg;
    
    log(DEBUG, "Iniciando resolución DNS para %s:%d", job->hostname, job->port);
    
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", job->port);
    
    // Esta es la llamada bloqueante que hacemos en el thread separado
    job->error_code = getaddrinfo(job->hostname, port_str, &hints, &job->result);
    
    if (job->error_code == 0) {
        log(DEBUG, "Resolución DNS exitosa para %s", job->hostname);
    } else {
        log(ERROR, "Error en resolución DNS para %s: %s", job->hostname, gai_strerror(job->error_code));
    }
    
    // Notificar al selector que la resolución terminó
    selector_notify_block(job->selector, job->conn->client_fd);
    
    return NULL;
}

void start_resolve_async(struct socks5_connection *conn, fd_selector selector) {
    // Crear job de resolución
    struct dns_resolution_job *job = malloc(sizeof(*job));
    if (!job) {
        log(ERROR, "No se pudo alocar memoria para job DNS");
        return;
    }
    
    job->conn = conn;
    job->selector = selector;
    strncpy(job->hostname, conn->target_host, sizeof(job->hostname) - 1);
    job->hostname[sizeof(job->hostname) - 1] = '\0';
    job->port = conn->target_port;
    job->result = NULL;
    job->error_code = 0;
    
    conn->dns_job = job;
    
    // Crear thread para resolución
    int ret = pthread_create(&job->thread_id, NULL, dns_resolution_thread, job);
    if (ret != 0) {
        log(ERROR, "Error creando thread DNS: %s", strerror(ret));
        free(job);
        conn->dns_job = NULL;
        return;
    }
    
    // Detach el thread para que se limpie automáticamente
    pthread_detach(job->thread_id);
    
    log(DEBUG, "Thread DNS iniciado para %s:%d", conn->target_host, conn->target_port);
}

// --------------------------
// ST_AUTH
// --------------------------

int socks5_auth_negotiate(struct socks5_connection *conn) {
    buffer *b = &conn->read_buf_client;
    size_t available;
    uint8_t *ptr = buffer_read_ptr(b, &available);

    if (available < 2) {
        return 0; // faltan datos: versión y nmethods
    }

    uint8_t ver = ptr[0];
    uint8_t nmethods = ptr[1];

    if (ver != SOCKS5_VERSION) {
        log(ERROR, "Versión SOCKS inválida: %d", ver);
        return -1; // versión inválida
    }

    if (available < 2 + nmethods) {
        return 0; // aún no llegaron todos los métodos
    }

    // procesar los métodos y elegir uno
    uint8_t method = SOCKS5_AUTH_NO_ACCEPTABLE; // 0xFF = no acceptable method
    bool supports_no_auth = false;
    bool supports_userpass = false;
    
    for (uint8_t i = 0; i < nmethods; i++) {
        uint8_t m = ptr[2 + i];
        if (m == SOCKS5_AUTH_USERPASS) {
            supports_userpass = true;
        }
    }

    // Preferir autenticación usuario/contraseña si está disponible
    if (supports_userpass) method = SOCKS5_AUTH_USERPASS;

    conn->auth_method = method;

    // consumir los bytes leídos
    buffer_read_adv(b, 2 + nmethods);

    // Enviar respuesta al cliente
    if (socks5_send_auth_response(conn, method) < 0) {
        log(ERROR, "Error enviando respuesta de autenticación");
        return -1;
    }

    if (method == SOCKS5_AUTH_NO_ACCEPTABLE) {
        log(INFO, "No hay método de autenticación aceptable");
        return -1; // no hay método aceptable
    }

    log(INFO, "Autenticación negociada exitosamente, método: 0x%02x", method);
    return 1; // éxito
}

int socks5_send_auth_response(struct socks5_connection *conn, uint8_t method) {
    uint8_t response[2] = {SOCKS5_VERSION, method};
    
    ssize_t sent = send(conn->client_fd, response, 2, MSG_NOSIGNAL);
    if (sent != 2) {
        log(ERROR, "Error enviando respuesta de autenticación: %s", strerror(errno));
        return -1;
    }
    
    log(DEBUG, "Respuesta de autenticación enviada: versión=%d, método=%d", 
        SOCKS5_VERSION, method);
    return 0;
}

// --------------------------
// ST_AUTH_USERPASS - Implementación híbrida usando parser.c
// --------------------------

int socks5_userpass_auth(struct socks5_connection *conn) {
    if (!conn || !conn->userpass_parser) {
        log(ERROR, "socks5_userpass_auth: conexión o parser NULL");
        return -1;
    }
    
    buffer *b = &conn->read_buf_client;
    
    // Alimentar el parser con los datos disponibles
    size_t available;
    uint8_t *ptr = buffer_read_ptr(b, &available);
    
    if (available == 0) {
        log(DEBUG, "No hay datos disponibles para autenticación usuario/contraseña");
        return 0; // No hay datos disponibles
    }
    
    log(DEBUG, "Procesando %zu bytes para autenticación usuario/contraseña usando parser híbrido", available);
    
    // Procesar byte por byte con el parser
    for (size_t i = 0; i < available; i++) {
        // Usar el parser.c para leer el byte
        const struct parser_event *event = parser_feed(conn->userpass_parser, ptr[i]);
        
        if (!event) {
            log(ERROR, "Parser devolvió evento NULL");
            buffer_read_adv(b, i + 1);
            socks5_send_userpass_response(conn, USERPASS_FAILURE);
            return -1;
        }
        
        // Procesar el evento con nuestra lógica manual
        int result = userpass_process_event(&conn->userpass_data, event);
        
        if (result < 0) {
            // Error en parsing
            log(ERROR, "Error en parsing híbrido de autenticación usuario/contraseña");
            buffer_read_adv(b, i + 1);
            socks5_send_userpass_response(conn, USERPASS_FAILURE);
            return -1;
        } else if (result == 1) {
            // Parsing completado
            buffer_read_adv(b, i + 1);
            
            // Validar credenciales
            const char *username = userpass_parser_get_username(&conn->userpass_data);
            const char *password = userpass_parser_get_password(&conn->userpass_data);
            
            if (!username || !password) {
                log(ERROR, "Credenciales NULL después del parsing");
                socks5_send_userpass_response(conn, USERPASS_FAILURE);
                return -1;
            }
            
            if (users_validate(username, password)) {
                // Autenticación exitosa
                strncpy(conn->auth_username, username, sizeof(conn->auth_username) - 1);
                conn->auth_username[sizeof(conn->auth_username) - 1] = '\0';
                conn->authenticated = true;
                
                log(INFO, "Usuario '%s' autenticado exitosamente usando parser híbrido", username);
                socks5_send_userpass_response(conn, USERPASS_SUCCESS);
                return 1;
            } else {
                // Credenciales inválidas
                log(INFO, "Credenciales inválidas para usuario '%s'", username);
                socks5_send_userpass_response(conn, USERPASS_FAILURE);
                return -1;
            }
        }
        // Si result == 0, continúa procesando más bytes
    }
    
    // Consumir todos los bytes procesados
    buffer_read_adv(b, available);
    
    // Necesita más datos
    return 0;
}

int socks5_send_userpass_response(struct socks5_connection *conn, uint8_t status) {
    uint8_t response[2] = {USERPASS_VERSION, status};
    
    ssize_t sent = send(conn->client_fd, response, 2, MSG_NOSIGNAL);
    if (sent != 2) {
        log(ERROR, "Error enviando respuesta de autenticación usuario/contraseña: %s", strerror(errno));
        return -1;
    }
    
    log(DEBUG, "Respuesta de autenticación usuario/contraseña enviada: status=%d", status);
    return 0;
}

int socks5_process_request(struct socks5_connection *conn) {
    buffer *b = &conn->read_buf_client;
    size_t available;
    uint8_t *ptr = buffer_read_ptr(b, &available);

    // Mínimo: VER + CMD + RSV + ATYP + mínimo 1 byte addr + 2 bytes puerto
    if (available < 7) {
        return 0; // faltan datos
    }

    uint8_t ver = ptr[0];
    uint8_t cmd = ptr[1];
    uint8_t rsv = ptr[2];
    uint8_t atyp = ptr[3];

    if (ver != SOCKS5_VERSION) {
        log(ERROR, "Versión SOCKS inválida en request: %d", ver);
        socks5_send_request_response(conn, SOCKS5_REP_GENERAL_FAILURE);
        return -1;
    }

    if (cmd != SOCKS5_CMD_CONNECT) {
        log(ERROR, "Comando no soportado: %d", cmd);
        socks5_send_request_response(conn, SOCKS5_REP_COMMAND_NOT_SUPPORTED);
        return -1;
    }

    // Parsear dirección según tipo
    size_t addr_len = 0;
    size_t total_len = 4; // VER + CMD + RSV + ATYP

    switch (atyp) {
        case SOCKS5_ATYP_IPV4:
            addr_len = 4;
            break;
        case SOCKS5_ATYP_DOMAINNAME:
            if (available < 5) return 0; // falta el byte de longitud
            addr_len = ptr[4] + 1; // +1 por el byte de longitud
            break;
        case SOCKS5_ATYP_IPV6:
            addr_len = 16;
            break;
        default:
            log(ERROR, "Tipo de dirección no soportado: %d", atyp);
            socks5_send_request_response(conn, SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED);
            return -1;
    }

    total_len += addr_len + 2; // +2 por el puerto

    if (available < total_len) {
        return 0; // faltan datos
    }

    // Extraer información de destino
    conn->target_atyp = atyp;
    uint8_t *addr_ptr = ptr + 4;

    switch (atyp) {
        case SOCKS5_ATYP_IPV4: {
            struct in_addr addr;
            memcpy(&addr, addr_ptr, 4);
            inet_ntop(AF_INET, &addr, conn->target_host, sizeof(conn->target_host));
            break;
        }
        case SOCKS5_ATYP_DOMAINNAME: {
            uint8_t domain_len = addr_ptr[0];
            if (domain_len >= sizeof(conn->target_host)) {
                log(ERROR, "Nombre de dominio demasiado largo: %d", domain_len);
                socks5_send_request_response(conn, SOCKS5_REP_GENERAL_FAILURE);
                return -1;
            }
            memcpy(conn->target_host, addr_ptr + 1, domain_len);
            conn->target_host[domain_len] = '\0';
            break;
        }
        case SOCKS5_ATYP_IPV6: {
            struct in6_addr addr;
            memcpy(&addr, addr_ptr, 16);
            inet_ntop(AF_INET6, &addr, conn->target_host, sizeof(conn->target_host));
            break;
        }
    }

    // Extraer puerto (network byte order)
    uint8_t *port_ptr = addr_ptr + addr_len;
    conn->target_port = (port_ptr[0] << 8) | port_ptr[1];

    // Consumir los bytes leídos
    buffer_read_adv(b, total_len);

    log(INFO, "Request SOCKS5: conectar a %s:%d (tipo: %d)", conn->target_host, conn->target_port, atyp);
    return 1; // éxito
}

int socks5_send_request_response(struct socks5_connection *conn, uint8_t reply_code) {
    // Respuesta básica: VER + REP + RSV + ATYP + BND.ADDR + BND.PORT
    uint8_t response[10] = {
        SOCKS5_VERSION,     // VER
        reply_code,         // REP
        0x00,              // RSV
        SOCKS5_ATYP_IPV4,  // ATYP (IPv4)
        0, 0, 0, 0,        // BND.ADDR (0.0.0.0)
        0, 0               // BND.PORT (0)
    };

    ssize_t sent = send(conn->client_fd, response, sizeof(response), MSG_NOSIGNAL);
    if (sent != sizeof(response)) {
        log(ERROR, "Error enviando respuesta de request: %s", strerror(errno));
        return -1;
    }

    log(DEBUG, "Respuesta de request enviada: reply_code=%d", reply_code);
    return 0;
}

int socks5_finish_connection(struct socks5_connection *conn) {
    struct addrinfo *addr_list = conn->addr_list;
    if (!addr_list) {
        log(ERROR, "No hay direcciones resueltas para conectar");
        return -1;
    }
    
    // Crear socket para conexión remota
    int remote_fd = -1;
    int connect_result = -1;
    
    // Intentar conectar con cada dirección disponible
    for (struct addrinfo *addr = addr_list; addr != NULL; addr = addr->ai_next) {
        remote_fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (remote_fd < 0) {
            log(DEBUG, "Error creando socket para familia %d: %s", addr->ai_family, strerror(errno));
            continue;
        }
        
        connect_result = connect(remote_fd, addr->ai_addr, addr->ai_addrlen);
        if (connect_result == 0) {
            // Conexión exitosa
            char addr_str[128];
            printSocketAddress(addr->ai_addr, addr_str);
            log(INFO, "Conectado exitosamente a %s", addr_str);
            break;
        }
        
        log(DEBUG, "Fallo conectando a una dirección: %s, intentando siguiente...", strerror(errno));
        close(remote_fd);
        remote_fd = -1;
    }
    
    if (remote_fd < 0 || connect_result < 0) {
        log(ERROR, "Error conectando a %s:%d: no se pudo conectar a ninguna dirección", 
            conn->target_host, conn->target_port);
        return -1;
    }
    
    // Ahora hacer el socket no bloqueante para el relay de datos
    if (selector_fd_set_nio(remote_fd) < 0) {
        log(ERROR, "Error configurando socket remoto como no bloqueante: %s", strerror(errno));
        close(remote_fd);
        return -1;
    }
    
    conn->remote_fd = remote_fd;
    log(INFO, "Conexión establecida a %s:%d (fd=%d)", conn->target_host, conn->target_port, remote_fd);
    return 0;
}
