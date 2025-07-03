#define _POSIX_C_SOURCE 200112L
#include "socks5.h"
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

    // procesar los métodos y elegir uno (NO_AUTH si está disponible)
    uint8_t method = 0xFF; // 0xFF = no acceptable method
    for (uint8_t i = 0; i < nmethods; i++) {
        uint8_t m = ptr[2 + i];
        if (m == NO_AUTH) {
            method = NO_AUTH;
            break;
        }
    }

    conn->auth_method = method;

    // consumir los bytes leídos
    buffer_read_adv(b, 2 + nmethods);

    // Enviar respuesta al cliente
    if (socks5_send_auth_response(conn, method) < 0) {
        log(ERROR, "Error enviando respuesta de autenticación");
        return -1;
    }

    if (method == 0xFF) {
        log(INFO, "No hay método de autenticación aceptable");
        return -1; // no hay método aceptable
    }

    log(INFO, "Autenticación negociada exitosamente, método: %d", method);
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

    log(INFO, "Request SOCKS5: conectar a %s:%d", conn->target_host, conn->target_port);
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
