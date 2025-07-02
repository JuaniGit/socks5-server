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
    buffer b = conn->read_buf_client;
    size_t available;
    uint8_t *ptr = buffer_read_ptr(&b, &available);

    if (available < 2) {
        return 0; // faltan datos: versión y nmethods
    }

    uint8_t ver = ptr[0];
    uint8_t nmethods = ptr[1];

    if (ver != SOCKS5_VERSION) {
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
    buffer_read_adv(&b, 2 + nmethods);

    if (method == 0xFF) {
        return -1; // no hay método aceptable
    }

    return 1; // éxito
}