#ifndef SOCKS5_H
#define SOCKS5_H

#include "../selector.h"
#include "connection.h"  // Para struct socks5_connection

// Constantes SOCKS5
#define SOCKS5_VERSION 0x05

// Métodos de autenticación
#define SOCKS5_AUTH_NO_AUTH 0x00
#define SOCKS5_AUTH_USERPASS 0x02
#define SOCKS5_AUTH_NO_ACCEPTABLE 0xFF

// Comandos
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_BIND 0x02
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03

// Tipos de dirección
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAINNAME 0x03
#define SOCKS5_ATYP_IPV6 0x04

// Códigos de respuesta
#define SOCKS5_REP_SUCCESS 0x00
#define SOCKS5_REP_GENERAL_FAILURE 0x01
#define SOCKS5_REP_CONNECTION_NOT_ALLOWED 0x02
#define SOCKS5_REP_NETWORK_UNREACHABLE 0x03
#define SOCKS5_REP_HOST_UNREACHABLE 0x04
#define SOCKS5_REP_CONNECTION_REFUSED 0x05
#define SOCKS5_REP_TTL_EXPIRED 0x06
#define SOCKS5_REP_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED 0x08

// Constantes para autenticación usuario/contraseña (RFC1929)
#define USERPASS_VERSION 0x01
#define USERPASS_SUCCESS 0x00
#define USERPASS_FAILURE 0x01

// Ejecuta la negociación de autenticación (estado ST_AUTH)
// Devuelve 0 si fue exitosa, -1 si hubo error (se envía respuesta de error al cliente).
int socks5_auth_negotiate(struct socks5_connection *conn);

// Procesa el request del cliente (estado ST_REQUEST)
// Si es válido, guarda los datos y arranca resolución DNS (asíncrona si es necesario)
int socks5_process_request(struct socks5_connection *conn);

// Termina la conexión TCP con el servidor remoto luego de resolver la dirección (ST_CONNECTING)
// Devuelve 0 si se conecta correctamente, -1 si no.
int socks5_finish_connection(struct socks5_connection *conn);

// Lanza un hilo de resolución DNS y luego llama a selector_notify_block()
void start_resolve_async(struct socks5_connection *conn, fd_selector selector);

// Nuevas funciones
int socks5_send_auth_response(struct socks5_connection *conn, uint8_t method);
int socks5_send_request_response(struct socks5_connection *conn, uint8_t reply_code);

// Funciones para autenticación usuario/contraseña
int socks5_userpass_auth(struct socks5_connection *conn);
int socks5_send_userpass_response(struct socks5_connection *conn, uint8_t status);

#endif
