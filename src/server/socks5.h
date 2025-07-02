#ifndef SOCKS5_H
#define SOCKS5_H

#include "../selector.h"
#include "connection.h"  // Para struct socks5_connection

// Ejecuta la negociación de autenticación (estado ST_AUTH)
// Devuelve 0 si fue exitosa, -1 si hubo error (se envía respuesta de error al cliente).
int socks5_auth_negotiate(struct socks5_connection *conn);

// Procesa el request del cliente (estado ST_REQUEST)
// Si es válido, guarda los datos y arranca resolución DNS (asíncrona si es necesario)
int socks5_process_request(struct socks5_connection *conn);

// Termina la conexión TCP con el servidor remoto luego de resolver la dirección (ST_CONNECTING)
// Devuelve 0 si se conecta correctamente, -1 si no.
int socks5_finish_connection(struct socks5_connection *conn);

// (Opcional) Lanza un hilo o tarea de resolución DNS (puede usar `getaddrinfo`) y luego
// debe llamar a `selector_notify_block()` cuando termine, para que se dispare ST_RESOLVING.
void start_resolve_async(struct socks5_connection *conn);

#endif