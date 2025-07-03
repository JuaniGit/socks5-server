#ifndef USERPASS_PARSER_H
#define USERPASS_PARSER_H

#include "../parser.h"
#include "../buffer.h"
#include <stdint.h>
#include <stdbool.h>

// Estados del parser simplificado - solo necesitamos uno para leer bytes
enum userpass_parser_state {
    USERPASS_READ = 0
};

// Estados de nuestra lógica manual
enum userpass_parse_state {
    PARSE_VERSION = 0,
    PARSE_ULEN,
    PARSE_USERNAME,
    PARSE_PLEN,
    PARSE_PASSWORD
};

// Tipos de eventos del parser (simplificado)
enum userpass_event_type {
    USERPASS_EVENT_BYTE = 0  // Solo un tipo: byte leído
};

// Estructura para mantener el estado del parsing
struct userpass_parser_data {
    // Estado de nuestra lógica manual
    enum userpass_parse_state state;
    
    // Datos del protocolo
    uint8_t version;
    uint8_t ulen;
    uint8_t plen;
    char username[256];
    char password[256];
    uint8_t username_bytes_read;
    uint8_t password_bytes_read;
    
    // Estado del parsing
    bool finished;
    bool error;
};

// Función de acción para el parser
void userpass_byte_action(struct parser_event *ret, const uint8_t c);

// Crear definición del parser (ahora retorna puntero)
struct parser_definition* userpass_parser_definition(void);

// Procesar eventos del parser con nuestra lógica manual
int userpass_process_event(struct userpass_parser_data *data, const struct parser_event *event);

// Inicializar datos del parser
void userpass_parser_data_init(struct userpass_parser_data *data);

// Funciones de acceso a los datos parseados
const char* userpass_parser_get_username(struct userpass_parser_data *data);
const char* userpass_parser_get_password(struct userpass_parser_data *data);
bool userpass_parser_is_done(struct userpass_parser_data *data);
bool userpass_parser_has_error(struct userpass_parser_data *data);

#endif
