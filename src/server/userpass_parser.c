#include "userpass_parser.h"
#include "../shared/logger.h"
#include <string.h>
#include <stdlib.h>

// Funciones de acción simplificadas - solo generan eventos de "byte leído"
void userpass_byte_action(struct parser_event *ret, const uint8_t c) {
    ret->type = USERPASS_EVENT_BYTE;
    ret->n = 1;
    ret->data[0] = c;
}

// Definición de transiciones - todas van al mismo estado y generan el mismo evento
static const struct parser_state_transition userpass_st_read[] = {
    {.when = ANY, .dest = USERPASS_READ, .act1 = userpass_byte_action}
};

// Array de estados - necesitamos asegurarnos de que el índice coincida
static const struct parser_state_transition *userpass_states[] = {
    userpass_st_read  // índice 0 = USERPASS_READ
};

// Cantidad de transiciones por estado - debe coincidir con el array anterior
static const size_t userpass_states_n[] = {
    sizeof(userpass_st_read) / sizeof(userpass_st_read[0])  // índice 0
};

// Definición estática del parser (debe persistir en memoria)
static struct parser_definition userpass_def = {0};
static bool parser_def_initialized = false;

struct parser_definition* userpass_parser_definition(void) {
    if (!parser_def_initialized) {
        userpass_def.states_count = sizeof(userpass_states) / sizeof(userpass_states[0]);
        userpass_def.states = userpass_states;
        userpass_def.states_n = userpass_states_n;
        userpass_def.start_state = USERPASS_READ;
        parser_def_initialized = true;
        
        // Debug: verificar que la definición es válida
        log(DEBUG, "Parser definition: states_count=%u, start_state=%u", 
            userpass_def.states_count, userpass_def.start_state);
    }
    
    return &userpass_def;
}

void userpass_parser_data_init(struct userpass_parser_data *data) {
    if (!data) return;
    
    memset(data, 0, sizeof(*data));
    data->state = PARSE_VERSION;
    data->finished = false;
    data->error = false;
    
    log(DEBUG, "Parser data inicializado, estado inicial: %d", data->state);
}

int userpass_process_event(struct userpass_parser_data *data, const struct parser_event *event) {
    if (!data || !event) {
        log(ERROR, "userpass_process_event: parámetros NULL");
        return -1;
    }
    
    if (data->finished || data->error) {
        return data->error ? -1 : 1;
    }
    
    // El parser solo nos da eventos de "byte leído"
    if (event->type != USERPASS_EVENT_BYTE) {
        log(ERROR, "Evento inesperado del parser: %d", event->type);
        data->error = true;
        return -1;
    }
    
    uint8_t byte = event->data[0];
    log(DEBUG, "Procesando byte 0x%02x en estado %d", byte, data->state);
    
    // Aquí procesamos el byte según nuestro estado manual
    switch (data->state) {
        case PARSE_VERSION:
            data->version = byte;
            if (data->version != 0x01) {
                log(ERROR, "Versión de autenticación usuario/contraseña inválida: 0x%02x", data->version);
                data->error = true;
                return -1;
            }
            log(DEBUG, "Versión de autenticación: 0x%02x", data->version);
            data->state = PARSE_ULEN;
            break;
            
        case PARSE_ULEN:
            data->ulen = byte;
            if (data->ulen == 0 || data->ulen > 255) {
                log(ERROR, "Longitud de usuario inválida: %d", data->ulen);
                data->error = true;
                return -1;
            }
            log(DEBUG, "Longitud de usuario: %d", data->ulen);
            data->username_bytes_read = 0;
            memset(data->username, 0, sizeof(data->username));
            data->state = PARSE_USERNAME;
            break;
            
        case PARSE_USERNAME:
            if (data->username_bytes_read < data->ulen && data->username_bytes_read < sizeof(data->username) - 1) {
                data->username[data->username_bytes_read] = byte;
                data->username_bytes_read++;
                
                if (data->username_bytes_read == data->ulen) {
                    data->username[data->username_bytes_read] = '\0';
                    log(DEBUG, "Usuario completo: %s", data->username);
                    data->state = PARSE_PLEN;
                }
            } else {
                log(ERROR, "Usuario demasiado largo");
                data->error = true;
                return -1;
            }
            break;
            
        case PARSE_PLEN:
            data->plen = byte;
            if (data->plen == 0 || data->plen > 255) {
                log(ERROR, "Longitud de contraseña inválida: %d", data->plen);
                data->error = true;
                return -1;
            }
            log(DEBUG, "Longitud de contraseña: %d", data->plen);
            data->password_bytes_read = 0;
            memset(data->password, 0, sizeof(data->password));
            data->state = PARSE_PASSWORD;
            break;
            
        case PARSE_PASSWORD:
            if (data->password_bytes_read < data->plen && data->password_bytes_read < sizeof(data->password) - 1) {
                data->password[data->password_bytes_read] = byte;
                data->password_bytes_read++;
                
                if (data->password_bytes_read == data->plen) {
                    data->password[data->password_bytes_read] = '\0';
                    data->finished = true;
                    log(DEBUG, "Parsing de credenciales completado para usuario: %s", data->username);
                    return 1; // Completado exitosamente
                }
            } else {
                log(ERROR, "Contraseña demasiado larga");
                data->error = true;
                return -1;
            }
            break;
            
        default:
            log(ERROR, "Estado de parsing inválido: %d", data->state);
            data->error = true;
            return -1;
    }
    
    return 0; // Necesita más datos
}

// Funciones de acceso a los datos parseados
const char* userpass_parser_get_username(struct userpass_parser_data *data) {
    return (data && data->finished) ? data->username : NULL;
}

const char* userpass_parser_get_password(struct userpass_parser_data *data) {
    return (data && data->finished) ? data->password : NULL;
}

bool userpass_parser_is_done(struct userpass_parser_data *data) {
    return data && data->finished;
}

bool userpass_parser_has_error(struct userpass_parser_data *data) {
    return data && data->error;
}
