#ifndef USERPASS_PARSER_H
#define USERPASS_PARSER_H

#include "../parser.h"
#include "../buffer.h"
#include <stdint.h>
#include <stdbool.h>

// estados + simple -> solo necesitamos uno para leer bytes
enum userpass_parser_state {
    USERPASS_READ = 0
};

// estados
enum userpass_parse_state {
    PARSE_VERSION = 0,
    PARSE_ULEN,
    PARSE_USERNAME,
    PARSE_PLEN,
    PARSE_PASSWORD
};

// tipos de eventos + simple
enum userpass_event_type {
    USERPASS_EVENT_BYTE = 0  // Solo un tipo: byte leído
};

struct userpass_parser_data {
    enum userpass_parse_state state;
    
    uint8_t version;
    uint8_t ulen;
    uint8_t plen;
    char username[256];
    char password[256];
    uint8_t username_bytes_read;
    uint8_t password_bytes_read;
    
    bool finished;
    bool error;
};

void userpass_byte_action(struct parser_event *ret, const uint8_t c);
struct parser_definition* userpass_parser_definition(void);
int userpass_process_event(struct userpass_parser_data *data, const struct parser_event *event);
void userpass_parser_data_init(struct userpass_parser_data *data);
const char* userpass_parser_get_username(struct userpass_parser_data *data);
const char* userpass_parser_get_password(struct userpass_parser_data *data);
bool userpass_parser_is_done(struct userpass_parser_data *data);
bool userpass_parser_has_error(struct userpass_parser_data *data);

#endif
