#ifndef ADMIN_CONFIG_H
#define ADMIN_CONFIG_H

#include <stdint.h>
#include <stdbool.h>

// config global del servidor que puede ser editada por admin
struct admin_server_config {
    uint32_t max_connections;
    uint32_t buffer_size;
    uint32_t timeout_seconds;
    bool config_changed;  // Flag para notificar cambios
};

struct admin_server_config* admin_config_get(void);
void admin_config_set_max_connections(uint32_t max_conn);
void admin_config_set_buffer_size(uint32_t buffer_size);
void admin_config_set_timeout(uint32_t timeout);
bool admin_config_has_changed(void);
void admin_config_mark_processed(void);
void admin_config_init(void);

#endif
