#ifndef ADMIN_CONFIG_H
#define ADMIN_CONFIG_H

#include <stdint.h>
#include <stdbool.h>

// config global del servidor que puede ser editada por admin
struct admin_server_config {
    uint32_t max_connections;
    uint32_t buffer_size;
    uint32_t timeout_seconds;
    bool config_changed; 
};

struct admin_server_config* admin_config_get(void);
void admin_config_set_max_connections(uint32_t max_conn);
bool admin_config_has_changed(void);
void admin_config_mark_processed(void);
void admin_config_init(void);

#endif
