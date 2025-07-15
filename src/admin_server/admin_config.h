#ifndef ADMIN_CONFIG_H
#define ADMIN_CONFIG_H

#include <stdint.h>
#include <stdbool.h>

typedef struct admin_server_config {
    uint64_t max_connections;
    bool config_changed;
} admin_server_config;

struct admin_server_config* admin_config_get(void);
void admin_config_set_max_connections(uint32_t max_conn);
bool admin_config_has_changed(void);
void admin_config_mark_processed(void);
void admin_config_init(void);

#endif
