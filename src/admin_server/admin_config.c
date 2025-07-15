#include "admin_config.h"
#include "../shared/logger.h"
#include <pthread.h>

// config global del servidor
admin_server_config admin_global_config = {
    500,
    false
};

static pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;

struct admin_server_config* admin_config_get(void) {
    return &admin_global_config;
}

void admin_config_set_max_connections(uint32_t max_conn) {
    pthread_mutex_lock(&config_mutex);
    
    if (admin_global_config.max_connections != max_conn) {
        uint32_t old_value = admin_global_config.max_connections;
        admin_global_config.max_connections = max_conn;
        admin_global_config.config_changed = true;
        
        log(INFO, "Configuración: max_connections cambiado de %u a %u", old_value, max_conn);
    }
    
    pthread_mutex_unlock(&config_mutex);
}

bool admin_config_has_changed(void) {
    pthread_mutex_lock(&config_mutex);
    bool changed = admin_global_config.config_changed;
    pthread_mutex_unlock(&config_mutex);
    return changed;
}

void admin_config_mark_processed(void) {
    pthread_mutex_lock(&config_mutex);
    admin_global_config.config_changed = false;
    pthread_mutex_unlock(&config_mutex);
}

void admin_config_init(void) {
    pthread_mutex_lock(&config_mutex);
    admin_global_config.max_connections = 500;
    admin_global_config.config_changed = false;
    pthread_mutex_unlock(&config_mutex);
    
    log(INFO, "%s", "Configuración admin inicializada con valores por defecto"); }
