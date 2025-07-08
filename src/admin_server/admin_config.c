#include "admin_config.h"
#include "../shared/logger.h"
#include <pthread.h>

// config global del servidor
static struct admin_server_config global_config = {
    .max_connections = 500,
    .buffer_size = 4096,
    .timeout_seconds = 30,
    .config_changed = false
};

static pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;

struct admin_server_config* admin_config_get(void) {
    return &global_config;
}

void admin_config_set_max_connections(uint32_t max_conn) {
    pthread_mutex_lock(&config_mutex);
    
    if (global_config.max_connections != max_conn) {
        uint32_t old_value = global_config.max_connections;
        global_config.max_connections = max_conn;
        global_config.config_changed = true;
        
        log(INFO, "Configuración: max_connections cambiado de %u a %u", old_value, max_conn);
    }
    
    pthread_mutex_unlock(&config_mutex);
}

void admin_config_set_buffer_size(uint32_t buffer_size) {
    pthread_mutex_lock(&config_mutex);
    
    if (global_config.buffer_size != buffer_size) {
        uint32_t old_value = global_config.buffer_size;
        global_config.buffer_size = buffer_size;
        global_config.config_changed = true;
        
        log(INFO, "Configuración: buffer_size cambiado de %u a %u", old_value, buffer_size);
    }
    
    pthread_mutex_unlock(&config_mutex);
}

void admin_config_set_timeout(uint32_t timeout) {
    pthread_mutex_lock(&config_mutex);
    
    if (global_config.timeout_seconds != timeout) {
        uint32_t old_value = global_config.timeout_seconds;
        global_config.timeout_seconds = timeout;
        global_config.config_changed = true;
        
        log(INFO, "Configuración: timeout cambiado de %u a %u", old_value, timeout);
    }
    
    pthread_mutex_unlock(&config_mutex);
}

bool admin_config_has_changed(void) {
    pthread_mutex_lock(&config_mutex);
    bool changed = global_config.config_changed;
    pthread_mutex_unlock(&config_mutex);
    return changed;
}

void admin_config_mark_processed(void) {
    pthread_mutex_lock(&config_mutex);
    global_config.config_changed = false;
    pthread_mutex_unlock(&config_mutex);
}

void admin_config_init(void) {
    pthread_mutex_lock(&config_mutex);
    global_config.max_connections = 500;
    global_config.buffer_size = 4096;
    global_config.timeout_seconds = 30;
    global_config.config_changed = false;
    pthread_mutex_unlock(&config_mutex);
    
    log(INFO, "Configuración admin inicializada con valores por defecto");
}
