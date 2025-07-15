#define _POSIX_C_SOURCE 200112L
#include "metrics.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdio.h>
#define math_log log
#include <math.h>
#undef log
#include "../shared/logger.h"

static struct socks5_metrics global_metrics;
static pthread_mutex_t metrics_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool metrics_initialized = false;

#define MAX_UNIQUE_USERS 1000
static char unique_users[MAX_UNIQUE_USERS][256];
static int unique_users_count = 0;

static void update_throughput(void) {
    time_t now = time(NULL);
    time_t elapsed = now - global_metrics.last_throughput_calculation;
    
    if (elapsed >= 1) {
        uint64_t bytes_diff = global_metrics.transfers.total_bytes_transferred - global_metrics.last_bytes_count;
        global_metrics.performance.current_throughput_bps = (double)bytes_diff / elapsed;
        
        global_metrics.last_throughput_calculation = now;
        global_metrics.last_bytes_count = global_metrics.transfers.total_bytes_transferred;
    }
}

static void update_connections_per_minute(void) {
    time_t now = time(NULL);
    
    global_metrics.connection_timestamps[global_metrics.connection_timestamp_index] = now;
    global_metrics.connection_timestamp_index = (global_metrics.connection_timestamp_index + 1) % 60;
    
    uint64_t count = 0;
    for (int i = 0; i < 60; i++) {
        if (global_metrics.connection_timestamps[i] > 0 && 
            (now - global_metrics.connection_timestamps[i]) <= 60) {
            count++;
        }
    }
    global_metrics.performance.connections_per_minute = count;
}

static bool is_user_unique(const char *username) {
    if (!username) return false;
    
    for (int i = 0; i < unique_users_count; i++) {
        if (strcmp(unique_users[i], username) == 0) {
            return false;
        }
    }
    return true;
}

static void add_unique_user(const char *username) {
    if (!username || unique_users_count >= MAX_UNIQUE_USERS) return;
    
    if (is_user_unique(username)) {
        strncpy(unique_users[unique_users_count], username, 255);
        unique_users[unique_users_count][255] = '\0';
        unique_users_count++;
        global_metrics.users.unique_users_count = unique_users_count;
    }
}

bool metrics_init(void) {
    pthread_mutex_lock(&metrics_mutex);
    
    if (metrics_initialized) {
        pthread_mutex_unlock(&metrics_mutex);
        return true;
    }
    
    memset(&global_metrics, 0, sizeof(global_metrics));
    
    global_metrics.performance.server_start_time = time(NULL);
    global_metrics.last_reset_time = time(NULL);
    global_metrics.last_throughput_calculation = time(NULL);
    
    unique_users_count = 0;
    
    metrics_initialized = true;
    pthread_mutex_unlock(&metrics_mutex);
    
    log(INFO, "%s", "Sistema de métricas inicializado");
    return true;
}

void metrics_destroy(void) {
    pthread_mutex_lock(&metrics_mutex);
    metrics_initialized = false;
    pthread_mutex_unlock(&metrics_mutex);
    log(INFO, "%s", "Sistema de métricas destruido");
}

void metrics_connection_started(void) {
    pthread_mutex_lock(&metrics_mutex);
    
    global_metrics.connections.total_connections++;
    global_metrics.connections.current_connections++;
    
    if (global_metrics.connections.current_connections > global_metrics.performance.max_concurrent_connections) {
        global_metrics.performance.max_concurrent_connections = global_metrics.connections.current_connections;
    }
    
    update_connections_per_minute();
    
    pthread_mutex_unlock(&metrics_mutex);
    
}

void metrics_connection_ended(bool successful, double connection_time_ms) {
    pthread_mutex_lock(&metrics_mutex);
    
    if (global_metrics.connections.current_connections > 0) {
        global_metrics.connections.current_connections--;
    }
    
    if (successful) {
        global_metrics.connections.successful_connections++;
    } else {
        global_metrics.connections.failed_connections++;
    }
    
    if (connection_time_ms > 0) {
        double current_avg = global_metrics.performance.avg_connection_time_ms;
        uint64_t total_successful = global_metrics.connections.successful_connections;
        
        if (total_successful == 1) {
            global_metrics.performance.avg_connection_time_ms = connection_time_ms;
        } else {
            global_metrics.performance.avg_connection_time_ms = 
                (current_avg * (total_successful - 1) + connection_time_ms) / total_successful;
        }
    }
    
    pthread_mutex_unlock(&metrics_mutex);
    
    log(DEBUG, "Métrica: Conexión terminada. Exitosa: %s, Tiempo: %.2fms", 
        successful ? "Sí" : "No", connection_time_ms);
}

void metrics_auth_method_used(uint8_t auth_method, bool success, const char *username) {
    pthread_mutex_lock(&metrics_mutex);
    
    switch (auth_method) {
        case 0x02: // Username/password
            if (success) {
                global_metrics.connections.auth_userpass_success++;
                if (username) {
                    add_unique_user(username);
                }
            } else {
                global_metrics.connections.auth_userpass_failed++;
            }
            break;
    }
    
    pthread_mutex_unlock(&metrics_mutex);
    
    log(DEBUG, "Métrica: Método de autenticación usado: 0x%02x, Exitoso: %s", 
        auth_method, success ? "Sí" : "No");
}

void metrics_request_type(uint8_t address_type) {
    pthread_mutex_lock(&metrics_mutex);
    
    switch (address_type) {
        case 0x01: // IPv4
            global_metrics.connections.requests_ipv4++;
            break;
        case 0x03: // Domain name
            global_metrics.connections.requests_domain++;
            break;
        case 0x04: // IPv6
            global_metrics.connections.requests_ipv6++;
            break;
    }
    
    pthread_mutex_unlock(&metrics_mutex);
    
    log(DEBUG, "Métrica: Tipo de request: 0x%02x", address_type);
}

void metrics_error_occurred(uint8_t error_type) {
    pthread_mutex_lock(&metrics_mutex);
    
    switch (error_type) {
        case METRICS_ERROR_DNS_RESOLUTION:
            global_metrics.connections.errors_dns_resolution++;
            break;
        case METRICS_ERROR_CONNECTION_REFUSED:
            global_metrics.connections.errors_connection_refused++;
            break;
        case METRICS_ERROR_NETWORK_UNREACHABLE:
            global_metrics.connections.errors_network_unreachable++;
            break;
        case METRICS_ERROR_GENERAL:
        default:
            global_metrics.connections.errors_general++;
            break;
    }
    
    pthread_mutex_unlock(&metrics_mutex);
    
    log(DEBUG, "Métrica: Error ocurrido: tipo %d", error_type);
}

void metrics_bytes_transferred(uint64_t from_client, uint64_t to_client, 
                              uint64_t from_remote, uint64_t to_remote) {
    pthread_mutex_lock(&metrics_mutex);
    
    global_metrics.transfers.bytes_from_client += from_client;
    global_metrics.transfers.bytes_to_client += to_client;
    global_metrics.transfers.bytes_from_remote += from_remote;
    global_metrics.transfers.bytes_to_remote += to_remote;
    global_metrics.transfers.total_bytes_transferred += (from_client + to_client + from_remote + to_remote);
    
    update_throughput();
    
    pthread_mutex_unlock(&metrics_mutex);
}

struct socks5_metrics metrics_get_snapshot(void) {
    struct socks5_metrics snapshot;
    
    pthread_mutex_lock(&metrics_mutex);
    snapshot = global_metrics;
    update_throughput();
    pthread_mutex_unlock(&metrics_mutex);
    
    return snapshot;
}

uint64_t metrics_get_total_connections(void) {
    pthread_mutex_lock(&metrics_mutex);
    uint64_t total = global_metrics.connections.total_connections;
    pthread_mutex_unlock(&metrics_mutex);
    return total;
}

uint64_t metrics_get_current_connections(void) {
    pthread_mutex_lock(&metrics_mutex);
    uint64_t current = global_metrics.connections.current_connections;
    pthread_mutex_unlock(&metrics_mutex);
    return current;
}

uint64_t metrics_get_total_bytes(void) {
    pthread_mutex_lock(&metrics_mutex);
    uint64_t total = global_metrics.transfers.total_bytes_transferred;
    pthread_mutex_unlock(&metrics_mutex);
    return total;
}

double metrics_get_current_throughput(void) {
    pthread_mutex_lock(&metrics_mutex);
    update_throughput();
    double throughput = global_metrics.performance.current_throughput_bps;
    pthread_mutex_unlock(&metrics_mutex);
    return throughput;
}

uint64_t metrics_get_connections_per_minute(void) {
    pthread_mutex_lock(&metrics_mutex);
    uint64_t cpm = global_metrics.performance.connections_per_minute;
    pthread_mutex_unlock(&metrics_mutex);
    return cpm;
}

void metrics_reset(void) {
    pthread_mutex_lock(&metrics_mutex);
    
    time_t start_time = global_metrics.performance.server_start_time;
    memset(&global_metrics, 0, sizeof(global_metrics));
    global_metrics.performance.server_start_time = start_time;
    global_metrics.last_reset_time = time(NULL);
    global_metrics.last_throughput_calculation = time(NULL);
    
    unique_users_count = 0;
    
    pthread_mutex_unlock(&metrics_mutex);
    
    log(INFO, "%s", "Métricas reseteadas");
}

uint64_t metrics_get_uptime_seconds(void) {
    pthread_mutex_lock(&metrics_mutex);
    uint64_t uptime = time(NULL) - global_metrics.performance.server_start_time;
    pthread_mutex_unlock(&metrics_mutex);
    return uptime;
}

void metrics_print_summary(void) {
    struct socks5_metrics snapshot = metrics_get_snapshot();
    uint64_t uptime = metrics_get_uptime_seconds();
    
    printf("\n=== RESUMEN DE MÉTRICAS SOCKS5 ===\n");
    printf("Tiempo de funcionamiento: %lu segundos (%.2f horas)\n", 
           uptime, uptime / 3600.0);
    
    printf("\n--- Conexiones ---\n");
    printf("Total histórico: %lu\n", snapshot.connections.total_connections);
    printf("Actuales: %lu\n", snapshot.connections.current_connections);
    printf("Exitosas: %lu\n", snapshot.connections.successful_connections);
    printf("Fallidas: %lu\n", snapshot.connections.failed_connections);
    printf("Máximo concurrentes: %lu\n", snapshot.performance.max_concurrent_connections);
    printf("Por minuto: %lu\n", snapshot.performance.connections_per_minute);
    
    printf("\n--- Autenticación ---\n");
    printf("Usuarios únicos: %lu\n", snapshot.users.unique_users_count);
    
    printf("\n--- Transferencia de Datos ---\n");
    printf("Total transferido: %lu bytes (%.2f MB)\n", 
           snapshot.transfers.total_bytes_transferred,
           snapshot.transfers.total_bytes_transferred / (1024.0 * 1024.0));
    printf("Del cliente: %lu bytes\n", snapshot.transfers.bytes_from_client);
    printf("Al cliente: %lu bytes\n", snapshot.transfers.bytes_to_client);
    printf("Del remoto: %lu bytes\n", snapshot.transfers.bytes_from_remote);
    printf("Al remoto: %lu bytes\n", snapshot.transfers.bytes_to_remote);
    printf("Throughput actual: %.2f bytes/seg (%.2f KB/s)\n", 
           snapshot.performance.current_throughput_bps,
           snapshot.performance.current_throughput_bps / 1024.0);
    
    printf("\n--- Rendimiento ---\n");
    printf("Tiempo promedio de conexión: %.2f ms\n", snapshot.performance.avg_connection_time_ms);
    
    if (snapshot.connections.total_connections > 0) {
        double success_rate = (double)snapshot.connections.successful_connections / 
                             snapshot.connections.total_connections * 100.0;
        printf("Tasa de éxito: %.2f%%\n", success_rate);
    }
    
    printf("=====================================\n\n");
}