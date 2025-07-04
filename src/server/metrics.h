#ifndef METRICS_H
#define METRICS_H

#include <stdint.h>
#include <time.h>
#include <stdbool.h>

// Estructura para métricas de conexiones
struct connection_metrics {
    // Conexiones
    uint64_t total_connections;           // Total histórico de conexiones
    uint64_t current_connections;         // Conexiones activas actuales
    uint64_t successful_connections;      // Conexiones completadas exitosamente
    uint64_t failed_connections;          // Conexiones que fallaron
    
    // Autenticación
    uint64_t auth_userpass_success;      // Autenticaciones usuario/contraseña exitosas
    uint64_t auth_userpass_failed;       // Autenticaciones usuario/contraseña fallidas
    
    // Tipos de destino
    uint64_t requests_ipv4;              // Requests a direcciones IPv4
    uint64_t requests_ipv6;              // Requests a direcciones IPv6
    uint64_t requests_domain;            // Requests a nombres de dominio
    
    // Errores por tipo
    uint64_t errors_dns_resolution;      // Errores de resolución DNS
    uint64_t errors_connection_refused;  // Conexiones rechazadas
    uint64_t errors_network_unreachable; // Red no alcanzable
    uint64_t errors_general;             // Errores generales
};

// Estructura para métricas de transferencia
struct transfer_metrics {
    uint64_t bytes_from_client;          // Bytes recibidos del cliente
    uint64_t bytes_to_client;            // Bytes enviados al cliente
    uint64_t bytes_from_remote;          // Bytes recibidos del servidor remoto
    uint64_t bytes_to_remote;            // Bytes enviados al servidor remoto
    uint64_t total_bytes_transferred;    // Total de bytes transferidos
};

// Estructura para métricas de rendimiento
struct performance_metrics {
    double avg_connection_time_ms;       // Tiempo promedio de establecimiento de conexión
    uint64_t max_concurrent_connections; // Máximo de conexiones concurrentes alcanzado
    time_t server_start_time;            // Tiempo de inicio del servidor
    uint64_t connections_per_minute;     // Conexiones por minuto (ventana deslizante)
    double current_throughput_bps;       // Throughput actual en bytes por segundo
};

// Estructura para métricas de usuarios
struct user_metrics {
    char most_active_user[256];          // Usuario más activo
    uint64_t most_active_user_connections; // Conexiones del usuario más activo
    uint64_t unique_users_count;         // Cantidad de usuarios únicos que se conectaron
};

// Estructura principal de métricas
struct socks5_metrics {
    struct connection_metrics connections;
    struct transfer_metrics transfers;
    struct performance_metrics performance;
    struct user_metrics users;
    
    // Timestamps para cálculos
    time_t last_reset_time;
    time_t last_throughput_calculation;
    uint64_t last_bytes_count;
    
    // Array para ventana deslizante de conexiones por minuto
    time_t connection_timestamps[60];    // Últimas 60 conexiones
    int connection_timestamp_index;
};

// Funciones públicas del sistema de métricas

// Inicializar el sistema de métricas
bool metrics_init(void);

// Destruir el sistema de métricas
void metrics_destroy(void);

// === Funciones para registrar eventos ===

// Registrar nueva conexión
void metrics_connection_started(void);

// Registrar conexión terminada (exitosa o fallida)
void metrics_connection_ended(bool successful, double connection_time_ms);

// Registrar método de autenticación usado
void metrics_auth_method_used(uint8_t auth_method, bool success, const char *username);

// Registrar tipo de request
void metrics_request_type(uint8_t address_type);

// Registrar error específico
void metrics_error_occurred(uint8_t error_type);

// Registrar bytes transferidos
void metrics_bytes_transferred(uint64_t from_client, uint64_t to_client, 
                              uint64_t from_remote, uint64_t to_remote);

// === Funciones para obtener métricas ===

// Obtener snapshot completo de métricas (thread-safe)
struct socks5_metrics metrics_get_snapshot(void);

// Obtener métricas específicas
uint64_t metrics_get_total_connections(void);
uint64_t metrics_get_current_connections(void);
uint64_t metrics_get_total_bytes(void);
double metrics_get_current_throughput(void);
uint64_t metrics_get_connections_per_minute(void);

// === Funciones de utilidad ===

// Resetear todas las métricas
void metrics_reset(void);

// Obtener tiempo de uptime del servidor en segundos
uint64_t metrics_get_uptime_seconds(void);

// Imprimir resumen de métricas
void metrics_print_summary(void);

// Obtener métricas en formato JSON (para APIs)
char* metrics_to_json(void);

// Constantes para tipos de error
#define METRICS_ERROR_DNS_RESOLUTION     1
#define METRICS_ERROR_CONNECTION_REFUSED 2
#define METRICS_ERROR_NETWORK_UNREACHABLE 3
#define METRICS_ERROR_GENERAL           4

#endif
