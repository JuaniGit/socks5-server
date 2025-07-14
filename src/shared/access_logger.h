#ifndef ACCESS_LOGGER_H
#define ACCESS_LOGGER_H

#include <stdbool.h>
#include <time.h>

// Estructura para la información de registro de acceso
struct access_log_info {
    time_t timestamp;
    char username[256];
    char client_ip[46];
    int client_port;
    char target_host[256];
    int target_port;
    char status[256];
};

// Inicializa el logger de acceso
bool access_logger_init(const char *log_file_path);

// Cierra el logger de acceso
void access_logger_close(void);

// Registra una entrada de acceso
void access_log(struct access_log_info *info);

#endif // ACCESS_LOGGER_H
