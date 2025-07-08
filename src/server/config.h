#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>
#include <netinet/in.h>

#define MAX_USERS_CLI 10
#define MAX_ADDRESS_LEN 256

typedef struct CliUsers {
    char username[256];
    char password[256];
    bool used;
} CliUsers;

struct server_config {
    // Direcciones y puertos
    char socks_address[MAX_ADDRESS_LEN];     // -l dirección-socks
    char management_address[MAX_ADDRESS_LEN]; // -L dirección-de-management
    int socks_port;                          // -p puerto-local (default 1080)
    int management_port;                     // -P puerto-conf (default 8080)
    
    // Usuarios desde línea de comandos
    CliUsers cli_users[MAX_USERS_CLI];              // -u user:pass
    int cli_users_count;
    
    // Flags
    bool show_help;                          // -h
    bool show_version;                       // -v
    
    // Logging
    bool access_log_enabled;
    bool password_log_enabled;
};

// Inicializar configuración con valores por defecto
void config_init(struct server_config *config);

// Parsear argumentos de línea de comandos
int config_parse_args(struct server_config *config, int argc, char *argv[]);

// Mostrar ayuda
void config_show_help(const char *program_name);

// Mostrar versión
void config_show_version(void);

// Agregar usuario desde línea de comandos
int config_add_cli_user(struct server_config *config, const char *user_pass);

#endif
