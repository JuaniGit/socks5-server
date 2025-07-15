#include "config.h"
#include "../shared/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#define SOCKS_PORT 1080
#define MANAGEMENT_PORT 8080

void config_init(struct server_config *config) {
    memset(config, 0, sizeof(*config));
    
    // defaults
    strcpy(config->socks_address, "0.0.0.0");         // todas las interfaces
    strcpy(config->management_address, "127.0.0.1");  // solo loopback
    config->socks_port = SOCKS_PORT;                
    config->management_port = MANAGEMENT_PORT;     
    config->cli_users_count = 0;
    config->show_help = false;
    config->show_version = false;
    config->access_log_enabled = true;
    config->password_log_enabled = true;
    
    log(INFO, "%s", "Configuración inicializada con valores por defecto");
}

void config_show_help(const char *program_name) {
    printf("NOMBRE\n");
    printf("       %s - proxy SOCKS versión 5 con esteroides\n\n", program_name);
    
    printf("SINOPSIS\n");
    printf("       %s [ POSIX style options ]\n\n", program_name);
    
    printf("OPCIONES\n");
    printf("       -h     Imprime la ayuda y termina.\n");
    printf("       -l dirección-socks\n");
    printf("              Establece la dirección donde servirá el proxy SOCKS. Por\n");
    printf("              defecto escucha en todas las interfaces.\n");
    printf("       -L dirección-de-management\n");
    printf("              Establece la dirección donde servirá el servicio de management.\n");
    printf("              Por defecto escucha únicamente en loopback.\n");
    printf("       -p puerto-local\n");
    printf("              Puerto TCP donde escuchará por conexiones entrantes SOCKS. Por\n");
    printf("              defecto el valor es 1080.\n");
    printf("       -P puerto-conf\n");
    printf("              Puerto donde escuchará por conexiones entrante del protocolo de\n");
    printf("              configuración. Por defecto el valor es 8080.\n");
    printf("       -u user:pass\n");
    printf("              Declara un usuario del proxy con su contraseña. Se puede\n");
    printf("              utilizar hasta 10 veces.\n");
    printf("       -a archivo-log\n");
    printf("              Archivo donde se registrarán los accesos. Por defecto, se\n");
    printf("              imprime en la salida estándar.\n");
    printf("       -v     Imprime información sobre la versión y termina.\n\n");
    
    printf("EJEMPLOS\n");
    printf("       %s -p 1080 -P 8080\n", program_name);
    printf("       %s -l 192.168.1.100 -u alice:wonderland -u bob:builder\n", program_name);
    printf("       %s -L 0.0.0.0\n", program_name);
}

void config_show_version(void) {
    printf("socks5d versión 1.0.0\n");
    printf("Proxy SOCKS5 con funcionalidades avanzadas\n");
    printf("Desarrollado para Protocolos de Comunicación - ITBA 2025\n");
}

int config_add_cli_user(struct server_config *config, const char *user_pass) {
    if (config->cli_users_count >= MAX_USERS_CLI) {
        log(ERROR, "Máximo de usuarios por línea de comandos alcanzado (%d)", MAX_USERS_CLI);
        return -1;
    }
    
    const char *colon = strchr(user_pass, ':');
    if (!colon) {
        log(ERROR, "%s", "Formato inválido para usuario. Use: usuario:contraseña");
        return -1;
    }
    
    size_t username_len = colon - user_pass;
    size_t password_len = strlen(colon + 1);
    
    if (username_len == 0 || password_len == 0) {
        log(ERROR, "%s", "Usuario y contraseña no pueden estar vacíos");
        return -1;
    }
    
    if (username_len >= 255 || password_len >= 255) {
        log(ERROR, "%s", "Usuario o contraseña demasiado largos");
        return -1;
    }
    
    CliUsers *user = &config->cli_users[config->cli_users_count];
    strncpy(user->username, user_pass, username_len);
    user->username[username_len] = '\0';
    strcpy(user->password, colon + 1);
    user->used = true;
    
    config->cli_users_count++;
    
    log(INFO, "Usuario agregado desde línea de comandos: %s", user->username);
    return 0;
}

int config_parse_args(struct server_config *config, int argc, char *argv[]) {
    int opt;
    
    while ((opt = getopt(argc, argv, "hl:NL:p:P:u:va:")) != -1) {
        switch (opt) {
            case 'h':
                config->show_help = true;
                break;
                
            case 'l':
                strncpy(config->socks_address, optarg, MAX_ADDRESS_LEN - 1);
                config->socks_address[MAX_ADDRESS_LEN - 1] = '\0';
                log(INFO, "Dirección SOCKS configurada: %s", config->socks_address);
                break;
                
            case 'L':
                strncpy(config->management_address, optarg, MAX_ADDRESS_LEN - 1);
                config->management_address[MAX_ADDRESS_LEN - 1] = '\0';
                log(INFO, "Dirección de management configurada: %s", config->management_address);
                break;
                
            case 'p':
                config->socks_port = atoi(optarg);
                if (config->socks_port <= 0 || config->socks_port > 65535) {
                    log(ERROR, "Puerto SOCKS inválido: %d", config->socks_port);
                    return -1;
                }
                log(INFO, "Puerto SOCKS configurado: %d", config->socks_port);
                break;
                
            case 'P':
                config->management_port = atoi(optarg);
                if (config->management_port <= 0 || config->management_port > 65535) {
                    log(ERROR, "Puerto de management inválido: %d", config->management_port);
                    return -1;
                }
                log(INFO, "Puerto de management configurado: %d", config->management_port);
                break;
                
            case 'u':
                if (config_add_cli_user(config, optarg) < 0) {
                    return -1;
                }
                break;
                
            case 'v':
                config->show_version = true;
                break;

            case 'a':
                strncpy(config->access_log_file, optarg, MAX_ADDRESS_LEN - 1);
                config->access_log_file[MAX_ADDRESS_LEN - 1] = '\0';
                config->access_log_enabled = true;
                break;
                
            case '?':
                log(ERROR, "Opción desconocida: -%c", optopt);
                return -1;
                
            default:
                log(ERROR, "%s", "Error parseando argumentos");
                return -1;
        }
    }
    
    return 0;
}
