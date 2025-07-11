#include "users.h"
#include "../shared/logger.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Base de datos de usuarios en memoria
struct user_credentials users_db[MAX_USERS];
size_t users_count = 0;

bool users_init(const char *csv_file) {
    users_count = 0;
    
    if (!csv_file) {
        csv_file = USERS_CSV_FILE;
    }
    
    FILE *file = fopen(csv_file, "r");
    if (!file) {
        log(ERROR, "No se pudo abrir archivo de usuarios: %s", csv_file);
        return false;
    }
    
    char line[512];
    size_t line_num = 0;
    
    while (fgets(line, sizeof(line), file) && users_count < MAX_USERS) {
        line_num++;
        
        line[strcspn(line, "\r\n")] = '\0';
        
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }
        
        char *separator = strchr(line, ';');
        if (!separator) {
            log(ERROR, "Formato inválido en línea %zu del archivo %s", line_num, csv_file);
            continue;
        }
        
        *separator = '\0';
        char *username = line;
        char *password = separator + 1;
        
        if (strlen(username) > MAX_USERNAME_LEN || strlen(password) > MAX_PASSWORD_LEN) {
            log(ERROR, "Usuario o contraseña demasiado largo en línea %zu", line_num);
            continue;
        }
        
        strncpy(users_db[users_count].username, username, MAX_USERNAME_LEN);
        users_db[users_count].username[MAX_USERNAME_LEN] = '\0';
        strncpy(users_db[users_count].password, password, MAX_PASSWORD_LEN);
        users_db[users_count].password[MAX_PASSWORD_LEN] = '\0';
        users_db[users_count].active = true;
        users_count++;
        
        log(DEBUG, "Usuario cargado: %s", username);
    }
    
    fclose(file);
    
    if (users_count == 0) {
        log(ERROR, "No se cargaron usuarios desde %s", csv_file);
        return false;
    }
    
    log(INFO, "Sistema de usuarios inicializado con %zu usuarios desde %s", users_count, csv_file);
    return true;
}

bool users_validate(const char *username, const char *password) {
    if (!username || !password) {
        return false;
    }
    
    for (size_t i = 0; i < users_count; i++) {
        if (users_db[i].active && 
            strcmp(users_db[i].username, username) == 0 &&
            strcmp(users_db[i].password, password) == 0) {
            log(DEBUG, "Usuario '%s' autenticado exitosamente", username);
            return true;
        }
    }
    
    log(INFO, "Intento de autenticación fallido para usuario '%s'", username);
    return false;
}

bool users_add(const char *username, const char *password) {
    if (!username || !password || users_count >= MAX_USERS) {
        return false;
    }
    
    if (strlen(username) > MAX_USERNAME_LEN || strlen(password) > MAX_PASSWORD_LEN) {
        return false;
    }
    
    for (size_t i = 0; i < users_count; i++) {
        if (strcmp(users_db[i].username, username) == 0) {
            // Usuario existe, actualizar contraseña
            strncpy(users_db[i].password, password, MAX_PASSWORD_LEN);
            users_db[i].password[MAX_PASSWORD_LEN] = '\0';
            users_db[i].active = true;
            log(INFO, "Usuario '%s' actualizado", username);
            return true;
        }
    }
    
    strncpy(users_db[users_count].username, username, MAX_USERNAME_LEN);
    users_db[users_count].username[MAX_USERNAME_LEN] = '\0';
    strncpy(users_db[users_count].password, password, MAX_PASSWORD_LEN);
    users_db[users_count].password[MAX_PASSWORD_LEN] = '\0';
    users_db[users_count].active = true;
    users_count++;
    
    log(INFO, "Usuario '%s' agregado exitosamente", username);
    return true;
}

bool users_remove(const char *username) {
    if (!username) {
        return false;
    }
    
    for (size_t i = 0; i < users_count; i++) {
        if (strcmp(users_db[i].username, username) == 0) {
            users_db[i].active = false;
            log(INFO, "Usuario '%s' desactivado", username);
            return true;
        }
    }
    
    return false;
}

size_t users_list(struct user_credentials *output, size_t max_count) {
    if (!output) {
        return 0;
    }
    
    size_t count = 0;
    for (size_t i = 0; i < users_count && count < max_count; i++) {
        if (users_db[i].active) {
            output[count] = users_db[i];
            count++;
        }
    }
    
    return count;
}
