#include "access_logger.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

static FILE *log_file = NULL;

bool access_logger_init(const char *log_file_path) {
    if (log_file_path == NULL) {
        log_file = stdout; // Si no se especifica un archivo, se usa stdout
    } else {
        log_file = fopen(log_file_path, "a");
        if (log_file == NULL) {
            return false;
        }
    }
    return true;
}

void access_logger_close(void) {
    if (log_file != NULL && log_file != stdout) {
        fclose(log_file);
    }
}

void access_log(struct access_log_info *info) {
    if (log_file == NULL) {
        return;
    }

    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%SZ", localtime(&info->timestamp));

    fprintf(log_file, "%s\t%s\tA\t%s\t%d\t%s\t%d\t%s\n",
            time_str,
            info->username,
            info->client_ip,
            info->client_port,
            info->target_host,
            info->target_port,
            info->status);
    fflush(log_file);
}
