#ifndef USERS_H
#define USERS_H

#include <stdbool.h>
#include <stddef.h>

#define MAX_USERNAME_LEN 255
#define MAX_PASSWORD_LEN 255
#define MAX_USERS 100
#define USERS_CSV_FILE "users.csv"

struct user_credentials {
    char username[MAX_USERNAME_LEN + 1];
    char password[MAX_PASSWORD_LEN + 1];
    bool active;
};

extern struct user_credentials users_db[MAX_USERS];
extern size_t users_count;

bool users_init(const char *csv_file);
bool users_validate(const char *username, const char *password);
bool users_add(const char *username, const char *password);
bool users_remove(const char *username);
size_t users_list(struct user_credentials *output, size_t max_count);
const char* users_get_welcome_message(void);

#endif
