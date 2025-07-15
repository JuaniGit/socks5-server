/**
 * stm.c - pequeño motor de maquina de estados donde los eventos son los
 *         del selector.c
 */
#include <stdlib.h>
#include "stm.h"
#include <stdio.h>
#include "selector.h"
#include "server/connection.h"
#include "admin_server/admin_protocol.h"

struct selector_key *key;

#define N(x) (sizeof(x)/sizeof((x)[0]))

void
stm_init(struct state_machine *stm) {
    // verificamos que los estados son correlativos, y que están bien asignados.
    for(unsigned i = 0 ; i <= stm->max_state; i++) {
        if(i != stm->states[i].state) {
            abort();
        }
    }

    if(stm->initial < stm->max_state) {
        stm->current = NULL;
    } else {
        abort();
    }
}

inline static void
handle_first(struct state_machine *stm, struct selector_key *key) {
    if(stm->current == NULL) {
        stm->current = stm->states + stm->initial;
        if(NULL != stm->current->on_arrival) {
            stm->current->on_arrival(stm->current->state, key);
        }
    }
}

inline static
void jump(struct state_machine *stm, unsigned next, struct selector_key *key) {
    if(next > stm->max_state) {
        abort();
    }
    if(stm->current != stm->states + next) {
        if(stm->current != NULL && stm->current->on_departure != NULL) {
            stm->current->on_departure(stm->current->state, key);
        }
        stm->current = stm->states + next;

        if(NULL != stm->current->on_arrival) {
            stm->current->on_arrival(stm->current->state, key);
        }
    }
}

unsigned
stm_handler_read(struct state_machine *stm, struct selector_key* key) {
    handle_first(stm, key);

    unsigned current_state = stm->current->state;
    unsigned next_state;

    if (stm->current->on_read_ready == NULL) {
        abort(); 
    }

    next_state = stm->current->on_read_ready(key);

    while (next_state != current_state) {
        unsigned max_state = stm->max_state;
        jump(stm, next_state, key);

        if (key->data == NULL || next_state == max_state) {
            return next_state;
        }

        stm = &((struct socks5_connection *) key->data)->stm;
        current_state = stm->current->state;

        if (stm->current->on_read_ready == NULL) break;

        next_state = stm->current->on_read_ready(key);
    }

    return next_state;
}

unsigned
stm_handler_read_admin(struct state_machine *stm, struct selector_key *key) {
    handle_first(stm, key);

    if (key == NULL || key->data == NULL) return stm->max_state;

    unsigned current_state = stm->current ? stm->current->state : stm->max_state;
    unsigned ret = current_state;
    unsigned max_state = stm->max_state; // Guardamos max_state ANTES de cualquier jump()

    do {
        if (stm == NULL || stm->current == NULL || stm->current->on_read_ready == NULL) {
            break;
        }

        ret = stm->current->on_read_ready(key);

        if (ret == current_state) break;

        jump(stm, ret, key);

        // CRÍTICO: Después de jump(), verificar inmediatamente si la conexión sigue válida
        // porque jump() puede haber destruido la conexión en on_arrival/on_departure
        if (key == NULL || key->data == NULL) {
            return ret;
        }

        // Verificar si llegamos al estado final usando la variable guardada
        if (ret >= max_state) {
            return ret;
        }

        // Obtener nueva referencia a stm SOLO si la conexión sigue válida
        struct admin_connection *admin_conn = (struct admin_connection *) key->data;
        if (admin_conn == NULL) {
            return ret;
        }

        stm = &admin_conn->stm;
        
        // Verificar que la nueva stm es válida
        if (stm == NULL || stm->current == NULL) {
            return ret;
        }

        current_state = stm->current->state;

    } while (stm->current && stm->current->on_read_ready != NULL);

    return ret;
}

unsigned
stm_handler_write(struct state_machine *stm, struct selector_key *key) {
    handle_first(stm, key);
    if(stm->current->on_write_ready == 0) {
        abort();
    }
    const unsigned int ret = stm->current->on_write_ready(key);
    jump(stm, ret, key);

    return ret;
}

unsigned
stm_handler_block(struct state_machine *stm, struct selector_key *key) {
    handle_first(stm, key);
    if(stm->current->on_block_ready == 0) {
        abort();
    }
    const unsigned int ret = stm->current->on_block_ready(key);
    jump(stm, ret, key);

    return ret;
}

void
stm_handler_close(struct state_machine *stm, struct selector_key *key) {
    if(stm->current != NULL && stm->current->on_departure != NULL) {
        stm->current->on_departure(stm->current->state, key);
    }
}

unsigned
stm_state(struct state_machine *stm) {
    unsigned ret = stm->initial;
    if(stm->current != NULL) {
        ret= stm->current->state;
    }
    return ret;
}