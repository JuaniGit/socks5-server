#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../shared/logger.h"
#include "tcpServerUtil.h"
#include "../selector.h"
#include <signal.h>


// Client tracking information
typedef struct { 
	int client_fd;
} connection_data;


void read_handler(struct selector_key *key) {
	connection_data *data = key->data;
	char buffer[1024];

	ssize_t count = recv(key->fd, buffer, sizeof(buffer), 0);
	if (count <= 0) {
		log(INFO, "client disconnected or error");
		selector_unregister_fd(key->s, key->fd);
		return;
	}

	// Simple echo
	ssize_t sent = send(key->fd, buffer, count, 0);
	if (sent < 0) {
		log(ERROR, "send() failed");
		selector_unregister_fd(key->s, key->fd);
	}
}


void close_handler(struct selector_key *key) {
	connection_data *data = key->data;
	log(DEBUG, "closing connection fd=%d", data->client_fd);
	close(data->client_fd);
	free(data);
}

void accept_handler(struct selector_key *key) {
	struct sockaddr_storage client_addr;
	socklen_t client_len = sizeof(client_addr);
	int client_fd = accept(key->fd, (struct sockaddr *) &client_addr, &client_len);
	if (client_fd < 0) {
		log(ERROR, "accept() failed");
		return;
	}
	log(INFO, "new connection accepted");

	if (selector_fd_set_nio(client_fd) < 0) {
		log(ERROR, "couldn't make client socket non-blocking");
		close(client_fd);
		return;
	}

	connection_data *data = calloc(1, sizeof(connection_data));
	data->client_fd = client_fd;

	fd_handler client_handler = {
		.handle_read = &read_handler,
		.handle_close = &close_handler,
	};

	if (selector_register(key->s, client_fd, &client_handler, OP_READ, data) != SELECTOR_SUCCESS) {
		log(ERROR, "couldn't register client fd with selector");
		free(data);
		close(client_fd);
	}
}


int main(int argc, char *argv[]) {
	if (argc != 2) {
		log(FATAL, "usage: %s <Server Port>", argv[0]);
	}

	char *servPort = argv[1];

	if (selector_init(&(struct selector_init) {
		.signal = SIGALRM,
		.select_timeout = { .tv_sec = 10, .tv_nsec = 0 }
	}) != SELECTOR_SUCCESS) {
		log(FATAL, "could not initialize selector");
		return 1;
	}

	int servSock = setupTCPServerSocket(servPort);
	if (servSock < 0)
		return 1;

	if (selector_fd_set_nio(servSock) < 0) {
		log(ERROR, "couldn't make server socket non-blocking");
		close(servSock);
		return 1;
	}

	fd_selector selector = selector_new(1024);
	if (selector == NULL) {
		log(FATAL, "could not create selector");
		return 1;
	}

	fd_handler server_handler = {
		.handle_read = &accept_handler,
	};

	if (selector_register(selector, servSock, &server_handler, OP_READ, NULL) != SELECTOR_SUCCESS) {
		log(FATAL, "could not register server socket in selector");
		return 1;
	}

	while (true) {
		if (selector_select(selector) != SELECTOR_SUCCESS) {
			log(ERROR, "selector_select failed");
			break;
		}
	}

	selector_destroy(selector);
	selector_close();
	return 0;
}



// int main(int argc, char *argv[]) {
// 	if (argc != 2) {
// 		log(FATAL, "usage: %s <Server Port>", argv[0]);
// 	}

// 	char * servPort = argv[1];

// 	int servSock = setupTCPServerSocket(servPort);
// 	if (servSock < 0 )
// 		return 1;

// 	while (1) { // Run forever
// 		// Wait for a client to connect
// 		int clntSock = acceptTCPConnection(servSock);
// 		if (clntSock < 0) {
// 			log(ERROR, "accept() failed");
// 		} else {
// 			handleTCPEchoClient(clntSock);
// 		}
// 	}
// }
