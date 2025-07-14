# SOCKS5 Server

This project is a C implementation of a SOCKSv5 proxy server, developed for the Communication Protocols course at ITBA. It features a non-blocking architecture, user authentication, and a run-time administration client.

## Features

*   **SOCKSv5 Protocol Support**: Full compliance with [RFC 1928](https://tools.ietf.org/html/rfc1928).
*   **User Authentication**: Secure access control using Username/Password authentication as per [RFC 1929](https://tools.ietf.org/html/rfc1929).
*   **High Performance**: Built with a non-blocking I/O model using `select()`, ensuring efficient handling of many concurrent connections.
*   **IPv4, IPv6 & FQDN Support**: Capable of handling requests for both IPv4 and IPv6 addresses, as well as FQDNs.
*   **Runtime Administration**: Comes with a separate administration client to monitor and manage the server in real-time without service interruption.
*   **Dynamic Configuration**:
    *   Manage users (add, delete, list).
    *   View live performance metrics.
    *   Adjust server settings like log level and maximum connections on the fly.

## Compilation

To compile the project, you need `make` and a C compiler like `gcc`.

**Build the project:**
    Run the `make` command from the root directory.
    ```sh
    make
    ```

This will generate two executables in the `./bin` directory:
*   `./bin/socks5d`: The SOCKS5 server.
*   `./bin/client`: The administration client.

## Usage

### SOCKS5 Server

To run the server, execute the `socks5d` binary.

```sh
./bin/socks5d [OPTIONS]
```

**Options:**

| Option                  | Description                                                                  | Default       |
| ----------------------- | ---------------------------------------------------------------------------- | ------------- |
| `-h`                    | Show the help message.                                                       | N/A           |
| `-v`                    | Show the server version.                                                     | N/A           |
| `-l <address>`          | The address for the SOCKS5 server to listen on (IPv4 or IPv6).               | `0.0.0.0`     |
| `-p <port>`             | The port for the SOCKS5 server.                                              | `1080`        |
| `-L <address>`          | The address for the administration server to listen on.                      | `127.0.0.1`   |
| `-P <port>`             | The port for the administration server.                                      | `8080`        |
| `-u <user:pass>`        | Add a user for authentication. Can be used multiple times.                   | No users      |

**Example:**

To start the server on port `8080` with two authorized users, `user1` and `user2`:

```sh
./bin/socks5d -p 8080 -u user1:pass1 -u user2:pass2
```

### Administration Client

The administration client connects to the server's management interface to monitor and control it.

```sh
./bin/client <host> <port>
```

**Arguments:**

*   `<host>`: The host where the administration server is running (e.g., `127.0.0.1`).
*   `<port>`: The port of the administration server (e.g., `8080`).

**Example:**

```sh
./bin/client 127.0.0.1 8080
```

Once connected, you can use the following commands:

| Command                 | Description                                                              |
| ----------------------- | ------------------------------------------------------------------------ |
| `help` / `menu`         | Show the list of available commands.                                     |
| `list-users`            | List all configured users.                                               |
| `add <user> <pass>`     | Add a new user.                                                          |
| `del <user>`            | Delete a user.                                                           |
| `metrics`               | Show current server metrics (connections, bytes transferred, etc.).      |
| `set-log <level>`       | Change the log level (`0`:DEBUG, `1`:INFO, `2`:ERROR, `3`:FATAL).        |
| `set-max <num>`         | Set the maximum number of concurrent connections.                        |
| `clear`                 | Clear the screen.                                                        |
| `quit` / `exit`         | Exit the client.                                                         |

## Project Structure

```
.
├── bin/              # Compiled binaries
├── obj/              # Compiled object files
├── src/              # Source code
│   ├── admin_client/ # Administration client source
│   ├── admin_server/ # Administration server source
│   ├── server/       # SOCKS5 server source
│   ├── shared/       # Shared code (logger, metrics, etc.)
│   └── test/         # Test files
├── Makefile          # Main Makefile
├── Makefile.inc      # Makefile include for configuration
├── README.md         # This file
└── ...
```
