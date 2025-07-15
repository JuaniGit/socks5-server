# Servidor SOCKS5

Este proyecto implementa un servidor proxy SOCKSv5 en C, junto con un cliente de administración para la configuración remota.

## Estructura del Repositorio

A continuación se detalla la ubicación de los archivos y directorios más importantes del proyecto:

- **`src/`**: Contiene todo el código fuente del proyecto.
  - **`server/`**: Código específico del servidor SOCKS5.
    - `main.c`: Punto de entrada del servidor.
    - `socks5.c`, `socks5.h`: Lógica central del protocolo SOCKS5.
    - `connection.c`, `connection.h`: Gestión de las conexiones de clientes.
    - `config.c`, `config.h`: Manejo de la configuración del servidor.
  - **`admin_client/`**: Código del cliente de administración.
    - `admin_client.c`: Punto de entrada y lógica del cliente.
  - **`admin_server/`**: Código para el manejo de la configuración remota del servidor.
    - `admin_protocol.c`, `admin_protocol.h`: Implementación del protocolo de administración.
  - **`shared/`**: Módulos de código compartidos entre el servidor y el cliente.
    - `logger.c`, `logger.h`: Funciones para el registro de eventos.
    - `metrics.c`, `metrics.h`: Funciones para la recolección de métricas.
    - `users.c`, `users.h`: Gestión de usuarios y autenticación.
- **`docs/`**:
  - `Informe.pdf`: Documentación detallada del proyecto.
- **`Makefile`**: Script principal para la compilación del proyecto.
- **`socks5d.8`**: Documento de manual en formato `man` para el ejecutable del servidor.
- **`users.csv`**: Archivo de ejemplo con formato `user:pass` para la definición de usuarios.
- **`README.md`**: Este mismo archivo.

## Compilación

Para compilar el servidor y el cliente, simplemente ejecute el siguiente comando en la raíz del proyecto:

```bash
make
```

Este comando generará los ejecutables en el directorio `bin/`.

### Artefactos Generados

Los archivos ejecutables generados se encontrarán en las siguientes rutas:

- **Servidor SOCKS5**: `bin/socks5d`
- **Cliente de Administración**: `bin/client`

Para eliminar los archivos generados por la compilación, puede ejecutar:

```bash
make clean
```

## Ejecución

### Servidor SOCKS5

El servidor se ejecuta a través del binario `socks5d`. A continuación se muestran las opciones disponibles:

```bash
./bin/socks5d [OPCIONES]
```

**Opciones:**

- **-h**: Muestra la ayuda y termina.
- **-l *dirección-socks***: Establece la dirección donde servirá el proxy SOCKS. Por defecto, escucha en todas las interfaces.
- **-L *dirección-de-management***: Establece la dirección donde servirá el servicio de management. Por defecto, escucha únicamente en loopback.
- **-p *puerto-local***: Puerto TCP donde escuchará por conexiones entrantes SOCKS. El valor por defecto es `1080`.
- **-P *puerto-conf***: Puerto donde escuchará por conexiones entrantes del protocolo de configuración. El valor por defecto es `8080`.
- **-u *user:pass***: Declara un usuario del proxy con su contraseña. Se puede utilizar hasta 10 veces.
- **-v**: Muestra información sobre la versión y termina.

**Ejemplos de uso:**

```bash
# Ejecutar el servidor en la dirección 0.0.0.0, puerto 1080, con un usuario "admin" y contraseña "admin"
./bin/socks5d -l 0.0.0.0 -p 1080 -u admin:admin

# Ejecutar el servidor con dos usuarios diferentes
./bin/socks5d -u user1:pass1 -u user2:pass2
```

### Cliente de Administración

El cliente de administración se utiliza para configurar el servidor de forma remota. Su uso se detalla en el `Informe.pdf`.