#!/bin/bash

echo "=== TESTING SOCKS5 ADDRESS BINDING ==="

# Función para probar una configuración
test_config() {
    local socks_addr="$1"
    local mgmt_addr="$2"
    local test_name="$3"

    echo ""
    echo "--- Test: $test_name ---"
    echo "SOCKS: $socks_addr:9090"
    echo "Management: $mgmt_addr:8080"

    # Iniciar servidor en background, redirigiendo stdout
    ./bin/socks5 -l "$socks_addr" -p 9090 -L "$mgmt_addr" -P 8080 -u test:123 > /dev/null &
    SERVER_PID=$!

    # Esperar que inicie
    sleep 2

    # Verificar que está escuchando
    echo "Verificando puertos..."
    if netstat -ln | grep -q ":9090.*LISTEN"; then
        echo "Puerto SOCKS 9090 está escuchando"
    else
        echo "Puerto SOCKS 9090 NO está escuchando"
    fi

    if netstat -ln | grep -q ":8080.*LISTEN"; then
        echo "Puerto Management 8080 está escuchando"
    else
        echo "Puerto Management 8080 NO está escuchando"
    fi

    # Probar conexión admin
    echo "Probando conexión admin..."
    timeout 5 ./bin/client "$mgmt_addr" 8080 <<EOF
admin123
9
EOF

    if [ $? -eq 0 ]; then
        echo "Conexión admin exitosa"
    else
        echo "Conexión admin falló"
    fi

    # Terminar servidor
    kill $SERVER_PID 2>/dev/null
    wait $SERVER_PID 2>/dev/null

    echo "Servidor terminado"
    sleep 1
}

# Tests adaptados a tu máquina
test_config "127.0.0.1" "127.0.0.1" "Loopback IPv4"
test_config "0.0.0.0" "0.0.0.0" "Todas las interfaces IPv4"
test_config "192.168.100.22" "192.168.100.22" "IP de red local (enp3s0)"
test_config "172.17.0.1" "172.17.0.1" "Docker bridge (docker0)"

echo ""
echo "=== TESTING COMPLETADO ==="
