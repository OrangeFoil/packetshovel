#include "esper_socket.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int esper_socket;

int esper_connect(char *ip, int port) {
    int socket_desc;
    struct sockaddr_in server;

    // Create socket
    socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_desc == -1) {
        printf("Unable to create socket\n");
    }

    server.sin_addr.s_addr = inet_addr(ip);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    // Connect to remote server
    if (connect(socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0) {
        printf("Connection to EsperCEP failed\n");
        exit(-1);
        return 1;
    }

    printf("Connected to EsperCEP (%s:%i)\n", ip, port);
    return socket_desc;
}

void esper_disconnect() {
    close(esper_socket);
}