#include "esper_socket.h"
#include "arguments.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

int esper_socket;

int esper_connect(char *ip, int port) {
    int socket_desc;
    struct sockaddr_in server;

    // Create socket
    socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_desc == -1) {
        if (!arguments.silent)
            printf("Unable to create socket\n");
    }

    server.sin_addr.s_addr = inet_addr(ip);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    // Connect to remote server
    if (connect(socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0) {
        if (!arguments.silent)
            printf("Connection to EsperCEP failed\n");
        exit(EXIT_FAILURE);
        return 1;
    }

    if (!arguments.silent)
        printf("Connected to EsperCEP (%s:%i)\n", ip, port);
    return socket_desc;
}

void esper_disconnect() {
    close(esper_socket);
}