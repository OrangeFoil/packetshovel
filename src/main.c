#include "esper_socket.h"
#include "sniffer.h"

int main(int argc, char *argv[]) {
    if (argc < 3 || argc > 4) {
        printf("Syntax is: %s IP-Address Port [Interface]\n", argv[0]);
        return -1;
    }

    // connect to EsperCEP
    int port;
    sscanf(argv[2], "%d", &port);
    esper_socket = esper_connect(argv[1], port);

    // sniffing
    char *dev = NULL;
    if (argc == 4) {
        dev = argv[3];
    }
    sniffer_start(dev);

    // disconnect EsperCEP
    esper_disconnect();
    return 0;
}
