#include "argument_parser.h"
#include "esper_socket.h"
#include "sniffer.h"

int main(int argc, char *argv[]) {
    // default values and argument parsing
    struct arguments arguments;
    arguments.silent = 0;
    arguments.verbose = 0;
    arguments.interface =
        NULL; // libpcap will try to auto-detect the default interface
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    // connect to EsperCEP
    esper_socket = esper_connect(arguments.ip_address, arguments.port);

    // sniffing
    sniffer_start(arguments.interface);

    // disconnect EsperCEP
    esper_disconnect();
    return 0;
}
