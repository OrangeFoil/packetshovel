#pragma once
#include <argp.h>

struct arguments {
    char *ip_address;
    int port;
    int silent, verbose;
    char *interface;
};

struct argp argp;