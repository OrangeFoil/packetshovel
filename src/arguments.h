/**
 * \file    arguments.h
 * \author  Marcus Legendre
 * \brief   Provides a struct holding the arguments passed from the command line
 */

#pragma once
#include <argp.h>

struct arguments {
    char *ip_address;
    int port;
    int silent, verbose;
    char *interface;
};

struct arguments arguments;
struct argp argp;