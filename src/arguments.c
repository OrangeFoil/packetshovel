/**
 * \file    arguments.h
 * \author  Marcus Legendre
 * \brief   Parses the arguments passed from the command line
 */

#include "arguments.h"
#include <argp.h>
#include <stdlib.h>

const char *argp_program_version = "Packet Shovel 0.1-dev";
const char *argp_program_bug_address = "<legendre@stud.fra-uas.de>";
static char doc[] = "Packet Shovel -- Sniffs and interprets IP packets, and "
                    "reports them to an EsperIO CSV socket";
static char args_doc[] = "IP-ADDRESS PORT [INTERFACE]";

static struct argp_option options[] = {
    {"verbose", 'v', 0, OPTION_ARG_OPTIONAL, "Produce verbose output"},
    {"quiet", 'q', 0, OPTION_ARG_OPTIONAL, "Don't produce any output"},
    {"silent", 's', 0, OPTION_ALIAS},
    {0}};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;

    switch (key) {
    case 'a':
        arguments->ip_address = arg;
        break;
    case 'p':
        arguments->port = atoi(arg);
        break;
    case 'q':
    case 's':
        arguments->silent = 1;
        break;
    case 'v':
        arguments->verbose = 1;
        break;
    case 'i':
        arguments->interface = arg;
        break;
    case ARGP_KEY_ARG:
        if (state->arg_num >= 3)
            argp_usage(state); // too many arguments
        if (state->arg_num == 0)
            arguments->ip_address = arg;
        if (state->arg_num == 1)
            arguments->port = atoi(arg);
        if (state->arg_num == 2)
            arguments->interface = arg;
        break;
    case ARGP_KEY_END:
        if (state->arg_num < 2)
            argp_usage(state); // not enough arguments
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

struct argp argp = {options, parse_opt, args_doc, doc};
