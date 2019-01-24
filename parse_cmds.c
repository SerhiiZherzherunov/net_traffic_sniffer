#include <getopt.h>
#include <stddef.h>
#include "parse_cmds.h"

static const char *opts_string = "RPo:vi:s:h?";

static const struct option parse_opts[] = {
    { "start",   no_argument,       NULL, 'R' },
    { "stop",    no_argument,       NULL, 'P' },
    { "show",    optional_argument, NULL, 'o' },
    { "verbose", no_argument,       NULL, 'v' },
    { "iface",   required_argument, NULL, 'i' },
    { "stat",    optional_argument, NULL, 's' },
    { "help",    no_argument,       NULL, 'h' },
    { NULL,      no_argument,       NULL,  0  }
};

void parse_command_line(int argc, char *argv[], Global_args_t *ga)
{
  int opt = 0;
  int opt_index;

  while (1) {
    opt = getopt_long(argc, argv, opts_string, parse_opts, &opt_index);
    switch(opt) {
        case 'R':
            ga->start = 1;
            break;
        case 'P':
            ga->stop = 1;
            break;
        case 'o':
            ga->show_ip = optarg;
            ga->check_ip = 1;
            break;
        case 'v':
            ga->verbose = 1;
            break;
        case 'i':
            ga->sniff_iface = optarg;
            break;
        case 's':
            ga->stat_iface = optarg;
            ga->stat_iface_show = 1;
            break;
        case 'h':   // break is absent intentionally
        case '?':
            ga->help = 1;
            break;
        case -1:
            return;
        default:
            break;
    }
  }
}
