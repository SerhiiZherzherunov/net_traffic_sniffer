#ifndef __PARSE_CMDS_H__
#define __PARSE_CMDS_H__

typedef struct global_args_s {
    int start;
    int stop;
    char *show_ip;
    int check_ip;
    int verbose;
    char *sniff_iface;
    char *stat_iface;
    int stat_iface_show;
    int help;
} Global_args_t;

void parse_command_line(int argc, char *argv[], Global_args_t *ga);

#endif // __PARSE_CMDS_H__
