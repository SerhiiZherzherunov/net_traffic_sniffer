#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <signal.h>
#include <dirent.h>
#include "daemon.h"
#include "help.h"
#include "parse_cmds.h"
#include "traffic.h"

void set_pid_file(const char *filename)
{
    FILE* f;

    f = fopen(filename, "w+");
    if(f) {
      fprintf(f, "%u", getpid());
      fclose(f);
    } else {
      write_log("Error open file %s to write pid.\n", filename);
    }
}

int get_pid_from_file(const char *filename, pid_t *pid)
{
    FILE* f;

    f = fopen(filename, "r");
    if(f) {
      fscanf(f, "%u", pid);
      fclose(f);
      write_log("pid from file %u\n", *pid);
      return 1;
    } else {
      write_log("File %s isn't exist.\n", filename);
    }
    return 0;
}

void output_record(Traffic_record_t *tr)
{
    printf("IP: %3.1u.%3.1u.%3.1u.%3.1u   packets: %d\n",
            tr->ip >> 24 & 0xff, tr->ip >> 16 & 0xff, tr->ip >> 8 & 0xff, tr->ip & 0xff, tr->cnt);
}

void stat_file_output(const char *filename, const unsigned int ip, const int check_ip)
{
    FILE *fi;
    size_t file_size;
    Traffic_record_t tr;
    int rec_num;
    int rec_size = sizeof(Traffic_record_t);
    int i;
    int output_rec_cnt = 0;

    if((fi = fopen(filename, "rb")) != NULL) {
        fseek(fi, 0, SEEK_END);
        file_size = ftell(fi);
        fseek(fi, 0, SEEK_SET);
        file_size -= file_size % rec_size;
        rec_num = file_size / rec_size;
        for(i = 0; i < rec_num; i++)
        {
            if(fread(&tr, rec_size, 1, fi) < 1) {
                write_log("Error reading stat file record!\n");
                break;
            }
            if(check_ip && tr.ip == ip || !check_ip) {
                output_record(&tr);
                output_rec_cnt++;
            }
        }
        fclose(fi);
        if(!output_rec_cnt) {
            printf("No record for current IP\n");
        }
    } else {
        printf("sniffer iface file: %s open error!\n", filename);
    }
    printf("\n");
}

void scan_sniffer_stat_files(const char *iface_str, const unsigned int ip, const int check_ip)
{
    DIR *dfd;
    struct dirent *dp;
    int if_len = iface_str == NULL ? 0 : strlen(iface_str);
    int f_name_len = strlen(STAT_FILE_DIR) + strlen(STAT_FILE_PREFIX) + if_len + strlen(STAT_FILE_EXT) + 1;
    char *filename_by_iface = NULL;
    char *filename = NULL;
    char iface[10];
    int stat_files_cnt = 0;

    if(if_len > 0) {
        filename_by_iface = malloc(f_name_len);
        strcpy(filename_by_iface, STAT_FILE_DIR);
        strcat(filename_by_iface, STAT_FILE_PREFIX);
        strcat(filename_by_iface, iface_str);
        strcat(filename_by_iface, STAT_FILE_EXT);
    }

    dfd = opendir(STAT_FILE_DIR);
    while( (dp = readdir(dfd)) != NULL ) {
        if(filename_by_iface != NULL) {
            if(!strncmp(filename_by_iface + strlen(STAT_FILE_DIR), dp->d_name, strlen(dp->d_name))) {
                // found sniffer stat file by iface
                printf("file by iface: %s, iface: %s\n", dp->d_name, iface_str);
                stat_files_cnt++;

                stat_file_output(filename_by_iface, ip, check_ip);
                break;
            }
        } else {
            if(!strncmp(STAT_FILE_PREFIX, dp->d_name, strlen(STAT_FILE_PREFIX))) {
                // found some sniffer stat file (by prefix)
                stat_files_cnt++;
                filename = realloc(filename, strlen(STAT_FILE_DIR) + strlen(dp->d_name) + 1);
                strcpy(filename, STAT_FILE_DIR);
                strcat(filename, dp->d_name);
                if_len = strlen(dp->d_name) - strlen(STAT_FILE_PREFIX) - strlen(STAT_FILE_EXT);
                if(if_len >= sizeof(iface))
                    if_len = sizeof(iface) - 1;
                strncpy(iface, dp->d_name + strlen(STAT_FILE_PREFIX), if_len);
                iface[if_len] = 0;
                printf("file: %s, iface: %s\n", dp->d_name, iface);

                stat_file_output(filename, ip, check_ip);
            }
        }
    }
    if(!stat_files_cnt)
        printf("Stat files not found.\n");
    free(filename_by_iface);
    free(filename);
    closedir(dfd);
}

FILE* get_records_from_iface_file(const char *sniff_iface, Traffic_record_t **tr, int *rec_num)
{
    FILE *fi;
    char *filename;
    size_t file_size = 0;
    int if_len = sniff_iface == NULL ? 0 : strlen(sniff_iface);

    *tr = NULL;
    *rec_num = 0;

    if(if_len > 0) {
        filename = malloc(strlen(STAT_FILE_DIR) + strlen(STAT_FILE_PREFIX) + if_len + strlen(STAT_FILE_EXT) + 1);
        strcpy(filename, STAT_FILE_DIR);
        strcat(filename, STAT_FILE_PREFIX);
        strcat(filename, sniff_iface);
        strcat(filename, STAT_FILE_EXT);
        if((fi = fopen(filename, "rb")) != NULL) {
            write_log("sniffer iface file exists: %s\n", filename);
            fseek(fi, 0, SEEK_END);
            file_size = ftell(fi);
            fseek(fi, 0, SEEK_SET);
            file_size -= file_size % sizeof(Traffic_record_t);
            if(file_size) {
                if((*tr = malloc(file_size)) == NULL) {
                    fclose(fi);
                    free(filename);
                    return NULL;
                }
                *rec_num = file_size / sizeof(Traffic_record_t);
                if(fread(*tr, file_size, 1, fi) < 1) {
                    write_log("Error reading stat file!");
                    free(*tr);
                    *rec_num = 0;
                }
            } else {
                write_log("zero length file\n");
            }
            fclose(fi);
        } else {
            write_log("sniffer iface file: %s not found. New will be created.\n", filename);
        }
        if((fi = fopen(filename, "wb")) == NULL) {
            write_log("Error opening stat file for writing!");
            free(*tr);
            free(filename);
            return NULL;
        }
        write_log("sniffer file: %s\n", filename);
        fwrite(*tr, file_size, 1, fi);
        fflush(fi);
        free(filename);
        return fi;
    }
    write_log("Bad sniff_iface string!");
    return NULL;
}


int main(int argc, char *argv[]) {

    int already_running;
    setbuf(stdout, NULL);
    // Our process ID and Session ID
    pid_t pid, sid;

    // Fill global args struct with command line parameters
    Global_args_t global_args = {
        .stop = 0,
        .start = 0,
        .show_ip = NULL,
        .verbose = 0,
        .sniff_iface = "eth0",
        .stat_iface = NULL,
        .stat_iface_show = 0,
        .help = 0
    };

    parse_command_line(argc, argv, &global_args);
    if (global_args.help)
        print_help();

    logs_output(global_args.verbose);

    write_log("start=%d, stop=%d, show_ip=\"%s\", check_ip=\"%d\", verbose=%d, sniff_iface=\"%s\", stat_iface=\"%s\", stat_show=%d, help=%d\n",
        global_args.start,
        global_args.stop,
        global_args.show_ip,
        global_args.check_ip,
        global_args.verbose,
        global_args.sniff_iface,
        global_args.stat_iface,
        global_args.stat_iface_show,
        global_args.help
      );

    // Check if daemon monitor is runnung
    already_running = get_pid_from_file(PID_FILE, &pid);
    write_log("running = %d\n", already_running);

    if(global_args.stop) {
        if(already_running) {
            kill(pid, SIGQUIT);
        } else {
            printf("[sniffer] wasn't running\n");
        }
    }

    if(opendir(STAT_FILE_DIR) == NULL) {
        mkdir(STAT_FILE_DIR, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    }

    if(global_args.stat_iface_show || global_args.check_ip) {
        unsigned int ip = 0;
        if(global_args.show_ip != NULL) {
            inet_aton(global_args.show_ip, (struct in_addr *) &(ip));
            ip = ntohl(ip);
            write_log("IP from cmd %x\n", ip);
        }
        scan_sniffer_stat_files(global_args.stat_iface, ip, global_args.check_ip);
    }

    if(global_args.start) {
        if(already_running) {
            write_log("[daemon] restarting\n");
            kill(pid, SIGTERM);
        }
        /* Daemon-monitor specific initialization goes here */
            printf("[sniffer] start\n");
            /* Fork off the parent process */
            pid = fork();
            if (pid < 0) {
                exit(EXIT_FAILURE);
            }
            /* If we got a good PID, then
               we can exit the parent process. */
            if (pid > 0) {
                exit(EXIT_SUCCESS);
            }

            /* Change the file mode mask */
            umask(0);

            /* Create a new SID for the child process */
            sid = setsid();
            if (sid < 0) {
                write_log("setsid failure ! Exiting.");
                exit(EXIT_FAILURE);
            }

            /* Change the current working directory */
            if ((chdir("/")) < 0) {
                /* Log the failure */
                exit(EXIT_FAILURE);
            }
            write_log("[monitor] sid=%d\n", sid);
            /* Close out the standard file descriptors */
            close(STDIN_FILENO);
            //close(STDOUT_FILENO);
            //close(STDERR_FILENO);
            // create file with monitor's PID

            Traffic_record_t *rec_ptr;
            int rec_num;
            FILE *fi = get_records_from_iface_file(global_args.sniff_iface, &rec_ptr, &rec_num);

            if(fi != NULL) {
                write_log("set_pid");
                set_pid_file(PID_FILE);
                monitor_proc(global_args.sniff_iface, fi, rec_ptr, rec_num);
            }
            printf("[sniffer] Exit.\n");
    }
    exit(EXIT_SUCCESS);
}
