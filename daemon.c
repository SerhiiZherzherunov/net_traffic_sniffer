#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include "daemon.h"
#include "sniffer.h"
#include "help.h"
#include "traffic.h"
#include <linux/if_ether.h>

enum {
  CHILD_NEED_TERMINATE = 101,
  CHILD_NEED_WORK
};

void dump(const unsigned char *data_buffer, const unsigned int length)
{
  unsigned char byte;
  unsigned int i, j;
  for (i = 0; i < length; i++)
  {
    byte = data_buffer[i];
    write_log("%02x ", data_buffer[i]);
    if ((i & 0xF) == 0xF || i == length - 1)
    {
      for (j = 0; j < 15 - (i & 15); j++)
        write_log("  ");
      write_log("| ");
      for (j = (i - (i & 15)); j <= i; j++)
      {
        byte = data_buffer[j];
        if (byte > 31 && byte < 127) {
          write_log("%c", byte);
        }
        else {
          write_log(".");
        }
      }
      write_log("\n");
    }
  }
}

void open_socket()
{
  int i, recv_length, fd;
  unsigned char buffer[10000];
  if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
  {
    perror("-1 return \n");
    return;
  }
  for (i = 0; i < 3; i++)
  {
    recv_length = recv(fd, buffer, 10000, 0);
    write_log("Got a %d byte packet\n", recv_length);
    perror(strerror(errno));
    if (recv_length > 0)
      dump(buffer, recv_length);
  }
}

int sniffer_run(const char *iface)
{
  write_log("sniffer pid %d\n", getpid());

  sniffer *sniffer = sniffer_create(htons(ETH_P_IP)); // htons here is very important!

  write_log("Sniffer created successfully.\n");

  // Initialize the sniffer.
  if (!sniffer_init(sniffer, iface))
  {
      printf("Error: sniffer initialization!\n");
      return CHILD_NEED_TERMINATE;
  }

  // Start to capture and analyze packets;
  sniffer_sniff(sniffer);

  return CHILD_NEED_TERMINATE;
}

int set_fd_limit(int max_fd)
{
  struct rlimit lim;
  int    status;

  // open descriptors limit
  lim.rlim_cur = max_fd;
  // open descriptors max limit
  lim.rlim_max = max_fd;

  status = setrlimit(RLIMIT_NOFILE, &lim);

  return status;
}


static void signal_error(int sig, siginfo_t *si, void *ptr)
{
  write_log("[DAEMON] Signal: %s, Addr: 0x%.16lX\n", strsignal(sig), (unsigned long)(si->si_addr));
  printf("[sniffer] Stopped\n");

  // finish process with restart signal
  exit(CHILD_NEED_WORK);
}

int monitor_proc(const char *iface, FILE* f_rec, Traffic_record_t *rec_ptr, int rec_num)
{
    int      pid;
    int      status;
    int      need_start = 1;
    sigset_t sigset;
    siginfo_t siginfo;
    // configure signals
    sigemptyset(&sigset);

    sigaddset(&sigset, SIGQUIT);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
    sigaddset(&sigset, SIGCHLD);
    sigaddset(&sigset, SIGUSR1);

    sigprocmask(SIG_BLOCK, &sigset, NULL);

    // main loop
    for (;;)
    {
        // if sniffer create needed
        if (need_start)
        {
            // create sniffer
            pid = fork();
        }

        need_start = 1;

        if (pid == -1) // error
        {
            write_log("[MONITOR] Fork failed (%s)\n", strerror(errno));
        }
        else if (!pid) // if daemon
        {
            // starting sniffer
            write_log("[sniffer] starting.\n");
            traffic_init(f_rec, rec_ptr, rec_num);

            status = sniffer_run(iface);
            exit(status);
        }
        else // if parent (monitor)
        {
            fclose(f_rec);
            free(rec_ptr);
            // waiting for signal
            sigwaitinfo(&sigset, &siginfo);
            write_log("[MONITOR] signal received\n");

            // signal from sniffer
            if (siginfo.si_signo == SIGCHLD)
            {
                write_log("[MONITOR] SIGCHLD\n");

                // exit status
                wait(&status);

                // convert status
                status = WEXITSTATUS(status);

                if (status == CHILD_NEED_WORK) // if need to start again
                {
                    write_log("[MONITOR] Child restart\n");
                }
                else //if (status == CHILD_NEED_TERMINATE)
                {
                    write_log("[MONITOR] Child stopped\n");
                    break;
                }
            }
            else if (siginfo.si_signo == SIGUSR1) // if signal from child
            {
                kill(pid, SIGUSR1); // send signal to the child
                need_start = 0; // reset new start flag
            }
            else // if other signal came
            {
                write_log("[MONITOR] Signal %s\n", strsignal(siginfo.si_signo));

                // kill child
                kill(pid, SIGKILL);
                status = 0;
                break;
            }
        }
    }

    write_log("[sniffer] Stop\n");
    // PID file delete
    unlink(PID_FILE);

    return status;
}
