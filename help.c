#include <stdio.h>
#include "help.h"

static int logs_enabled = 0;

void logs_output(int en)
{
  logs_enabled = en;
}

int is_logs(void)
{
  return logs_enabled;
}

void print_help(void)
{
  printf("Usage:\n\
  \tsudo ./net_traffic_snf\n\
  \t--start                  (packets are being sniffed from now on from default iface(eth0))\n\
  \t--stop                   (packets are not sniffed)\n\
  \t--show=[ip] count        (print number of packets received from ip address)\n\
  \tselect --iface=[iface]   (select interface for sniffing eth0, wlan0, ethN, wlanN...)\n\
  \t--stat=[iface]           (show all collected statistics for particular interface, if iface omitted - for all interfaces.)\n\
  \t--verbose                (logs output)\n\
  \t--help                   (show usage information)\n");
}
