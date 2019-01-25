#ifndef __DAEMON_H__
#define __DAEMON_H__

#include <stdio.h>
#include "traffic.h"

//#define PID_FILE "/var/run/net_traffik_snf.pid"
#define PID_FILE "/tmp/net_traffik_snf.pid"
#define STAT_FILE_PREFIX "net_traffic_"
#define STAT_FILE_EXT ".snf"
#define STAT_FILE_DIR "/etc/net_traffic_snf/"

void daemon_run(void);
int monitor_proc(const char *iface, FILE* f_rec, Traffic_record_t *rec_ptr, int rec_num);

#endif // __DAEMON_H__
