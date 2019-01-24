#ifndef __TRAFFIC_H__
#define __TRAFFIC_H__

typedef struct traffic_record_s {
    unsigned int ip;
    unsigned int cnt;
} Traffic_record_t;

void traffic_add(unsigned int ip);
int traffic_init(FILE *fd, Traffic_record_t *rec_ptr, unsigned int start_iface_ips_num);

#endif // __TRAFFIC_H__