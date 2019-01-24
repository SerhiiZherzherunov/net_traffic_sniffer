#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "help.h"
#include "traffic.h"

static Traffic_record_t *tr;
static FILE *stat_fd;
static unsigned int ips_num;

int traffic_init(FILE *fd, Traffic_record_t *rec_ptr, unsigned int start_iface_ips_num)
{
    stat_fd = fd;
    ips_num = start_iface_ips_num;
    tr = ips_num ? rec_ptr : NULL;
}

// Shifts right records for a one record freeing up space for a new one.
void insert_new_ip(unsigned int index, unsigned int records_num)
{
    for(long i = records_num - 1, j = i - 1; j >= index ; i--, j--)
    {
        tr[i].ip = tr[j].ip;
        tr[i].cnt = tr[j].cnt;
    }
}

int ip_find(unsigned int ip, unsigned int *offset)
{
    long mid = 0;
    long left = 0;
    long right = ips_num - 1;

    *offset = 0;
    if(tr == NULL)
        return 0;

    while(left <= right) {
        mid = left + (right - left) / 2;

        if (ip < tr[mid].ip) {
            *offset = mid;
            right = mid - 1;
        }
        else if (ip > tr[mid].ip) {
            *offset = mid + 1;
            left = mid + 1;
        }
        else {
            *offset = mid;
            return 1;
        }
    }

    return 0;
}

// Increases packet counter by ip,
// If record for current ip doesn't exist, adds new one ip record to sorted array
void traffic_add(unsigned int ip)
{
    unsigned int offset;
    Traffic_record_t *new_tr;

    ip = ntohl(ip);
    //write_log("\nip=%.8X\n", ip);

    if( !ip_find(ip, &offset) ) {
        new_tr = (Traffic_record_t*)realloc(tr, ++ips_num * sizeof(Traffic_record_t));
        if (new_tr != NULL) {
            tr = new_tr;

            insert_new_ip(offset, ips_num);
            tr[offset].ip = ip;
            tr[offset].cnt = 0;

            fseek(stat_fd, 0, SEEK_SET);
            if(fwrite(tr, ips_num * sizeof(Traffic_record_t), 1, stat_fd) < 1)
                write_log("traffic all records write error");
            fflush(stat_fd);

        } else {
            free(tr);
            fclose(stat_fd);
            write_log("Memory allocation error\n");
            exit(1);
        }
    }
    tr[offset].cnt++;

//    fseek(stat_fd, 0, SEEK_SET);
//    if(fwrite(tr, ips_num * sizeof(Traffic_record_t), 1, stat_fd) < 1)
//        write_log("traffic all record write error");
//    write_log("ips_num=%d\n",ips_num);

    fseek(stat_fd, offset * sizeof(Traffic_record_t), SEEK_SET);
    if(fwrite(&tr[offset], sizeof(Traffic_record_t), 1, stat_fd) < 1)
        write_log("traffic one record write error!");
    fflush(stat_fd);

}
