
#ifndef _SYSINFO_H_
#define _SYSINFO_H_
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

/**
 * AUTH: lilin
 * github: https://github.com/lilin5819/sysinfo
 * email: 1657301947@qq.com
 */

//KB
typedef struct sysinfo_t{
    long uptime;
    unsigned long totalram;
    unsigned long freeram;
    float freeram_rate;
    unsigned int procs;
}sysinfo_t;

typedef struct cpuinfo_item{
    char key[32];
    char value[1024];
}cpuinfo_item;

typedef struct meminfo_item{
    char key[32];
    char value[32];
    char extra[8];
}meminfo_item;

typedef struct route_item{
    char ifname[32];
    char dest[32];
    char gateway[32];
    char flags[8];
    char metric[8];
    char mask[32];
}route_item;

enum RT_QUERY_TYPE{
    RT_IFNAME = 0,
    RT_DEST,
    RT_GATEWAY,
    RT_FLAGS,
    RT_METRIC,
    RT_MASK,
};

typedef struct arp_item{
    char ip[32];
    char type[8];
    char flags[8];
    char mac[32];
    char ifname[32];
}arp_item;

enum ARP_QUERY_TYPE{
    ARP_IP = 0,
    ARP_TYPE,
    ARP_FLAGS,
    ARP_MAC,
    ARP_IFNAME,
};

long get_uptime();
unsigned long get_totalram();
unsigned long get_freeram();
double get_freeram_rate();
unsigned int get_procs();

sysinfo_t *get_sysinfo();
void print_sysinfo(sysinfo_t *sys);

char* get_file_value(char *filename);
char* get_netdev_info(char *ifname,char *item);
int cpuinfo_query(char *find_key,cpuinfo_item **item,size_t max);
int meminfo_query(char *find_key,meminfo_item **item,size_t max);
int route_query(enum RT_QUERY_TYPE type,char *find_key,route_item **item,size_t max);
int arp_query(enum ARP_QUERY_TYPE type,char *find_key,arp_item **item,size_t max);


char *iphex2ipstr(char *iphex);
char *get_if_info(char *ifname,int cmd);           // ioctl based
char *get_gw(void);                           // file based
char *get_gw_if(void);
char *get_if_ipstr(char *ifname);
char *get_if_macstr(char *ifname);

char *macstr_fmt(char *mac,char *sep);
char *macstr_unfmt(char *mac,char *sep);

int test_get_sysinfo(char *ifname);
void test_all_sysinfo_api(void);

#endif