#ifndef _ENV_H_
#define _ENV_H_
#include "common.h"
#include "sysinfo.h"
typedef struct env_t
{
    sysinfo_t *sysinfo;
    int nroute;
    route_item *route;
    int narp;
    arp_item *arp;
} env_t;

char *get_if_ipstr(char *ifname);
char *get_if_macstr(char *ifname);
// char *get_gw(void);
void timer_netcheck_cb(uv_timer_t *handle);
#endif