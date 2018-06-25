#include <uv.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include "log.h"
#include "core.h"

char *get_if_ipstr(char *ifname) 
{
    char ipstr[32] = {0};
    uv_interface_address_t *info;
    int count, i;

    uv_interface_addresses(&info, &count);
    i = count;

    while (i--) {
        uv_interface_address_t interface = info[i];

        if(!strcmp(interface.name,ifname) && (interface.address.address4.sin_family == AF_INET)){
            uv_ip4_name(&interface.address.address4, ipstr, sizeof(ipstr));
            // log_s(ipstr);
            return strdup(ipstr);
        }
    }

    uv_free_interface_addresses(info, count);
    return NULL;
}

char *get_if_macstr(char *ifname) 
{
    char macstr[32] = {0};
    uv_interface_address_t *info;
    int count, i;

    uv_interface_addresses(&info, &count);
    i = count;

    while (i--) {
        uv_interface_address_t interface = info[i];

        if(!strcmp(interface.name,ifname) && (interface.address.address4.sin_family == AF_INET)){
            sprintf(macstr,"%02X%02X%02X%02X%02X%02X",
            interface.phys_addr[0]&0xff,interface.phys_addr[1]&0xff,interface.phys_addr[2]&0xff,interface.phys_addr[3]&0xff,interface.phys_addr[4]&0xff,interface.phys_addr[5]&0xff);
            return strdup(macstr);
        }
    }

    uv_free_interface_addresses(info, count);
    return NULL;
}

char *get_gw(void)
{
    FILE *f;
    char line[100] , *p , *c, *g, *saveptr;

    f = fopen("/proc/net/route" , "r");
    while(fgets(line , 100 , f))
    {
        p = strtok_r(line , " \t", &saveptr);
        c = strtok_r(NULL , " \t", &saveptr);
        g = strtok_r(NULL , " \t", &saveptr);
        if(p!=NULL && c!=NULL)
        {
            if(strcmp(c , "00000000") == 0)
            {
                if (g)
                {
                    char *pend;
                    int ng=strtol(g,&pend,16);
                    struct in_addr addr;
                    addr.s_addr=ng;
                    return strdup(inet_ntoa(addr));
                }
                break;
            }
        }
    }

    fclose(f);
    return NULL;
}
