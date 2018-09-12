#include "core.h"
#include "env.h"

#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/socket.h>
#include<net/if.h>
#include <sys/types.h>
#include <netinet/in.h> 
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/ether.h> 

#include "sysinfo.h"
#include "log.h"

#ifdef USE_UV_NET_API
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
            // log_string(ipstr);
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
#endif



// TODO: 完善网络检测层，自连自回收，实现勤奋检测和懒惰检测的自动切换和被动切换
void timer_netcheck_cb(uv_timer_t *handle)
{
    pcore_ctx *pcore = container_of(handle, pcore_ctx, timer_netcheck_handle);
    // if(pcore->cfg.mode == ELINK_SERVER_MODE) return;

    // char * ipstr = get_if_ipstr("wlan0");
    // char * macstr = get_if_macstr("wlan0");
    // char * gw = get_gw();

    // if(!ipstr && pcore->client.online == 1){
    //     uv_close((uv_handle_t*)&pcore->client.tcp_handle,close_cb);
    //     pcore->client.online = 0;
    //     return;
    // }
    // if(!gw || pcore->client.online == 1)
    //     return;
    // // log_string(ipstr);
    // // log_string(gw);
    // pcore->client.online = 1;
    // pcore->client.ip = "127.0.0.1";
    // pcore->client.mac = strdup(get_netdev_info(get_gw_if(),"address"));
    // pcore->client.gw = "127.0.0.1";
    // ok(0 == uv_tcp_init(uv_default_loop(), &pcore->client.tcp_handle));
    // ok(0 == uv_ip4_addr("127.0.0.1", ELINK_SERVER_PORT, &pcore->client.addr));
    // ok(0 == uv_tcp_connect(&pcore->client.conn,&pcore->client.tcp_handle,(struct sockaddr *)&pcore->client.addr,on_client_mode_connect));

    test_all_sysinfo_api();
}