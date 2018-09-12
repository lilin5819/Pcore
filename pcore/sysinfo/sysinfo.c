#define _GNU_SOURCE
#include <sys/sysinfo.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/types.h>
#include <netinet/in.h> 
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/ether.h> 
#include "sysinfo.h"
#include "log.h"

#undef MALLOC
#undef FREE
#undef strupr
#undef strlwr

#define MALLOC malloc

#define FREE(P)      \
    do                      \
    {                       \
        if (P)         \
            free(P); \
        P = NULL;      \
    } while (0)

#ifndef FCLOSE
#define FCLOSE(stream)      \
    do                      \
    {                       \
        if (stream)         \
            fclose(stream); \
        stream = NULL;      \
    } while (0)
#endif

#ifndef CONTAINER_OF
#define CONTAINER_OF(ptr, type, field)                                        \
  ((type *) ((char *) (ptr) - ((char *) &((type *) 0)->field)))
#endif

#ifndef container_of
#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

static inline void strip_r(char *str)
{
    if(!str) return ;
    char *p = str + strlen(str) - 1;
    while(*p == ' ' || *p == '\r' || *p == '\n' || *p == '\t')
    {
        *p = '\0';
        p--;
    }
}

char* strupr(char *str)
{
    int i = 0;
    if(!str) return NULL;
    for(i = 0 ;i < strlen(str);i++)
        str[i] = toupper(str[i]);
    return str;
}

char* strlwr(char *str)
{
    int i = 0;
    if(!str) return NULL;
    for(i = 0 ;i < strlen(str);i++)
        str[i] = tolower(str[i]);
    return str;
}
/**
 * AUTH: lilin
 * github: https://github.com/lilin5819/sysinfo
 * email: 1657301947@qq.com
 */

long get_uptime()
{
    struct sysinfo info;
    if(-1 == sysinfo(&info))
        return 0;

    return info.uptime;        
}
//KB
unsigned long get_totalram()
{
    struct sysinfo info;
    if(-1 == sysinfo(&info))
        return 0;

    return info.totalram>>10;    
}
//KB
unsigned long get_freeram()
{
    struct sysinfo info;
    if(-1 == sysinfo(&info))
        return 0;

    return info.freeram>>10;    
}

double get_freeram_rate()
{
    struct sysinfo info;
    if(-1 == sysinfo(&info))
        return 0;

    return 100.0*info.freeram/info.totalram;    
}

unsigned int get_procs()
{
    struct sysinfo info;
    if(-1 == sysinfo(&info))
        return 0;

    return info.procs;  
}

sysinfo_t *get_sysinfo()
{
    struct sysinfo info;
    sysinfo_t *sysinfo_p = NULL;
    if(-1 == sysinfo(&info))
        return NULL;
    
    if(!(sysinfo_p = (sysinfo_t *)MALLOC(sizeof(sysinfo_t)))){
        return NULL;
    }
    sysinfo_p->uptime = info.uptime;
    sysinfo_p->totalram = info.totalram>>10;
    sysinfo_p->freeram = info.freeram>>10;
    sysinfo_p->freeram_rate = 100.0*info.freeram/info.totalram;    
    sysinfo_p->procs = info.procs;

    return sysinfo_p;
}

void print_sysinfo(sysinfo_t *sys)
{
    if(!sys) return;
    printf("uptime:%ld sec\n",sys->uptime);
    printf("totalram:%lu KB\n",sys->totalram);
    printf("freeram:%lu KB\n",sys->freeram);
    printf("freeram_rate:%.2f%%\n",sys->freeram_rate);
    printf("procs:%u\n",sys->procs);
}

char* get_file_value(char *filename)
{
    FILE *stream = NULL;
    char *line = NULL;
    static char value[128] = {0}; 
    ssize_t nread = 0,len = 0;

    if(!filename) return NULL;
    if (!(stream = fopen(filename, "r")) ) {
        perror("fopen");
        goto OUT;
    }

    nread = getline(&line, &len, stream);
    strip_r(line);
    if(nread > 0 && line)
        sprintf(value,"%s",line);

OUT:
    FREE(line);
    FCLOSE(stream);
    return nread > 0 ? value : NULL;
}

char* get_netdev_info(char *ifname,char *item)
{
    char filename[64];
    if(strlen(ifname) > 16 || strlen(item) > 16){
        printf("ifname or item too long\n");
        return NULL;
    }

    sprintf(filename,"/sys/class/net/%s/%s",ifname,item);
    return get_file_value(filename);
}

int cpuinfo_query(char *find_key,cpuinfo_item **item,size_t max)
{
    FILE *stream = NULL;
    char *line = NULL;
    size_t len = 0,nline = 0,nfound = 0;
    ssize_t nread;

    if(!find_key || !item) return 0;
    max = max >= 8 ? 8 : max;
    if(!(*item = (cpuinfo_item *)MALLOC(max * sizeof(cpuinfo_item))) ) {
        perror("MALLOC");
        goto OUT;
    }

    if (!(stream = fopen("/proc/cpuinfo", "r")) ) {
        perror("fopen");
        goto OUT;
    }

    while ((nread = getline(&line, &len, stream)) != -1) {
        if(nread <= 1 ) continue;
        sscanf(line,"%[^:]: %[^\n]",(*item)[nfound].key,(*item)[nfound].value);
        strip_r((*item)[nfound].key);
        if(0 == strcmp((*item)[nfound].key,find_key)){
            // printf("idex=%d key=\"%s\" value=\"%s\"\n",nfound,(*item)[nfound].key,(*item)[nfound].value);
            if(++nfound == max) break;
        }
    }

OUT:
    FREE(line);
    FCLOSE(stream);
    return nfound;
}

int meminfo_query(char *find_key,meminfo_item **item,size_t max)
{
    FILE *stream = NULL;
    char *line = NULL;
    size_t len = 0,nline = 0,nfound = 0;
    ssize_t nread;

    if(!find_key || !item) return 0;
    max = max >= 8 ? 8 : max;
    if(!((*item) = (meminfo_item *)MALLOC(max * sizeof(meminfo_item)))) {
        perror("MALLOC");
        goto OUT;
    }

    if (!(stream = fopen("/proc/meminfo", "r")) ) {
        perror("fopen");
        goto OUT;
    }

    while ((nread = getline(&line, &len, stream)) != -1) {
        if(nline++ == 0 || nread <= 1) continue;
        sscanf(line,"%[^:]: %s %s",(*item)[nfound].key,(*item)[nfound].value,(*item)[nfound].extra);
        if(0 == strcmp((*item)[nfound].key,find_key)){
            // printf("idex=%d key=\"%s\" value=\"%s\" extra=\"%s\"\n",nfound,(*item)[nfound].key,(*item)[nfound].value,(*item)[nfound].extra);
            if(++nfound == max) break;
        }
    }

OUT:
    FREE(line);
    FCLOSE(stream);
    return nfound;
}

int route_query(enum RT_QUERY_TYPE type,char *find_key,route_item **item,size_t max)
{
    FILE *stream = NULL;
    char *line = NULL,*pkey = NULL;
    size_t len = 0,nline = 0,nfound = 0;
    ssize_t nread;

    if(!find_key || !item) return 0;
    max = max >= 8 ? 8 : max;
    if(!((*item) = (route_item *)MALLOC(max * sizeof(route_item)))) {
        perror("MALLOC");
        goto OUT;
    }

    switch (type){
        case  RT_IFNAME:
            pkey = (*item)->ifname;
            break;
        case  RT_DEST:
            pkey = (*item)->dest;
            break;
        case  RT_GATEWAY:
            pkey = (*item)->gateway;
            break;
        case  RT_FLAGS:
            pkey = (*item)->flags;
            break;
        case  RT_METRIC:
            pkey = (*item)->metric;
            break;
        case  RT_MASK:
            pkey = (*item)->mask;
            break;
        default:
            pkey = (*item)->ifname;
            break;
    }
    if (!(stream = fopen("/proc/net/route", "r")) ) {
        perror("fopen");
        goto OUT;
    }

    while ((nread = getline(&line, &len, stream)) != -1) {
        if(nline++ == 0 || nread <= 1) continue;
        sscanf(line,"%s %s %s %s %*s %*s %s %s %*s %*s %*s",
            (*item)[nfound].ifname,(*item)[nfound].dest,(*item)[nfound].gateway,(*item)[nfound].flags,(*item)[nfound].metric,(*item)[nfound].mask);
        if(0 == strcmp(pkey,find_key)){
            // printf("ifname=\"%s\" dest=\"%s\" gateway=\"%s\" flags=\"%s\" metric=\"%s\" mask=\"%s\"\n",
                // (*item)[nfound].ifname,(*item)[nfound].dest,(*item)[nfound].gateway,(*item)[nfound].flags,(*item)[nfound].metric,(*item)[nfound].mask);
            pkey  = pkey + sizeof(route_item);
            if(++nfound == max) break;
        }
    }

OUT:
    FREE(line);
    FCLOSE(stream);
    return nfound;
}


int arp_query(enum ARP_QUERY_TYPE type,char *find_key,arp_item **item,size_t max)
{
    FILE *stream = NULL;
    char *line = NULL,*pkey = NULL;
    size_t len = 0,nline = 0,nfound = 0;
    ssize_t nread;

    if(!find_key || !item) return 0;
    max = max >= 8 ? 8 : max;
    if(!((*item) = (arp_item *)MALLOC(max * sizeof(arp_item)))) {
        perror("MALLOC");
        goto OUT;
    }

    switch (type){
        case  ARP_IP:
            pkey = (*item)->ip;
            break;
        case  ARP_TYPE:
            pkey = (*item)->type;
            break;
        case  ARP_FLAGS:
            pkey = (*item)->flags;
            break;
        case  ARP_MAC:
            pkey = (*item)->mac;
            break;
        default:
            pkey = (*item)->ifname;
            break;
    }
    if (!(stream = fopen("/proc/net/arp", "r")) ) {
        perror("fopen");
        goto OUT;
    }

    while ((nread = getline(&line, &len, stream)) != -1) {
        if(nline++ == 0 || nread <= 1) continue;
        sscanf(line,"%s %s %s %s %*s %s",
            (*item)[nfound].ip,(*item)[nfound].type,(*item)[nfound].flags,(*item)[nfound].mac,(*item)[nfound].ifname);
        if(0 == strcasecmp(pkey,find_key)){
            // printf("ip=\"%s\" type=\"%s\" flags=\"%s\" mac=\"%s\" ifname=\"%s\"\n",
                // (*item)[nfound].ip,(*item)[nfound].type,(*item)[nfound].flags,(*item)[nfound].mac,(*item)[nfound].ifname);
            pkey  = pkey + sizeof(arp_item);
            if(++nfound == max) break;
        }
    }

OUT:
    FREE(line);
    FCLOSE(stream);
    return nfound;
}


// /proc/cpuinfo
// /proc/meminfo
// /proc/net/route
// /proc/net/arp
// /proc/net/dev
// #if 0

int test_get_sysinfo(char *ifname)
{
    int ninfo = 0,i = 0;
    cpuinfo_item *cpu_item = NULL;
    meminfo_item *mem_item = NULL;
    route_item *route_item = NULL;
    arp_item *arp_item = NULL;
    char *value = NULL;

    if(!ifname) return NULL;

    printf("uptime          : %ld\n",get_uptime());//打印从设备开启到现在的时间，单位为秒    
    printf("totalram           : %lu KB\n",get_totalram());//总可用内存大小  
    printf("freeram            : %lu KB\n",get_freeram()); //剩余内存   
    printf("freeram_rate       : %f%%\n",get_freeram_rate());    //进程数
    printf("procs              : %u\n",get_procs());    //进程数

    value = get_netdev_info(ifname,"speed");
    if(value)
        printf("ifname=\"%s\" speed=%s\n",ifname,value);

    value = get_netdev_info(ifname,"mtu");
    if(value)
        printf("ifname=\"%s\" mtu=%s\n",ifname,value);

    value = get_netdev_info(ifname,"mtuc");
    if(value)
        printf("ifname=\"%s\" mtuc=%s\n",ifname,value);

    ninfo = cpuinfo_query("model name",&cpu_item,4);
    for(i=0;i<ninfo;i++)
        printf("key=\"%s\" value=\"%s\"\n",cpu_item[i].key,cpu_item[i].value);

    ninfo = meminfo_query("SwapTotal",&mem_item,4);
    for(i=0;i<ninfo;i++)
        printf("key=\"%s\" value=\"%s\" extra=\"%s\"\n",mem_item[i].key,mem_item[i].value,mem_item[i].extra);
    
    ninfo = route_query(RT_DEST,"00000000",&route_item,4);
    for(i=0;i<ninfo;i++)
        printf("ifname=\"%s\" dest=\"%s\" gateway=\"%s\" flags=\"%s\" metric=\"%s\" mask=\"%s\"\n",
            route_item[i].ifname,route_item[i].dest,route_item[i].gateway,route_item[i].flags,route_item[i].metric,route_item[i].mask);

    ninfo = arp_query(ARP_IFNAME,ifname,&arp_item,4);
    for(i=0;i<ninfo;i++)
        printf("ip=\"%s\" type=\"%s\" flags=\"%s\" mac=\"%s\" ifname=\"%s\"\n",
            arp_item[i].ip,arp_item[i].type,arp_item[i].flags,arp_item[i].mac,arp_item[i].ifname);

    FREE(cpu_item);
    FREE(mem_item);
    FREE(route_item);
    FREE(arp_item);
    return 0;
}

// #endif
char *get_if_info(char *ifname,int cmd)
{
    char *value = NULL;
	int socketfd;

    if(!ifname) return NULL;
    struct ifreq struReq;
    memset(&struReq, 0x00, sizeof(struct ifreq));
    strncpy(struReq.ifr_name, ifname, sizeof(struReq.ifr_name));  
    
    socketfd = socket(PF_INET, SOCK_STREAM, 0);
    if (-1 == ioctl(socketfd, cmd, &struReq)) {
        perror("ioctl");
        return NULL;
    }
    switch (cmd){
        case SIOCGIFHWADDR:
            value = macstr_fmt(ether_ntoa((struct ether_addr*)struReq.ifr_hwaddr.sa_data),":"); 
            break;
        case SIOCGIFADDR:
            value = inet_ntoa(((struct sockaddr_in *)&(struReq.ifr_addr))->sin_addr);
            break;
        case SIOCGIFNETMASK:
            value = inet_ntoa(((struct sockaddr_in *)&(struReq.ifr_netmask))->sin_addr);    
            break;
        default:
            break;
    }
 
    // log_string(value);
    close(socketfd);
 
    return value;   
}

char *get_if_ipstr(char *ifname)
{
	return get_if_info(ifname,SIOCGIFADDR);
}

char *get_if_macstr(char *ifname)
{
    // return get_netdev_info(ifname,"address");
	return get_if_info(ifname,SIOCGIFHWADDR);
}

char *iphex2ipstr(char *iphex)
{
    if(!iphex || !iphex[0])
        return NULL;
    int ng=strtol(iphex,NULL,16);  //16进制
    struct in_addr addr;
    addr.s_addr=ng;
    return inet_ntoa(addr);
}

char *get_gw(void)
{
    int ninfo = 0,i = 0;
    route_item *route_item = NULL;
    struct in_addr addr;
    char *value = NULL;

    ninfo = route_query(RT_DEST,"00000000",&route_item,1);
    // for(i=0;i<ninfo;i++)
        // printf("ifname=\"%s\" dest=\"%s\" gateway=\"%s\" flags=\"%s\" metric=\"%s\" mask=\"%s\"\n",
        //     route_item[i].ifname,route_item[i].dest,route_item[i].gateway,route_item[i].flags,route_item[i].metric,route_item[i].mask);
    if(ninfo){
        value = iphex2ipstr(route_item[0].gateway);
        FREE(route_item);
        return value;
    }
    
    return NULL;
}

char *get_gw_if(void)
{
    int ninfo = 0,i = 0;
    route_item *route_item = NULL;
    struct in_addr addr;
    static char value[32] = {0};

    ninfo = route_query(RT_DEST,"00000000",&route_item,1);
    // for(i=0;i<ninfo;i++)
        // printf("ifname=\"%s\" dest=\"%s\" gateway=\"%s\" flags=\"%s\" metric=\"%s\" mask=\"%s\"\n",
            // route_item[i].ifname,route_item[i].dest,route_item[i].gateway,route_item[i].flags,route_item[i].metric,route_item[i].mask);
    if(ninfo){
        sprintf(value,"%s",route_item[0].ifname);
        FREE(route_item);
        return value;
    }
    
    return NULL;
}

char *get_ipstr_from_macstr(char *macstr)
{
    if(!macstr) return NULL;
    static char ipstr[32] = {0};
    arp_item *arp_item = NULL;
    if(arp_query(ARP_MAC,macstr,&arp_item,1) > 0){
        sprintf(ipstr,"%s",arp_item[0].ip);
        FREE(arp_item);
        return ipstr;
    }
    return NULL;
}

char *get_macstr_from_ipstr(char *ipstr)
{
    if(!ipstr) return NULL;
    static char macstr[32] = {0};
    arp_item *arp_item = NULL;
    if(arp_query(ARP_IP,ipstr,&arp_item,1) > 0){
        sprintf(macstr,"%s",macstr_fmt(arp_item[0].mac,":"));
        FREE(arp_item);
        return macstr;
    }
    return NULL;
}

char *macstr_fmt(char *mac,char *sep)
{
    if(!mac || !sep || strlen(sep) > 4) return NULL;
    char *net_mac = NULL;
    static char out_macstr[64] = {0};
    net_mac = (char *)ether_aton(mac);
    if(!net_mac) return NULL;
    sprintf(out_macstr,"%02X%s%02X%s%02X%s%02X%s%02X%s%02X",
        net_mac[0]&0xff,sep,net_mac[1]&0xff,sep,net_mac[2]&0xff,sep,net_mac[3]&0xff,sep,net_mac[4]&0xff,sep,net_mac[5]&0xff);
    return out_macstr;
}

char *macstr_unfmt(char *mac,char *sep)
{
    if(!mac || !sep || strlen(sep) > 4) return NULL;
    char fmt[64] = {0},net_mac[6] = {0};
    static char out_macstr[64] = {0};
    sprintf(fmt,"%%02X%s%%02X%s%%02X%s%%02X%s%%02X%s%%02X",sep,sep,sep,sep,sep);
    sscanf(mac,fmt,&net_mac[0],&net_mac[1],&net_mac[2],&net_mac[3],&net_mac[4],&net_mac[5]);
    if(!net_mac) return NULL;
    sprintf(out_macstr,"%02X:%02X:%02X:%02X:%02X:%02X",
        net_mac[0]&0xff,net_mac[1]&0xff,net_mac[2]&0xff,net_mac[3]&0xff,net_mac[4]&0xff,net_mac[5]&0xff);
    return out_macstr;
}

void test_all_sysinfo_api(void)
{
    test_get_sysinfo(get_gw_if());
#ifdef _LOG_H_
    log_string(get_gw());
    log_string(get_gw_if());
    log_string(get_if_macstr(get_gw_if()));
    log_string(get_if_ipstr(get_gw_if()));
    log_string(get_if_info(get_gw_if(),SIOCGIFHWADDR));
    log_string(get_if_info(get_gw_if(),SIOCGIFADDR));
    log_string(get_if_info(get_gw_if(),SIOCGIFNETMASK));

    log_string(get_if_ipstr("eth0"));
    log_string(get_if_ipstr("eth1"));
    log_string(get_if_ipstr("enp0s8"));
    log_string(get_if_ipstr("wlan0"));

    log_string(get_ipstr_from_macstr("50:2b:73:ff:9d:81"));
    log_string(get_macstr_from_ipstr("172.16.0.155"));
    log_string(macstr_fmt(get_macstr_from_ipstr("172.16.0.155"),"-"));
    log_string(macstr_unfmt(macstr_fmt(get_macstr_from_ipstr("172.16.0.155"),"-"),"-"));

    log_string(macstr_fmt(get_macstr_from_ipstr("172.16.0.155"),"="));
    log_string(macstr_fmt(get_macstr_from_ipstr("172.16.0.155"),""));
#endif
}