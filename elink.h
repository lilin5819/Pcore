#ifndef _ELINK_H_

#include <stdint.h>

// #include"cjson/cJSON.h"
// #include"uv.h"
// #include"server.h"
// #define ELINK_SERVER_PORT 32768
/*
	E-link proto Header struct.
*/
#pragma pack(1)

typedef struct ELINK_HEADER
{
    uint32_t magic;  // Net order, 0x3f721fb5
    uint32_t length; // Net order, length of data after header(not contain head).
    uint8_t data[0];
} ELINK_HEADER_STRU;
#pragma pack()

#define FREE(x)        \
    do                 \
    {                  \
        if (x != NULL) \
        {              \
            free(x);   \
            x = NULL;  \
        }              \
    } while (0);

#define ELINK_MAGIC 0x3f721fb5
#define ELINK_MAGIC_LEN 4
#define ELINK_CONTENT_LEN 4
#define ELINK_HEADER_LEN (ELINK_MAGIC_LEN + ELINK_CONTENT_LEN)

#define ELINKCC_MAGIC 0x43545347574d5032 //CTSGWMP2
#define ELINKCC_MAGIC_LEN 8
#define ELINKCC_HEADER_LEN (ELINKCC_MAGIC_LEN + ELINK_CONTENT_LEN)
#define ELINKCC_TAIL_LEN 2 //\r\n
#define ELINK_MSG_LEN(_len) ((_len) + ELINKCC_HEADER_LEN + ELINKCC_TAIL_LEN)

#define DH_128_KEY_LEN 16
#define ECDH_112_KEY_LEN 14
#define ECDH_112_KEY_SIZE 15

#define AES_128_BLOCK_SIZE 16
#define CKEY_SKEY_LEN 16

#define ELINK_SN_LEN 34

#define ELINK_TIMEOUT_5S 5
#define ELINK_TIMEOUT_10S 10
#define ELINK_TIMEOUT_20S 20

#define UNKNOWN_FD -1

#define ELINK_SERVER_IP "0.0.0.0"
#define ELINK_SERVER_PORT 32768

#if USE_LOCAL_BSS_SERVER
#define DEFAULT_BSS_ADDR "127.0.0.1"
#define DEFAULT_BSS_PORT 6666
#else
#define DEFAULT_BSS_ADDR "apbss1.189cube.com"
#define DEFAULT_BSS_PORT 8088
#endif

#define MOD_16_INTGER(num) (num + (16 - num % 16) % 16)

/*
	E-link proto Message type string.
*/
#define ELINK_MESSAGE_TYPE_KEY_NEG_REQ "keyngreq"
#define ELINK_MESSAGE_TYPE_KEY_NEG_ACK "keyngack"
#define ELINK_MESSAGE_TYPE_DH_ALGO "dh"
#define ELINK_MESSAGE_TYPE_DEV_REGISTER "dev_reg"
#define ELINK_MESSAGE_TYPE_ACK "ack"
#define ELINK_MESSAGE_TYPE_KEEP_ALIVE "keepalive"
#define ELINE_MESSAGE_TYPE_CFG "cfg"
#define ELINE_MESSAGE_TYPE_GET_STATUS "get_status"
#define ELINE_MESSAGE_TYPE_STATUS "status"
#define ELINE_MESSAGE_TYPE_DEV_REPORT "dev_report"
#define ELINK_MESSAGE_TYPE_WAN_REPORT "wan_report"
#define ELINK_MESSAGE_TYPE_GET_RSSI_INFO "getrssiinfo"
#define ELINK_MESSAGE_TYPE_RSSI_INFO "rssiinfo"
#define ELINK_MESSAGE_TYPE_DEASSOCIATION "deassociation"

#endif // !_ELINK_H_
