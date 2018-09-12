#ifndef _MSG_H_
#define _MSG_H_
#include "sds.h"
#include "cJSON.h"
#include "list.h"

#pragma pack(1)

typedef struct ELINK_HEADER
{
    uint32_t magic;  // Net order, 0x3f721fb5
    uint32_t length; // Net order, length of data after header(not contain head).
    uint8_t data[0];
} ELINK_HEADER_STRU;
#pragma pack()

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

// #define ELINK_SERVER_IP "0.0.0.0"
// #define ELINK_SERVER_PORT 32768

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

// #define SERVER_MODE 0x01

// #define IS_SERVER_MODE(flag) (flag & SERVER_MODE)
#define MSG_ST_IN_LIST 0x01
// #define MSG_ST_IN_LIST 0x02
// #define MSG_ST_IN_LIST 0x04
// #define MSG_ST_IN_LIST 0x08

#define SDS_FREE(x)        \
    do                 \
    {                  \
          sdsfree(x);   \
          x = NULL;  \
    } while (0);

#define JSON_FREE(x)        \
    do                 \
    {                  \
            cJSON_Delete(x);   \
            x = NULL;  \
    } while (0);

#define log_sds_h(x)        \
    do                 \
    {                  \
        if (x != NULL) \
            log_mem(x,sdslen(x));   \
    } while (0);


#ifdef CONFIG_MSG
typedef struct keys_t {
  sds dh_p;      //prime
  sds dh_g;      //gen
  sds dh_pubkey; //pub key
  sds dh_privkey; //private key
  sds dh_sharekey;
  sds dh_serverkey;
  sds dh_clientkey;
} keys_t;
#endif

typedef struct model_info_t{
  int mode;
  sds mode_str;
  sds mac;
  sds vendor;
  sds swversion;
  sds hwversion;
  int wireless;
  sds sn;
  sds uptime;
  int contype;
  sds contype_str;
}model_info_t;

typedef struct ap_info_t{
  int enable;
  int mode;
  sds mode_str;
  sds ssid;
  sds rssi;
  sds band;
  sds channel;
  sds key;
  sds auth;
  sds ecrypto;
  sds txpower;
  struct list_head list;
}ap_info_t;

typedef struct elink_msg_t{
  sds call_type;
  uv_work_cb call;
	uv_after_work_cb after_call;
  sds cb_type;
  uv_work_cb cb;
	uv_after_work_cb after_cb;
	uv_work_t msg_req;
	uv_write_t wr_req;
  cJSON *call_json;
  cJSON *cb_json;
  sds ip;
  sds mac;
  int seq;
  struct list_head list;
  pcore_client_ctx *client;
  int flag;
  uint64_t timestamp;
} elink_msg_t;

typedef struct elink_session_ctx{
  pcore_client_ctx *client;
  int sid;
  sds name;
  int mode;
  sds mac;
  sds host;
  sds ip;
  sds gw;
  int dh_done;
  uint32_t seq;
  model_info_t model_info;
	// uv_work_t msg_req;
	// uv_write_t wr_req;
	uv_timer_t timer_call_handle;
	uv_timer_t timer_keepalive_handle;
	uv_timer_t timer_call_ret_check_handle;
  struct list_head call_list;               //客户端模式：待远程调用的消息
  struct list_head waitack_list;            //客户端模式：远程调用完成，待接受回馈的消息
  struct list_head ap_list;
  struct list_head msg_list;                //服务器模式：接受和处理的消息
  keys_t keys;
}elink_session_ctx;

struct list_head *get_msg_list(void);
void msg_list_free(struct list_head *list);
void msg_free(elink_msg_t *msg);

void msg_add_to_list(elink_session_ctx * ctx,struct list_head *list,char *type);

void data_recved_handle(uv_stream_t *client,uv_buf_t *buf);
void msg_start_call(pcore_client_ctx *client);
sds aes128_cmd(sds in, sds key, int do_encrypt);
sds elink_msg_decrypto(sds data,sds sharekey);
sds elink_msg_crypto(sds data,sds sharekey);


void msg_cb_dispatch(elink_session_ctx * ctx,elink_msg_t *msg);
void msg_call_ret_check(elink_session_ctx * ctx,elink_msg_t *msg);

int json_get_int(cJSON *json,char *key);
char * json_get_str(cJSON *json,char *key);

sds elink_msg_pack(elink_session_ctx * ctx,sds data);
sds elink_msg_unpack(elink_session_ctx * ctx,uv_buf_t *data);

void msg_call_done(uv_work_t* req,int status);
void msg_cb_done(uv_work_t* req,int status);

void msg_keepalive_call(uv_work_t* req);
void msg_keepalive_cb(uv_work_t* req);

void msg_keyngreq_call(uv_work_t* req);
void msg_keyngreq_cb(uv_work_t* req);

void msg_dh_call(uv_work_t* req);
void msg_dh_cb(uv_work_t* req);

char *base64(const unsigned char *inputBuffer, int inputLen,int *outLen);
char *unbase64(char *input, int length, int *outLen);

uv_buf_t str_cpy2buf(char *str,int len);
uv_buf_t buf_cpy2buf(uv_buf_t *buf);
uv_buf_t buf_unbase64(uv_buf_t *buf);
uv_buf_t buf_base64(uv_buf_t *buf);

sds unb64_block(sds in);
sds b64_block(sds in);
int gen_dh_param(sds p,sds g);
int gen_dh_keypair(sds p,sds g,sds pubkey,sds privkey);
int gen_dh_sharekey(sds p,sds g,sds privkey,sds peer_pubkey,sds sharekey);

#endif // !_MSG_H_