#ifndef _MSG_H_

#include<openssl/dh.h>
// #include "list.h"
// #include "cJSON.h"
// #include "server.h"
#define MSG_ST_IN_LIST 0x01
// #define MSG_ST_IN_LIST 0x02
// #define MSG_ST_IN_LIST 0x04
// #define MSG_ST_IN_LIST 0x08

typedef struct {
  elink_client_ctx *client_ctx;
  int flag;
  uint32_t timestamp;
  char *type;
  char *ip;
  char *mac;
  int seq;
  cJSON *json;
  cJSON *ret_json;
  struct list_head list;
} elink_msg_t;


struct list_head *get_msg_list(void);
void msg_list_free(struct list_head *list);
void msg_free(elink_msg_t *msg);

void recved_handle(uv_stream_t *client,uv_buf_t *buf);
void msg_cb_dispatch(elink_msg_t *msg);

int json_get_int(cJSON *json,char *key);
char * json_get_str(cJSON *json,char *key);

uv_buf_t elink_msg_unpack(elink_client_ctx *client,uv_buf_t *buf);
uv_buf_t elink_msg_pack(elink_client_ctx *client,uv_buf_t *buf);

// typedef void (*uv_work_cb)(uv_work_t* req);
// typedef void (*uv_after_work_cb)(uv_work_t* req, int status);

// typedef uv_buf_t (*msg_call_t)(elink_client_ctx *client,elink_msg_t *msg);
typedef void (*on_msg_call)(uv_work_t* req);
// typedef uv_buf_t (*msg_cb_t)(elink_client_ctx *client,elink_msg_t *msg);
void msg_send_after_cb(uv_work_t* req,int status);

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