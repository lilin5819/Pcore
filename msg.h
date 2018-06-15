#ifndef _MSG_H_

// #include "list.h"
// #include "cJSON.h"
// #include "server.h"
#define MSG_ST_IN_LIST 0x01
// #define MSG_ST_IN_LIST 0x02
// #define MSG_ST_IN_LIST 0x04
// #define MSG_ST_IN_LIST 0x08

typedef struct {
  int flag;
  char *type;
  char *ip;
  char *mac;
  int seq;
  // elink_client_ctx *client_ctx;
  cJSON *json;
  // cJSON *send_json;
  struct list_head list;
} elink_msg_t;

struct list_head *msg_list_init(void);

void recved_handle(uv_stream_t *client,uv_buf_t *buf);
void msg_cb_dispatch(elink_client_ctx *client,elink_msg_t *msg);

int json_get_int(cJSON *json,char *key);
char * json_get_str(cJSON *json,char *key);

uv_buf_t elink_msg_unpack(elink_client_ctx *client,uv_buf_t *buf);
uv_buf_t elink_msg_pack(elink_client_ctx *client,uv_buf_t *buf);

typedef uv_buf_t (*msg_cb_t)(elink_client_ctx *client,elink_msg_t *msg);

uv_buf_t msg_keyngreq_cb(elink_client_ctx *client,elink_msg_t *msg);
uv_buf_t msg_dh_cb(elink_client_ctx *client,elink_msg_t *msg);
uv_buf_t msg_keepalive_cb(elink_client_ctx *client,elink_msg_t *msg);

#endif // !_MSG_H_