#include <uv.h>
#include "server.h"
#include "elink.h"
#include "msg.h"
#include "cJSON.h"
#include "list.h"
#include "log.h"

typedef struct
{
	const char *type;
	msg_cb_t cb;
} msg_cb_map_t;

msg_cb_map_t msg_cb_array[] = {
	{"keyngreq", msg_keyngreq_cb},
	{"dh", msg_dh_cb},
	{"keepalive", msg_keepalive_cb}};

struct list_head g_msg_list;
LIST_HEAD(g_msg_list);

struct list_head *msg_list_init(void)
{
	log_();
	INIT_LIST_HEAD(&g_msg_list);
	return &g_msg_list;
}

static struct list_head *get_msg_list(void)
{
	return &g_msg_list;
}

int elink_check_header(const char *buf, int hdr_size)
{
	uint32_t magic1 = 0;
	uint64_t magic2 = 0;
	uint32_t len = 0;

	if (hdr_size == ELINK_HEADER_LEN)
	{
		memcpy(&magic1, buf, sizeof(magic1));

		if (htonl(magic1) != ELINK_MAGIC)
		{
			log("invalid magic 0x%x", htonl(magic1));
			return 0;
		}
		else
		{
			memcpy(&len, buf + ELINK_MAGIC_LEN, ELINK_CONTENT_LEN);
		}
	}
	else if (hdr_size == ELINKCC_HEADER_LEN)
	{
		memcpy(&magic2, buf, sizeof(magic2));

		if (htobe64(magic2) != ELINKCC_MAGIC)
		{
			log("invalid magic 0x%x", htobe64(magic2));
			return 0;
		}
		else
		{
			memcpy(&len, buf + ELINKCC_MAGIC_LEN, ELINK_CONTENT_LEN);
		}
	}

	log("%s: hdr size %d, msg len is %d", __func__, hdr_size, htonl(len));

	return htonl(len);
}

uv_buf_t elink_msg_pack(elink_client_ctx *client, uv_buf_t *data)
{
	uint32_t buf_len = 0, magic = htonl(ELINK_MAGIC);
	char *newbuf = NULL;

	// if (!data || !data->base || data->len <= 0) {
	// 	log("%s, invalid data", __func__);
	// 	return NULL;
	// }

	buf_len = htonl(data->len);
	newbuf = malloc(ELINK_HEADER_LEN + data->len);

	if (newbuf)
	{
		memcpy(newbuf, &magic, ELINK_MAGIC_LEN);
		memcpy(newbuf + ELINK_MAGIC_LEN, &buf_len, 4);
		memcpy(newbuf + ELINK_HEADER_LEN, data->base, data->len);
	}
	else
	{
		log("%s, failed to malloc", __func__);
	}

	return uv_buf_init(newbuf, ELINK_HEADER_LEN + data->len);
}

uv_buf_t elink_msg_unpack(elink_client_ctx *client, uv_buf_t *data)
{
	char *msg_buf = NULL;
	int msg_len = 0;
	msg_len = elink_check_header(data->base, ELINK_HEADER_LEN);
	// if(msg_len <= 0) {
	//     log("msg header error");
	//     return NULL;
	// }
	msg_buf = (char *)malloc(msg_len + 1);
	msg_buf[msg_len] = 0;
	memcpy(msg_buf, data->base + ELINK_HEADER_LEN, msg_len);
	// cJSON *json = cJSON_Parse(msg_buf);
	// recved_data = cJSON_Print(json);
	// log_s(recved_data);
	// log_s(msg_buf);
	// free(msg_buf);
	return uv_buf_init(msg_buf, msg_len);
}

int json_get_int(cJSON *json, char *key)
{
	cJSON *item = cJSON_GetObjectItem(json, key);
	return (item && item->type == cJSON_Number) ? item->valueint : 0;
}

char *json_get_str(cJSON *json, char *key)
{
	cJSON *item = cJSON_GetObjectItem(json, key);
	return (item && item->type == cJSON_String) ? item->valuestring : NULL;
}

void send_msg(elink_client_ctx *client, uv_buf_t *send_buf)
{
	log_();
	uv_buf_t crypto_buf;
	crypto_buf = elink_msg_pack(client, send_buf);
	ok(crypto_buf.base != NULL);
	// uv_write(&wr_req,(uv_stream_t*)&stream,&buf,1,on_write);
	uv_write_t *wr_req = (uv_write_t *)malloc(sizeof(uv_write_t));
	uv_write(wr_req, (uv_stream_t *)&client->tcp_handle, &crypto_buf, 1, on_write);
}

void elink_msg_free(elink_msg_t *msg)
{
	if (msg->list.next)
		list_del(&msg->list);
	log_();
	FREE(msg->type);
	FREE(msg->ip);
	FREE(msg->mac);
	if (msg->json)
	{
		cJSON_Delete(msg->json);
		msg->json = NULL;
	}
	FREE(msg)
}

void recved_handle(uv_stream_t *stream, uv_buf_t *recved_buf)
{
	cJSON *json = NULL;
	char *type = NULL;
	char *mac = NULL;
	uint32_t seq = 0;
	uv_buf_t unpack_buf;
	elink_msg_t *msg = (elink_msg_t *)malloc(sizeof(elink_msg_t));
	memset(msg, 0, sizeof(*msg));
	// log_s(recved_buf->base);

	elink_client_ctx *client_ctx = container_of(stream, elink_client_ctx, tcp_handle);
	ok(client_ctx != NULL);
	log_s(client_ctx->name);
	unpack_buf = elink_msg_unpack(client_ctx, recved_buf);
	log_s(unpack_buf.base);
	json = cJSON_Parse(unpack_buf.base);
	if (json)
	{
		type = json_get_str(json, "type");
		mac = json_get_str(json, "mac");
		seq = json_get_int(json, "sequence");
		if (type && mac)
		{
			if (!client_ctx->mac)
				client_ctx->mac = strdup(mac);
			else if (strcmp(client_ctx->mac, mac))
				log_e("client mac changed");
			msg->type = strdup(type);
			msg->mac = strdup(mac);
			msg->seq = seq;
			msg->json = cJSON_Duplicate(json, 1);
			INIT_LIST_HEAD(&msg->list);
			list_add(&msg->list, &g_msg_list);
			msg->flag |= MSG_ST_IN_LIST;
			log("type:%s mac:%s sequence:%d", type, mac, seq);
			msg_cb_dispatch(client_ctx, msg);
		}
		cJSON_Delete(json);
	}

	elink_msg_free(msg);
	FREE(unpack_buf.base);
	log_();
}

void msg_cb_dispatch(elink_client_ctx *client, elink_msg_t *msg)
{
	uv_buf_t send_buf = {0};
	if (!msg->json || !msg->mac)
	{
		log_e("json or type is NULL");
		return;
	}
	// if(!strcmp(type,"keyngreq")){
	// 	msg_cb_keyngreq(json,mac,sequence);
	// }
	for (int i = 0; i < sizeof(msg_cb_array) / sizeof(msg_cb_t); i++)
	{
		log("msg->type=%d msg_cb_array[%d].type=%s", msg->type, i, msg_cb_array[i].type);
		if (!strcmp(msg_cb_array[i].type, msg->type))
		{
			send_buf = msg_cb_array[i].cb(client, msg);
			log_s(send_buf.base);
			break;
		}
	}
	log("send_buf.base:%p send_buf.len:%d", send_buf.base, send_buf.len);
	if (!send_buf.base)
		log_e("msg type \"%s\": can't find callback", msg->type);
	if (send_buf.base && send_buf.len > 0)
		send_msg(client, &send_buf);
	log_();
}

uv_buf_t msg_keyngreq_cb(elink_client_ctx *client, elink_msg_t *msg)
{
	char *send_data = NULL;
	cJSON *send_json = cJSON_CreateObject();
	cJSON_AddStringToObject(send_json, "type", "keyngack");
	cJSON_AddStringToObject(send_json, "mac", msg->mac);
	cJSON_AddNumberToObject(send_json, "sequence", msg->seq);

	cJSON_AddStringToObject(send_json, "keymode", "dh");
	send_data = cJSON_Print(send_json);
	cJSON_Delete(send_json);
	// log_s(send_data);
	return uv_buf_init(send_data, strlen(send_data));
	// send_msg(client,send_data,strlen(send_data));
}

uv_buf_t msg_dh_cb(elink_client_ctx *client, elink_msg_t *msg)
{
	elink_server_ctx *server = elink_get_server_ctx();
	char *send_data = NULL;
	cJSON *rcev_obj_data = NULL;
	char *client_pubkey = NULL, *client_dh_p = NULL, *client_dh_g = NULL;

	ok(msg->json != NULL);
	rcev_obj_data = cJSON_GetObjectItem(msg->json, "data");
	ok(rcev_obj_data != NULL);
	client_pubkey = json_get_str(rcev_obj_data, "dh_key");
	client_dh_p = json_get_str(rcev_obj_data, "dh_p");
	client_dh_g = json_get_str(rcev_obj_data, "dh_g");
	client->keys.dh_pubkey.base = strdup(client_pubkey);
	client->keys.dh_p.base = strdup(client_dh_p);
	client->keys.dh_g.base = strdup(client_dh_g);

	log_s(client->keys.dh_pubkey.base);
	log_s(client->keys.dh_p.base);
	log_s(client->keys.dh_g.base);

	cJSON *send_json = cJSON_CreateObject();
	cJSON *send_obj_data = cJSON_CreateObject();

	cJSON_AddStringToObject(send_json, "type", "dh");
	cJSON_AddStringToObject(send_json, "mac", msg->mac);
	cJSON_AddNumberToObject(send_json, "sequence", msg->seq);

	cJSON_AddStringToObject(send_obj_data, "dh_key", client->keys.dh_pubkey.base);
	cJSON_AddStringToObject(send_obj_data, "dh_p", client->keys.dh_p.base);
	cJSON_AddStringToObject(send_obj_data, "dh_g", client->keys.dh_g.base);
	cJSON_AddItemToObject(send_json, "data", send_obj_data);
	send_data = cJSON_Print(send_json);
	// log_s(send_data);
	return uv_buf_init(send_data, strlen(send_data));
	// send_msg(client,send_data,strlen(send_data));
}

uv_buf_t msg_keepalive_cb(elink_client_ctx *client, elink_msg_t *msg)
{
}
