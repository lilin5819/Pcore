#include <uv.h>
#include "server.h"
#include "elink.h"
#include "msg.h"
#include "cJSON.h"
#include "list.h"
#include "sds.h"
#include "log.h"

typedef struct
{
	const char *type;
	on_msg_call call;
	uv_work_cb cb;
	uv_after_work_cb after_cb;
} msg_call_map_t;

msg_call_map_t msg_call_array[] = {
	{"keepalive", 	msg_keepalive_call,	msg_keepalive_cb,	msg_send_after_cb},
	{"keyngreq", 	msg_keyngreq_call,	msg_keyngreq_cb,	msg_send_after_cb},
	{"dh", 			msg_dh_call,		msg_dh_cb,			msg_send_after_cb}
	};

void msg_free(elink_msg_t *msg)
{
	msg->client_ctx = NULL;
	FREE(msg->type);
	FREE(msg->ip);
	FREE(msg->mac);
	if(msg->json)
		cJSON_Delete(msg->json);
}

void msg_list_free(struct list_head *msg_list)
{
	elink_msg_t *node,*next;
	ok(msg_list && msg_list->next && msg_list->prev);
	if(msg_list && msg_list->next && msg_list->prev)
		list_for_each_entry_safe(node,next,msg_list,list){
			list_del(&node->list);
			msg_free(node);
		}
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

uv_buf_t elink_msg_pack(elink_client_ctx *ctx, uv_buf_t *data)
{
	uint32_t buf_len = 0, magic = htonl(ELINK_MAGIC);
	char *newbuf = NULL;

	// if (!data || !data->base || data->len <= 0) {
	// 	log("%s, invalid data", __func__);
	// 	return NULL;
	// }

	buf_len = htonl(data->len);
	newbuf = malloc(ELINK_HEADER_LEN + data->len+1);

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

uv_buf_t elink_msg_unpack(elink_client_ctx *ctx, uv_buf_t *data)
{
	char *msg_buf = NULL;
	int msg_len = 0;
	msg_len = elink_check_header(data->base, ELINK_HEADER_LEN);

	msg_buf = (char *)malloc(msg_len + 1);
	msg_buf[msg_len] = 0;
	memcpy(msg_buf, data->base + ELINK_HEADER_LEN, msg_len);

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

// TODO: 只有消息接收和处理最终部分使用uv_buf_t，其他地方改成sds
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
	if (msg->list.next && msg->list.prev)
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
// TODO: 只有消息接收和处理最终部分使用uv_buf_t，其他地方改成sds
void recved_handle(uv_stream_t *stream, uv_buf_t *recved_buf)
{
	cJSON *json = NULL;
	char *type = NULL;
	char *mac = NULL;
	uint32_t seq = 0;
	uv_buf_t unpack_buf = {0};
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
			msg->client_ctx = client_ctx;
			INIT_LIST_HEAD(&msg->list);
			// list_add(&msg->list, g_msg_list);
			list_add(&msg->list, &client_ctx->msg_list);
			msg->flag |= MSG_ST_IN_LIST;
			log("type:%s mac:%s sequence:%d", type, mac, seq);
			msg_cb_dispatch(msg);
		}
		cJSON_Delete(json);
	}

	elink_msg_free(msg);
	FREE(unpack_buf.base);
	log_();
}

void msg_cb_dispatch(elink_msg_t *msg)
{
	// uv_buf_t send_buf = {0};
	uv_work_t req = {0};
	// if (!msg->json || !msg->mac)
	// {
	// 	log_e("json or type is NULL");
	// 	return;
	// }

	// for (int i = 0; i < sizeof(msg_cb_array) / sizeof(msg_cb_t); i++)
	// {
	// 	log("msg->type=%d msg_cb_array[%d].type=%s", msg->type, i, msg_cb_array[i].type);
	// 	if (!strcmp(msg_cb_array[i].type, msg->type))
	// 	{
	// 		send_buf = msg_cb_array[i].cb(client, msg);
	// 		log_s(send_buf.base);
	// 		break;
	// 	}
	// }
	// log("send_buf.base:%p send_buf.len:%d", send_buf.base, send_buf.len);
	// if (!send_buf.base)
	// 	log_e("msg type \"%s\": can't find callback", msg->type);
	// if (send_buf.base && send_buf.len > 0)
	// 	send_msg(client, &send_buf);
	// log_();

	for (int i = 0; i < sizeof(msg_call_array) / sizeof(msg_call_array[0]); i++)
	{
		if (!strcmp(msg_call_array[i].type, msg->type))
		{
			log("msg->type=%d msg_call_array[%d].type=%s", msg->type, i, msg_call_array[i].type);
			req.data = (void *) &msg;
			uv_queue_work(uv_default_loop(), &req, msg_call_array[i].cb, msg_call_array[i].after_cb);
			break;
		}
	}

	// FREE(send_buf.base);
}
//
void msg_send_after_cb(uv_work_t* req,int status)
{
	elink_server_ctx *server = get_elink_server_ctx();
	elink_msg_t *msg = (elink_msg_t*)req->data;
	// if(server->keys.dh_sharekey)
	uv_buf_t crypto_buf;

	log_();
	// crypto_buf = elink_msg_pack(msg->client_ctx, send_buf);
	// ok(crypto_buf.base != NULL);
	// // uv_write(&wr_req,(uv_stream_t*)&stream,&buf,1,on_write);
	// uv_write_t *wr_req = (uv_write_t *)malloc(sizeof(uv_write_t));
	// uv_write(wr_req, (uv_stream_t *)&client->tcp_handle, &crypto_buf, 1, on_write);
	free(req);
}

void msg_keepalive_call(uv_work_t* req)
{

}

void msg_keepalive_cb(uv_work_t* req)
{

}

void msg_keyngreq_call(uv_work_t* req)
{

}

void msg_keyngreq_cb(uv_work_t* req)
{
	elink_msg_t *msg = (elink_msg_t*)req->data;
	char *send_data = NULL;
	cJSON *send_json = cJSON_CreateObject();
	cJSON_AddStringToObject(send_json, "type", "keyngack");
	cJSON_AddStringToObject(send_json, "mac", msg->mac);
	cJSON_AddNumberToObject(send_json, "sequence", msg->seq);

	cJSON_AddStringToObject(send_json, "keymode", "dh");
	send_data = cJSON_Print(send_json);
	cJSON_Delete(send_json);
	// log_s(send_data);

	// return uv_buf_init(send_data, strlen(send_data));
	FREE(send_data);
}

void msg_dh_call(uv_work_t* req)
{

}

void msg_dh_cb(uv_work_t* req)
{
	elink_server_ctx *server = get_elink_server_ctx();
	cJSON *rcev_obj_data = NULL;
	elink_msg_t *msg = (elink_msg_t*)req->data;

	ok(msg->json != NULL);
	rcev_obj_data = cJSON_GetObjectItem(msg->json, "data");
	ok(rcev_obj_data != NULL);
	sds b64_p = sdsnewlen(json_get_str(rcev_obj_data, "dh_p"),128);
	sds b64_g = sdsnewlen(json_get_str(rcev_obj_data, "dh_g"),128);
	sds b64_pubkey = sdsnewlen(json_get_str(rcev_obj_data, "dh_key"),128);

	sdsupdatelen(b64_p);
	sdsupdatelen(b64_g);
	sdsupdatelen(b64_pubkey);
	log_s(b64_p);
	log_s(b64_g);
	log_s(b64_pubkey);
	sds s_p = unb64_block(b64_p);
	sds s_g = unb64_block(b64_g);
	sds s_pubkey = unb64_block(b64_pubkey);

	log_mem(s_p,sdslen(s_p));
	log_mem(s_g,sdslen(s_g));
	log_mem(s_pubkey,sdslen(s_pubkey));

	msg->client_ctx->keys.dh_p = s_p;
	msg->client_ctx->keys.dh_g = s_g;
	msg->client_ctx->keys.dh_pubkey = s_pubkey;

	server->keys.dh_p = sdsnewlen(s_p,sdslen(s_p));
	server->keys.dh_g = sdsnewlen(s_g,sdslen(s_g));
	server->keys.dh_pubkey = sdsnewlen("",sdslen(s_pubkey));
	server->keys.dh_privkey = sdsnewlen("",sdslen(s_pubkey));
	server->keys.dh_sharekey = sdsnewlen("",sdslen(s_pubkey));

	gen_dh_keypair(s_p,s_g,server->keys.dh_pubkey,server->keys.dh_privkey);
	gen_dh_sharekey(s_p,s_g,server->keys.dh_privkey,msg->client_ctx->keys.dh_pubkey,server->keys.dh_sharekey);
	
	cJSON *send_json = cJSON_CreateObject();
	cJSON *send_obj_data = cJSON_CreateObject();

	cJSON_AddStringToObject(send_json, "type", "dh");
	cJSON_AddStringToObject(send_json, "mac", msg->mac);
	cJSON_AddNumberToObject(send_json, "sequence", msg->seq);

	sds b64_server_pubkey = b64_block(server->keys.dh_pubkey);
	cJSON_AddStringToObject(send_obj_data, "dh_p", b64_p);
	cJSON_AddStringToObject(send_obj_data, "dh_g", b64_g);
	cJSON_AddStringToObject(send_obj_data, "dh_key", b64_server_pubkey);
	cJSON_AddItemToObject(send_json, "data", send_obj_data);
	msg->ret_json = send_json;

	cJSON_Delete(rcev_obj_data);
	cJSON_Delete(send_obj_data);
}
