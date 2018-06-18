#include <uv.h>
#include "core.h"
#include "msg.h"
#include "sds.h"
#include "list.h"
#include "log.h"

typedef struct
{
	const char *type;
	uv_work_cb call;
	uv_after_work_cb after_call;
	const char *ret_type;
	uv_work_cb cb;
	uv_after_work_cb after_cb;
} msg_call_vec_t;

msg_call_vec_t msg_call_map[] = {
	{"keepalive", 		msg_keepalive_call,		msg_chk_after_call,		"ack",			msg_keepalive_cb,		msg_ret_after_cb},
	{"keyngreq", 		msg_keyngreq_call,		msg_chk_after_call,		"keyngack",		msg_keyngreq_cb,		msg_ret_after_cb},
	{"dh", 				msg_dh_call,			msg_chk_after_call,		"dh",			msg_dh_cb,				msg_ret_after_cb},
	// {"dev_reg", 		msg_dev_reg_call,		"ack",			msg_dev_reg_cb,			msg_ret_after_cb}
	};

char msg_login_calls[][10] = {"keyngreq","dh","dev_reg"};

void msg_free(elink_msg_t *msg)
{
	msg->client = NULL;
	SDS_FREE(msg->type);
	SDS_FREE(msg->type);
	SDS_FREE(msg->ip);
	SDS_FREE(msg->mac);
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

	if (hdr_size == ELINK_HEADER_LEN) {
		memcpy(&magic1, buf, sizeof(magic1));

		if (htonl(magic1) != ELINK_MAGIC) {
			log("invalid magic 0x%x", htonl(magic1));
			return 0;
		} else {
			memcpy(&len, buf + ELINK_MAGIC_LEN, ELINK_CONTENT_LEN);
		}
	} else if (hdr_size == ELINKCC_HEADER_LEN) {
		memcpy(&magic2, buf, sizeof(magic2));

		if (htobe64(magic2) != ELINKCC_MAGIC) {
			log("invalid magic 0x%x", htobe64(magic2));
			return 0;
		} else {
			memcpy(&len, buf + ELINKCC_MAGIC_LEN, ELINK_CONTENT_LEN);
		}
	}

	log("%s: hdr size %d, msg len is %d", __func__, hdr_size, htonl(len));

	return htonl(len);
}

uv_buf_t elink_msg_pack(sds data)
{
	uint32_t buf_len = 0, magic = htonl(ELINK_MAGIC);
	char *newbuf = NULL;

	buf_len = htonl(sdslen(data));
	newbuf = malloc(ELINK_HEADER_LEN + sdslen(data)+1);

	if (newbuf) {
		memcpy(newbuf, &magic, ELINK_MAGIC_LEN);
		memcpy(newbuf + ELINK_MAGIC_LEN, &buf_len, 4);
		memcpy(newbuf + ELINK_HEADER_LEN, data, sdslen(data));
	} else {
		log("%s, failed to malloc", __func__);
	}

	return uv_buf_init(newbuf, ELINK_HEADER_LEN + sdslen(data));
}

sds elink_msg_unpack(uv_buf_t *data)
{
	int msg_len = 0;
	msg_len = elink_check_header(data->base, ELINK_HEADER_LEN);
	return sdsnewlen(data->base + ELINK_HEADER_LEN, msg_len);
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
// void send_msg(elink_session_ctx *client, sds send_buf)
// {
// 	log_();
// 	uv_buf_t crypto_buf = elink_msg_pack(send_buf);
// 	ok(crypto_buf.base != NULL);
// 	uv_write_t *wr_req = (uv_write_t *)malloc(sizeof(uv_write_t));
// 	uv_write(wr_req, (uv_stream_t *)&client->tcp_handle, &crypto_buf, 1, on_write);
// }

void elink_msg_free(elink_msg_t *msg)
{
	log_();
	if (msg->list.next && msg->list.prev)
		list_del(&msg->list);
	FREE(msg->type);
	FREE(msg->ip);
	FREE(msg->mac);
	if (msg->json)
	{
		cJSON_Delete(msg->json);
		msg->json = NULL;
	}
	if (msg->ret_json)
	{
		cJSON_Delete(msg->ret_json);
		msg->ret_json = NULL;
	}
	FREE(msg)
}

static void on_timer_call(uv_timer_t *handle)
{
    elink_session_ctx *ctx = container_of(handle, elink_session_ctx, timer_call_handle);
	struct list_head *node;
	if(ctx->msg_list.next != &ctx->msg_list){
		node = ctx->msg_list.next;
		list_del(node);
		elink_msg_t *msg = container_of(node,elink_msg_t,list);
		log_s(msg->mac);
		uv_queue_work(uv_default_loop(), &msg->msg_req, msg->call, msg->after_call);
	}else{
		uv_close((uv_handle_t*)handle,close_cb);
	}
}

void msg_add_call_to_list(elink_session_ctx * ctx,struct list_head *list,char *type)
{
	for (int i = 0; i < sizeof(msg_call_map) / sizeof(msg_call_map[0]); i++)
	{
		if (!strcmp(msg_call_map[i].type, type))
		{
			// log("msg->type=%s msg_call_map[%d].type=%s msg_call_map[%d].ret_type=%s", type, i, msg_call_map[i].type, i, msg_call_map[i].ret_type);
			log_s(type);
			elink_msg_t * msg =  malloc(sizeof(elink_msg_t));
			memset(msg,0,sizeof(elink_msg_t));
			msg->type = sdsdup((const sds)msg_call_map[i].type);
			msg->call = msg_call_map[i].call;
			msg->after_call = msg_call_map[i].after_call;
			msg->type = sdsdup((const sds)msg_call_map[i].type);
			msg->cb = msg_call_map[i].cb;
			msg->after_cb = msg_call_map[i].after_cb;
			msg->msg_req.data = ctx;
			INIT_LIST_HEAD(&msg->list);
			list_add_tail(&msg->list,list);

			break;
		}
	}
}

void msg_start_call(elink_client_ctx *client)
{
	elink_session_ctx * ctx = NULL;
	log_();
	ok(client->data != NULL);
	if (!client->data)
	{
		log_();
		ctx = malloc(sizeof(elink_session_ctx));
		log_();
		ok(ctx != NULL);
		memset(ctx, 0, sizeof(elink_session_ctx));
		log_();
		INIT_LIST_HEAD(&ctx->call_list);
		INIT_LIST_HEAD(&ctx->ap_list);
		INIT_LIST_HEAD(&ctx->msg_list);
		client->data = ctx;
		log("this is a new client,alloc session context !!!");
	}
	else
		ctx = (elink_session_ctx *)client->data;
	log_();
	for (int i = 0; i < sizeof(msg_login_calls) / sizeof(msg_login_calls[0]); i++)
	{
		// log_s(msg_login_calls[i]);
		msg_add_call_to_list(ctx,&ctx->msg_list,msg_login_calls[i]);                           //加入三个调用到链表中
	}

	uv_timer_init(uv_default_loop(),&ctx->timer_call_handle);
	uv_timer_start(&ctx->timer_call_handle,on_timer_call,0*1000,10*1000);       // 立马启动，10秒运行一次
}


void data_recved_handle(uv_stream_t *stream, uv_buf_t *recved_buf)
{
	cJSON *json = NULL;
	char *type = NULL;
	char *mac = NULL;
	uint32_t seq = 0;
	sds s_unpack_data = {0};
	elink_session_ctx * ctx = NULL;
	elink_msg_t *msg = (elink_msg_t *)malloc(sizeof(elink_msg_t));
	memset(msg, 0, sizeof(*msg));

	elink_client_ctx *client = container_of(stream, elink_client_ctx, tcp_handle);
	ok(client != NULL);
	log_s(client->name);
	s_unpack_data = elink_msg_unpack(recved_buf);
	log_s(s_unpack_data);
	json = cJSON_Parse(s_unpack_data);
	log_p(json);
	if (json)
	{
		type = json_get_str(json, "type");
		mac = json_get_str(json, "mac");
		seq = json_get_int(json, "sequence");
		if (type && mac)
		{
			if(!client->data){
				ctx = malloc(sizeof(elink_session_ctx));
				ok(client->data != NULL);
				memset(client->data,0,sizeof(elink_session_ctx));
				INIT_LIST_HEAD(&ctx->ap_list);
				INIT_LIST_HEAD(&ctx->msg_list);
				client->data = ctx;
				log("this is a new client,alloc session context !!!");
			}else
				ctx = (elink_session_ctx *)client->data;

			client->timestamp = uv_hrtime();
			msg->timestamp = client->timestamp;
			msg->type = sdsnew(type);
			msg->mac = sdsnew(mac);
			msg->seq = seq;
			msg->json = cJSON_Duplicate(json, 1);
			msg->client = client;

			INIT_LIST_HEAD(&msg->list);
			list_add_tail(&msg->list, &ctx->msg_list);
			msg->flag |= MSG_ST_IN_LIST;
			log("type:%s mac:%s sequence:%d", type, mac, seq);

			msg_cb_dispatch(ctx,msg);
			log_();
		}
		log_();
		cJSON_Delete(json);
	}

	// elink_msg_free(msg);
	SDS_FREE(s_unpack_data);

	log_();
}


void msg_cb_dispatch(elink_session_ctx * ctx,elink_msg_t *msg)
{
	for (int i = 0; i < sizeof(msg_call_map) / sizeof(msg_call_map[0]); i++)
	{
		if (!strcmp(msg_call_map[i].type, msg->type))
		{
			log("msg->type=%d msg_call_map[%d].type=%s msg_call_map[%d].ret_type=%s", msg->type, i, msg_call_map[i].type, i, msg_call_map[i].ret_type);
			msg->type = sdsdup((const sds)msg_call_map[i].type);
			msg->call = msg_call_map[i].call;
			msg->after_call = msg_call_map[i].after_call;
			msg->type = sdsdup((const sds)msg_call_map[i].type);
			msg->cb = msg_call_map[i].cb;
			msg->after_cb = msg_call_map[i].after_cb;
			msg->msg_req.data = (void *)ctx;
			uv_queue_work(uv_default_loop(), &msg->msg_req, msg_call_map[i].cb, msg_call_map[i].after_cb);
			break;
		}
	}
}

sds elink_msg_crypto(sds data)
{

	// sds s_crypto_data
	return data;
}

void on_msg_write_done(uv_write_t *req, int status)
{
#ifdef CONFIG_MSG
	// elink_protocal_ctx *ctx = container_of(req, elink_protocal_ctx, wr_req);
    log_();
	// elink_msg_t *msg = (elink_msg_t*)req->data;
	elink_msg_t *msg = container_of(req, elink_msg_t, wr_req);
	elink_session_ctx *ctx = (elink_session_ctx *)req->data;
    if (status)
    {
        log("Write error %s", uv_strerror(status));
    }
    msg_free(msg);
#endif
	memset(req,0,sizeof(*req));
}

void msg_chk_after_call(uv_work_t* req,int status)
{
	log_();
	elink_msg_t *msg = container_of(req, elink_msg_t, msg_req);
	log_();
	elink_session_ctx *ctx = (elink_session_ctx *)req->data;
	log_();
	log_s(msg->type);
	log_u(msg->seq);
	cJSON_AddStringToObject(msg->ret_json, "type", (char *)msg->type);
	cJSON_AddStringToObject(msg->ret_json, "mac", (char*)get_if_macstr("eth0"));
	cJSON_AddNumberToObject(msg->ret_json, "sequence", msg->seq);
	msg->seq ++;
	log_();

	char *text = cJSON_Print(msg->ret_json);

	log_();
	sds s_data = sdsnewlen(text,strlen(text));
	log_s(s_data);
	if(ctx->keys.dh_sharekey)
		s_data = elink_msg_crypto(s_data);
	log_();
	uv_buf_t crypto_buf = elink_msg_pack(s_data);
	ok(crypto_buf.base != NULL && crypto_buf.len > 0);
	// uv_write_t *wr_req = (uv_write_t *)malloc(sizeof(uv_write_t));
	uv_write(&msg->wr_req, (uv_stream_t *)&msg->client->tcp_handle, &crypto_buf, 1, on_msg_write_done);
	SDS_FREE(s_data);
	// free(req);
	memset(req,0,sizeof(*req));
}

void msg_ret_after_cb(uv_work_t* req,int status)
{
	log_();
	// elink_session_ctx *ctx = container_of(req, elink_session_ctx, msg_req);
	// elink_msg_t *msg = (elink_msg_t*)req->data;
	elink_msg_t *msg = container_of(req, elink_msg_t, wr_req);
	elink_session_ctx *ctx = (elink_session_ctx *)req->data;
	cJSON_AddStringToObject(msg->ret_json, "type", (char *)msg->ret_type);
	cJSON_AddStringToObject(msg->ret_json, "mac", (char*)msg->mac);
	cJSON_AddNumberToObject(msg->ret_json, "sequence", msg->seq);

	char *text = cJSON_Print(msg->ret_json);

	sds s_data = sdsnewlen(text,strlen(text));
	log_s(s_data);
	if(ctx->keys.dh_sharekey)
		s_data = elink_msg_crypto(s_data);
	log_();
	uv_buf_t crypto_buf = elink_msg_pack(s_data);
	ok(crypto_buf.base != NULL && crypto_buf.len > 0);
	// uv_write_t *wr_req = (uv_write_t *)malloc(sizeof(uv_write_t));
	uv_write(&msg->wr_req, (uv_stream_t *)&msg->client->tcp_handle, &crypto_buf, 1, on_msg_write_done);
	SDS_FREE(s_data);
	// free(req);
	memset(req,0,sizeof(*req));
}

void msg_keepalive_call(uv_work_t* req)
{
	log_();
	elink_session_ctx *ctx = container_of(req, elink_session_ctx, msg_req);

}

void msg_keepalive_cb(uv_work_t* req)
{
	log_();
}

void msg_keyngreq_call(uv_work_t* req)
{
	log_();
}

void msg_keyngreq_cb(uv_work_t* req)
{
	log_();
	// elink_msg_t *msg = (elink_msg_t*)req->data;
	elink_msg_t *msg = container_of(req, elink_msg_t, msg_req);
	elink_session_ctx *ctx = (elink_session_ctx *)req->data;
	msg->ret_json = cJSON_CreateObject();
	cJSON_AddStringToObject(msg->ret_json, "keymode", "dh");
}

void msg_dh_call(uv_work_t* req)
{
	log_();
}

void msg_dh_cb(uv_work_t* req)
{
	log_();
	// elink_session_ctx *ctx = container_of(req, elink_session_ctx, msg_req);
	elink_server_ctx *server = get_elink_server_ctx();
	cJSON *rcev_obj_data = NULL;
	// elink_msg_t *msg = (elink_msg_t*)req->data;
	elink_msg_t *msg = container_of(req, elink_msg_t, msg_req);
	elink_session_ctx *ctx = (elink_session_ctx *)req->data;
	sds b64_p = NULL,b64_g = NULL, b64_pubkey = NULL,b64_server_pubkey = NULL;
	sds s_p = NULL,s_g = NULL, s_pubkey = NULL,s_server_pubkey = NULL , s_server_privkey = NULL;

	ok(msg->json != NULL);
	rcev_obj_data = cJSON_GetObjectItem(msg->json, "data");
	ok(rcev_obj_data != NULL);
	b64_p = sdsnewlen(json_get_str(rcev_obj_data, "dh_p"),128);
	b64_g = sdsnewlen(json_get_str(rcev_obj_data, "dh_g"),128);
	b64_pubkey = sdsnewlen(json_get_str(rcev_obj_data, "dh_key"),128);
	cJSON_Delete(rcev_obj_data);

	sdsupdatelen(b64_p);
	sdsupdatelen(b64_g);
	sdsupdatelen(b64_pubkey);
	log_s(b64_p);
	log_s(b64_g);
	log_s(b64_pubkey);
	s_p = unb64_block(b64_p);
	s_g = unb64_block(b64_g);
	s_pubkey = unb64_block(b64_pubkey);													//base64解密

	log_mem(s_p,sdslen(s_p));
	log_mem(s_g,sdslen(s_g));
	log_mem(s_pubkey,sdslen(s_pubkey));

	ctx->keys.dh_p = s_p;
	ctx->keys.dh_g = s_g;
	ctx->keys.dh_pubkey = s_pubkey;

	s_server_pubkey = sdsnewlen("",sdslen(s_pubkey));
	s_server_privkey = sdsnewlen("",sdslen(s_pubkey));

	gen_dh_keypair(s_p,s_g,s_server_pubkey,s_server_privkey);							//生成服务器秘钥对
	gen_dh_sharekey(s_p,s_g,s_server_privkey,s_pubkey,ctx->keys.dh_sharekey);	//生成共享秘钥
	log_mem(s_p,sdslen(s_p));
	log_mem(s_g,sdslen(s_g));
	log_mem(s_pubkey,sdslen(s_pubkey));

	log_mem(s_server_pubkey,sdslen(s_server_pubkey));
	log_mem(s_server_privkey,sdslen(s_server_privkey));
	log_mem(ctx->keys.dh_sharekey,sdslen(ctx->keys.dh_sharekey));

	cJSON *send_json = cJSON_CreateObject();
	cJSON *send_obj_data = cJSON_CreateObject();

	cJSON_Delete(send_obj_data);

	b64_server_pubkey = b64_block(s_server_pubkey);                                     //将服务器公钥发给客户端
	cJSON_AddStringToObject(send_obj_data, "dh_p", b64_p);
	cJSON_AddStringToObject(send_obj_data, "dh_g", b64_g);
	cJSON_AddStringToObject(send_obj_data, "dh_key", b64_server_pubkey);
	cJSON_AddItemToObject(send_json, "data", send_obj_data);

	msg->ret_json = send_json;
}
