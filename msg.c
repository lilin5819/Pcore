#include <uv.h>
#include "core.h"
#include "msg.h"
#include "sds.h"
#include "list.h"
#include "log.h"

typedef struct
{
	const char *call_type;
	uv_work_cb call;
	uv_after_work_cb after_call;
	const char *cb_type;
	uv_work_cb cb;
	uv_after_work_cb after_cb;
} msg_call_vec_t;

msg_call_vec_t msg_call_map[] = {
	{"keepalive", 		msg_keepalive_call,		msg_call_done,		"ack",			msg_ack_cb,				msg_cb_done},
	{"keyngreq", 		msg_keyngreq_call,		msg_call_done,		"keyngack",		msg_keyngreq_cb,		msg_cb_done},
	{"dh", 				msg_dh_call,			msg_call_done,		"dh",			msg_dh_cb,				msg_cb_done},
	{"dev_reg", 		msg_dev_reg_call,		msg_call_done,     "ack",			msg_ack_cb,				msg_cb_done},
	};

char msg_login_calls[][10] = {"keyngreq","dh","dev_reg","keepalive","keepalive","keepalive","keepalive"};

void msg_free(elink_msg_t *msg)
{
	msg->client = NULL;
	SDS_FREE(msg->call_type);
	SDS_FREE(msg->call_type);
	SDS_FREE(msg->ip);
	SDS_FREE(msg->mac);
	JSON_FREE(msg->call_json);
	JSON_FREE(msg->cb_json);
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

long elink_check_header(const char *buf, int hdr_size)
{
	uint32_t magic1 = 0;
	uint64_t magic2 = 0;
	uint32_t len = 0;

	if (hdr_size == ELINK_HEADER_LEN) {
		memcpy(&magic1, buf, sizeof(magic1));
		if (ntohl(magic1) != ELINK_MAGIC) {
			log("invalid magic 0x%x", htonl(magic1));
			return 0;
		} else {
			memcpy(&len, buf + ELINK_MAGIC_LEN, ELINK_CONTENT_LEN);
		}
	} else if (hdr_size == ELINKCC_HEADER_LEN) {
		memcpy(&magic2, buf, sizeof(magic2));

		if (ntohl(magic2) != ELINKCC_MAGIC) {
			log("invalid magic 0x%x", ntohl(magic2));
			return 0;
		} else {
			memcpy(&len, buf + ELINKCC_MAGIC_LEN, ELINK_CONTENT_LEN);
		}
	}

	log("%s: hdr size %d, msg len is %d", __func__, hdr_size, ntohl(len));
	// log_d(ntohl(len));

	return ntohl(len);
}

sds elink_msg_pack(elink_session_ctx * ctx,sds data)
{
	log_();
	uint32_t msg_len =0,buf_len = 0, magic = htonl(ELINK_MAGIC);
	msg_len = MOD_16_INTGER(sdslen(data));
	data = sdsgrowzero(data,msg_len);
	buf_len = htonl(msg_len);
	sds newbuf = sdsempty();
	log_d(sdslen(data));
	if (newbuf) {
		newbuf = sdscatlen(newbuf, &(magic), ELINK_MAGIC_LEN);
		newbuf = sdscatlen(newbuf, &buf_len, 4);
		if(ctx->dh_done){
			sds crypto_buf = aes128_cmd(data,ctx->keys.dh_sharekey,1);
			log_();
			newbuf = sdscatsds(newbuf, crypto_buf);
			log_();
		}else{
			newbuf = sdscatlen(newbuf, data, msg_len);
		}
	} else {
		log("%s, failed to malloc", __func__);
	}
	
	log_d(sdslen(newbuf));
	return newbuf;
}

sds elink_msg_unpack(elink_session_ctx * ctx,uv_buf_t *data)
{
	log_();
	long msg_len = 0;
	msg_len = elink_check_header(data->base, ELINK_HEADER_LEN);
	log_ld(msg_len);
	// log(sdscatrepr(sdsempty(),data->base,data->len));

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

void elink_msg_free(elink_msg_t *msg)
{
	log_();
	if (msg->list.next && msg->list.prev)
		list_del(&msg->list);
	SDS_FREE(msg->call_type);
	SDS_FREE(msg->cb_type);
	SDS_FREE(msg->ip);
	SDS_FREE(msg->mac);
	JSON_FREE(msg->call_json);
	JSON_FREE(msg->cb_json);
	FREE(msg)
}

static void on_timer_call(uv_timer_t *handle)
{
    elink_session_ctx *ctx = container_of(handle, elink_session_ctx, timer_call_handle);
	struct list_head *node;
	if(ctx->call_list.next != &ctx->call_list){
		node = ctx->call_list.next;
		list_del(node);
		elink_msg_t *msg = container_of(node,elink_msg_t,list);
		msg->seq = ctx->seq++;
		log_s(msg->mac);
		uv_queue_work(uv_default_loop(), &msg->msg_req, msg->call, msg->after_call);
	}else{
		log("there is no bootup handle to call");
		uv_close((uv_handle_t*)handle,close_cb);
	}
}

void msg_add_to_list(elink_session_ctx * ctx,struct list_head *list,char *type)
{
	for (int i = 0; i < ARRAY_SIZE(msg_call_map); i++)
	{
		if (!strcmp(msg_call_map[i].call_type, type))
		{
			// log("msg->call_type=%s msg_call_map[%d].call_type=%s msg_call_map[%d].cb_type=%s", type, i, msg_call_map[i].call_type, i, msg_call_map[i].cb_type);
			log_s(type);
			elink_msg_t * msg =  malloc(sizeof(elink_msg_t));
			memset(msg,0,sizeof(elink_msg_t));
			msg->call_type = sdsnew(msg_call_map[i].call_type);
			msg->call = msg_call_map[i].call;
			msg->after_call = msg_call_map[i].after_call;
			msg->cb_type = sdsnew(msg_call_map[i].cb_type);
			msg->cb = msg_call_map[i].cb;
			msg->after_cb = msg_call_map[i].after_cb;
			msg->client = ctx->client;
			msg->ip = sdsnew(ctx->ip);
			msg->mac = sdsnew(ctx->mac);
			// msg->gw = sdsnew(ctx->gw);

			msg->msg_req.data = ctx;
			msg->wr_req.data = ctx;

			INIT_LIST_HEAD(&msg->list);
			list_add_tail(&msg->list,list);
			break;
		}
	}
}

elink_session_ctx *elink_session_ctx_alloc(elink_client_ctx *client)
{
	log_();
	elink_session_ctx* ctx = malloc(sizeof(elink_session_ctx));
	log_();
	ok(ctx != NULL);
	memset(ctx, 0, sizeof(elink_session_ctx));
	log_();
	INIT_LIST_HEAD(&ctx->call_list);
	INIT_LIST_HEAD(&ctx->ap_list);
	INIT_LIST_HEAD(&ctx->msg_list);
	INIT_LIST_HEAD(&ctx->waitack_list);
	ctx->name = sdsnew("msg_layer");
	ctx->mode = get_elink_mode(); //client mode
	ctx->mac = sdsnew(client->mac);
	ctx->host = sdsnew(client->ip);
	ctx->ip = sdsnew(client->ip);
	ctx->gw = sdsnew(client->gw);
	ctx->keys.dh_p = sdsempty();
	ctx->keys.dh_g = sdsempty();
	ctx->keys.dh_pubkey = sdsempty();
	ctx->keys.dh_privkey = sdsempty();
	ctx->keys.dh_sharekey = sdsempty();
	ctx->client = client;
	log_d(ctx->dh_done);
	return ctx;
}

void msg_start_call(elink_client_ctx *client)
{
	elink_session_ctx * ctx = NULL;
	log_();
	if (!client->data)
	{
		ctx = elink_session_ctx_alloc(client);
		client->data = ctx; 
		log("this is a new client,alloc session context !!!");
	}
	else
		ctx = (elink_session_ctx *)client->data;
	ok(client->data != NULL);
	log_();
	for (int i = 0; i < ARRAY_SIZE(msg_login_calls); i++)
	{
		msg_add_to_list(ctx,&ctx->call_list,msg_login_calls[i]);                           //加入三个调用到链表中
	}

	uv_timer_init(uv_default_loop(),&ctx->timer_call_handle);
	uv_timer_start(&ctx->timer_call_handle,on_timer_call,0*1000,2*1000);       // 立马启动，10秒运行一次
}

elink_msg_t *find_msg(struct list_head *msg_list,sds type,sds mac,uint32_t sequence)
{
	log_();
	elink_msg_t *node = NULL,*next = NULL;
	log("find type:%s mac:%s seq:%u",type,mac,sequence);
	list_for_each_entry_safe(node,next,msg_list,list){
		log("node->cb_type:%s node->mac:%s node->seq:%u ",node->cb_type,node->mac,node->seq);
		if(!strcmp(node->cb_type,type) && !strcmp(node->mac,mac) && node->seq == sequence){
			list_del(&node->list);
			return node;
		}
	}
	return NULL;
}

void data_recved_handle(uv_stream_t *stream, uv_buf_t *recved_buf)
{
	cJSON *json = NULL;
	char *type = NULL;
	char *mac = NULL;
	uint32_t seq = 0;
	sds s_unpack_data = NULL;
	sds s_decrypto_data = NULL;
	elink_session_ctx * ctx = NULL;
	elink_msg_t *msg = NULL;

	elink_client_ctx *client = container_of(stream, elink_client_ctx, tcp_handle);
	if(!client->data){
		ctx = elink_session_ctx_alloc(client);
		client->data = ctx; 
		log("this is a new client,alloc session context !!!");
	}else
		ctx = (elink_session_ctx *)client->data;
	log_d(ctx->dh_done);
	ok(client != NULL);
	log_s(client->name);
	log_s(sdscatrepr(sdsempty(),recved_buf->base,recved_buf->len));
	s_unpack_data = elink_msg_unpack(ctx,recved_buf);
	// log_s(s_unpack_data);
	log_d(sdslen(s_unpack_data));
	s_decrypto_data = s_unpack_data;
	// log_d(ctx->dh_done);
	if(ctx->dh_done)
		s_decrypto_data = elink_msg_decrypto(s_unpack_data,ctx->keys.dh_sharekey);

	log_s(sdscatrepr(sdsempty(),s_decrypto_data,sdslen(s_decrypto_data)));
	json = cJSON_Parse(s_decrypto_data);
	log_p(json);
	if (json)
	{
		type = json_get_str(json, "type");
		mac = json_get_str(json, "mac");
		seq = json_get_int(json, "sequence");
		if (type && mac)
		{
			client->timestamp = uv_hrtime();
			log_d(get_elink_mode());
			int mode = get_elink_mode();
			// if(mode == ELINK_SERVER_MODE)         // TODO: 查找对应seq mac,创建msg或找到waitack链中对应的msg
			{
				msg = find_msg(&ctx->waitack_list,type,mac,seq);
				if(msg){
					msg->cb_json = cJSON_Duplicate(json, 1);
					msg_call_ret_check(ctx,msg);
				} else {
					msg = (elink_msg_t *)malloc(sizeof(elink_msg_t));
					memset(msg, 0, sizeof(*msg));
					msg->timestamp = client->timestamp;
					msg->call_type = sdsnew(type);
					msg->cb_type = sdsempty();
					log_s(msg->call_type);
					msg->mac = sdsnew(mac);
					msg->ip = sdsnew(ctx->ip);
					// msg->gw = sdsnew(ctx->gw);
					msg->seq = seq;
					msg->call_json = cJSON_Duplicate(json, 1);
					// if(!msg->client)
					msg->client = client;

					INIT_LIST_HEAD(&msg->list);
					list_add_tail(&msg->list, &ctx->msg_list);
					// msg->flag |= MSG_ST_IN_LIST;
					log("type:%s mac:%s sequence:%d", type, mac, seq);
					msg_cb_dispatch(ctx,msg);
				}

			}
			log_();
		}
		log_();
		JSON_FREE(json);
	}

	// elink_msg_free(msg);
	// SDS_FREE(s_unpack_data);

	// log_();
}

void msg_call_ret_check(elink_session_ctx * ctx,elink_msg_t *msg)
{
	log_e("TODO: msg_call_ret_check");
	log_s(msg->cb_type);
	ok(msg->cb_json != NULL);
	if(!strcmp(msg->cb_type,"dh")){
		cJSON *obj_data = cJSON_GetObjectItem(msg->cb_json,"data");
		log_s(cJSON_Print(msg->cb_json));
		ok(obj_data != NULL);
		char *peer_pubkey = json_get_str(obj_data,"dh_key");
		log_s(peer_pubkey);
		sds b64_peer_pubkey = sdsempty();
		log_();
		b64_peer_pubkey = sdscpy(b64_peer_pubkey,peer_pubkey);
		log_();
		sds s_peer_pubkey = unb64_block(b64_peer_pubkey);
		log_();
		gen_dh_sharekey(ctx->keys.dh_p,ctx->keys.dh_g,ctx->keys.dh_privkey,s_peer_pubkey,ctx->keys.dh_sharekey);
		log_();
	}
}

void msg_cb_dispatch(elink_session_ctx * ctx,elink_msg_t *msg)
{
	log_();
	for (int i = 0; i < ARRAY_SIZE(msg_call_map); i++)
	{
		if (!strcmp((const sds)msg_call_map[i].call_type,(const sds) msg->call_type))
		{
			log("msg->call_type=%s msg_call_map[%d].call_type=%s msg_call_map[%d].cb_type=%s", msg->call_type, i, msg_call_map[i].call_type, i, msg_call_map[i].cb_type);
			sdscpy(msg->call_type,msg_call_map[i].call_type);
			msg->call = msg_call_map[i].call;
			msg->after_call = msg_call_map[i].after_call;
			sdscpy(msg->cb_type,msg_call_map[i].cb_type);
			msg->cb = msg_call_map[i].cb;
			msg->after_cb = msg_call_map[i].after_cb;
			msg->msg_req.data = (void *)ctx;
			uv_queue_work(uv_default_loop(), &msg->msg_req, msg_call_map[i].cb, msg_call_map[i].after_cb);
			break;
		}
	}
}

sds elink_msg_decrypto(sds data,sds sharekey)
{
	log_();
	// log_sds_h(sharekey);
	return (sdslen(sharekey) != 16) ? data : aes128_cmd(data,sharekey,0);
}

sds elink_msg_crypto(sds data,sds sharekey)
{
	log_();
	// log_sds_h(sharekey);
	return (sdslen(sharekey) != 16) ? data : aes128_cmd(data,sharekey,1);
}

void on_msg_call_done(uv_write_t *req, int status)
{
    log_();
#ifdef CONFIG_MSG
	elink_msg_t *msg = container_of(req, elink_msg_t, wr_req);
	elink_session_ctx *ctx = (elink_session_ctx *)req->data;
    if (status)
    {
        log("Write error %s", uv_strerror(status));
    }
	if(!strcmp(msg->call_type,"dh"))
		ctx->dh_done = 1;
	// list_del(&msg->list);
	// INIT_LIST_HEAD(&msg->list); 	
	list_add_tail(&msg->list,&ctx->waitack_list);
#endif
	memset(req,0,sizeof(*req));
}

void on_msg_cb_done(uv_write_t *req, int status)
{
    log_();
#ifdef CONFIG_MSG
	elink_msg_t *msg = container_of(req, elink_msg_t, wr_req);
	elink_session_ctx *ctx = (elink_session_ctx *)req->data;
    if (status)
    {
        log("Write error %s", uv_strerror(status));
    }
	if(!strcmp(msg->cb_type,"dh"))
		ctx->dh_done = 1;
	
	list_del(&msg->list);
    msg_free(msg);
#endif
}

#define GET_WORK_MSG_CTX();        \
	elink_msg_t *msg = container_of(req, elink_msg_t, msg_req); \
	elink_session_ctx *ctx = (elink_session_ctx *)req->data; \
	if(!msg->call_json) msg->call_json = cJSON_CreateObject();  \
	if(!msg->cb_json) msg->cb_json = cJSON_CreateObject(); 

#define MSG_CALL_DEFAULT_VALUE(); \
	cJSON_AddStringToObject(msg->call_json, "type", (char *)msg->call_type); \
	cJSON_AddStringToObject(msg->call_json, "mac", (char*)msg->mac); \
	cJSON_AddNumberToObject(msg->call_json, "sequence", msg->seq);     

#define MSG_CB_DEFAULT_VALUE(); \
	cJSON_AddStringToObject(msg->cb_json, "type", (char *)msg->cb_type); \
	cJSON_AddStringToObject(msg->cb_json, "mac", (char*)msg->mac); \
	cJSON_AddNumberToObject(msg->cb_json, "sequence", msg->seq);

void msg_call_done(uv_work_t* req,int status)
{
	GET_WORK_MSG_CTX();

	sds s_data = NULL;
	sds s_crypto_data = NULL;
	sds s_send_data = NULL;

	// msg->seq = ctx->seq;
	msg->mac = sdsnew(ctx->mac);
	log_s(msg->call_type);
	// log_s(msg->cb_type);
	log_s(msg->mac);
	log_u(msg->seq);
	ok(msg->call_json != NULL);

	ctx->seq ++;
	
	log_s(msg->mac);
	log_s(ctx->name);
	ok(msg->cb_json != NULL);
	char *text = cJSON_Print(msg->call_json);
	s_data = sdsnew(text);

	log_s(sdscatrepr(sdsempty(),s_data,sdslen(s_data)));
	s_send_data = elink_msg_pack(ctx,s_data);
	log_s(sdscatrepr(sdsempty(),s_send_data,sdslen(s_send_data)));
	ok(s_send_data != NULL && sdslen(s_send_data) > 0);
	uv_buf_t buf = uv_buf_init(s_send_data,sdslen(s_send_data));

	msg->wr_req.data = ctx;
	ok(msg->client != NULL);
	uv_write(&msg->wr_req, (uv_stream_t *)&msg->client->tcp_handle, &buf, 1, on_msg_call_done);
	log_();

	SDS_FREE(s_data);
}

void msg_cb_done(uv_work_t* req,int status)
{
	log_();

	GET_WORK_MSG_CTX();

	sds s_data = NULL;
	sds s_send_data = NULL;

	log_s(msg->mac);
	log_s(ctx->name);
	log_();
	ok(msg->cb_json != NULL);
	char *text = cJSON_Print(msg->cb_json);
	s_data = sdsnew(text);
	// log_s(s_data);
	log_s(sdscatrepr(sdsempty(),s_data,sdslen(s_data)));
	s_send_data = elink_msg_pack(ctx,s_data);
	log_s(sdscatrepr(sdsempty(),s_send_data,sdslen(s_send_data)));

	ok(s_send_data != NULL );
	ok(sdslen(s_send_data) > 0);
	uv_buf_t buf = uv_buf_init(s_send_data,sdslen(s_send_data));
	msg->wr_req.data = ctx;
	uv_write(&msg->wr_req, (uv_stream_t *)&msg->client->tcp_handle, &buf, 1, on_msg_cb_done);
	// SDS_FREE(s_data);
	// free(req);
	memset(req,0,sizeof(*req));
	// JSON_FREE(msg->cb_json);
}

void msg_keepalive_call(uv_work_t* req)
{
	log_();
	GET_WORK_MSG_CTX();
	MSG_CALL_DEFAULT_VALUE();

}

void msg_ack_cb(uv_work_t* req)
{
	GET_WORK_MSG_CTX();
	MSG_CB_DEFAULT_VALUE();
	log_();
}

void msg_keyngreq_call(uv_work_t* req)
{
	GET_WORK_MSG_CTX();
	MSG_CALL_DEFAULT_VALUE();

	cJSON *arr = cJSON_CreateArray();
	cJSON *obj_keymode = cJSON_CreateObject();
	log_();
	cJSON_AddStringToObject(obj_keymode,"keymode","dh");
	log_();
	cJSON_AddItemToArray(arr,obj_keymode);
	log_();
	cJSON_AddItemToObject(msg->call_json,"keymodelist",arr);
	log_();
	// cJSON_AddStringToObject(msg->call_json,"version",ctx->version);
	cJSON_AddStringToObject(msg->call_json,"version","V2017.1.0");
	ok(msg->call_json != NULL);
	log_();


}

void msg_keyngreq_cb(uv_work_t* req)
{
	log_();
	GET_WORK_MSG_CTX();
	MSG_CB_DEFAULT_VALUE();

	cJSON_AddStringToObject(msg->cb_json, "keymode", "dh");
}

void msg_dh_call(uv_work_t* req)
{
	log_();
	GET_WORK_MSG_CTX();
	MSG_CALL_DEFAULT_VALUE();

	
	gen_dh_param(ctx->keys.dh_p,ctx->keys.dh_g);
	log_sds_h(ctx->keys.dh_p);
	log_sds_h(ctx->keys.dh_g);
	gen_dh_keypair(ctx->keys.dh_p,ctx->keys.dh_g,ctx->keys.dh_pubkey,ctx->keys.dh_privkey);
	log_sds_h(ctx->keys.dh_pubkey);
	log_sds_h(ctx->keys.dh_privkey);
	log_sds_h(ctx->keys.dh_sharekey);

	cJSON *send_obj_data = cJSON_CreateObject();

	sds b64_p = b64_block(ctx->keys.dh_p);                                     //将服务器公钥发给客户端
	sds b64_g = b64_block(ctx->keys.dh_g);                                     //将服务器公钥发给客户端
	sds b64_pubkey = b64_block(ctx->keys.dh_pubkey);                                     //将服务器公钥发给客户端
	log_s(b64_p);
	log_s(b64_g);
	log_s(b64_pubkey);
	cJSON_AddStringToObject(send_obj_data, "dh_p", b64_p);
	cJSON_AddStringToObject(send_obj_data, "dh_g", b64_g);
	cJSON_AddStringToObject(send_obj_data, "dh_key", b64_pubkey);
	cJSON_AddItemToObject(msg->call_json, "data", send_obj_data);

	SDS_FREE(b64_p);
	SDS_FREE(b64_g);
	SDS_FREE(b64_pubkey);
}

void msg_dh_cb(uv_work_t* req)
{
	log_();
	GET_WORK_MSG_CTX();
	MSG_CB_DEFAULT_VALUE();
	elink_server_ctx *server = get_elink_server_ctx();
	cJSON *rcev_obj_data = NULL,*send_obj_data = NULL;
	sds b64_p = NULL,b64_g = NULL, b64_peer_pubkey = NULL,b64_me_pubkey = NULL;
	sds s_p = NULL,s_g = NULL, s_peer_pubkey = NULL,s_me_pubkey = NULL , s_me_privkey = NULL;

	ok(msg->cb_json != NULL);

	rcev_obj_data = cJSON_GetObjectItem(msg->call_json, "data");
	ok(rcev_obj_data != NULL);
	if(!rcev_obj_data ) 
		goto end;
	b64_p = sdsnewlen(json_get_str(rcev_obj_data, "dh_p"),32);
	b64_g = sdsnewlen(json_get_str(rcev_obj_data, "dh_g"),32);
	b64_peer_pubkey = sdsnewlen(json_get_str(rcev_obj_data, "dh_key"),32);

	sdsupdatelen(b64_p);
	sdsupdatelen(b64_g);
	sdsupdatelen(b64_peer_pubkey);
	log_s(b64_p);
	log_s(b64_g);
	log_s(b64_peer_pubkey);
	s_p = unb64_block(b64_p);
	s_g = unb64_block(b64_g);
	s_peer_pubkey = unb64_block(b64_peer_pubkey);													//base64解密

	log_sds_h(s_p);
	log_sds_h(s_g);
	log_sds_h(s_peer_pubkey);

	ctx->keys.dh_p = s_p;
	ctx->keys.dh_g = s_g;
	ctx->keys.dh_pubkey = s_peer_pubkey;

	s_me_pubkey = sdsnewlen("",16);
	s_me_privkey = sdsnewlen("",16);

	gen_dh_keypair(s_p,s_g,s_me_pubkey,s_me_privkey);	
	log_sds_h(s_me_pubkey);
	log_sds_h(s_me_privkey);						//生成服务器秘钥对

	log_p(ctx->keys.dh_sharekey);
	gen_dh_sharekey(s_p,s_g,s_me_privkey,s_peer_pubkey,ctx->keys.dh_sharekey);	//生成共享秘钥

	log_sds_h(s_me_pubkey);
	log_sds_h(s_me_privkey);
	log_sds_h(ctx->keys.dh_sharekey);

	// send_json = cJSON_CreateObject();
	send_obj_data = cJSON_CreateObject();

	b64_me_pubkey = b64_block(s_me_pubkey);                                     //将服务器公钥发给客户端
	cJSON_AddStringToObject(send_obj_data, "dh_p", b64_p);
	cJSON_AddStringToObject(send_obj_data, "dh_g", b64_g);
	cJSON_AddStringToObject(send_obj_data, "dh_key", b64_me_pubkey);
	cJSON_AddItemToObject(msg->cb_json, "data", send_obj_data);

end:
	SDS_FREE(b64_p);
	SDS_FREE(b64_g);
	SDS_FREE(b64_peer_pubkey);
	SDS_FREE(b64_me_pubkey);

	// SDS_FREE(s_p);
	// SDS_FREE(s_g);
	// SDS_FREE(s_peer_pubkey);
	// SDS_FREE(b64_me_pubkey);
	// SDS_FREE(s_me_privkey);
}

void msg_dev_reg_call(uv_work_t* req)
{
	log_();
	GET_WORK_MSG_CTX();
	MSG_CALL_DEFAULT_VALUE();

}

void msg_dev_reg_cb(uv_work_t* req)
{
	log_();
	GET_WORK_MSG_CTX();
	MSG_CB_DEFAULT_VALUE();
}