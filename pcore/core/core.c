#include "core.h"
#include "env.h"
#include "log.h"
#include "zmalloc.h"

#ifdef CONFIG_MSG
#include "msg.h"
#endif
static int online = 0;

pcore_ctx *g_pcore_ctx = NULL;
pcore_server_ctx *g_server_ctx = NULL;
struct list *g_client_list = NULL;


int get_pcore_mode(void)
{
    return g_pcore_ctx->cfg.mode;
}

pcore_ctx *get_pcore_ctx(void)
{
    return g_pcore_ctx;
}

pcore_server_ctx *get_pcore_server_ctx(void)
{
    return &g_pcore_ctx->server;
}

pcore_client_ctx *get_pcore_client_ctx(void)
{
    return &g_pcore_ctx->client;
}

void on_client_mode_connect(uv_connect_t *conn, int status)
{
    pcore_client_ctx *client = container_of(conn, pcore_client_ctx, conn);

    if (status < 0)
    {
        log_printf("New connection error %s\n", uv_strerror(status));
        // zfree(conn);
        memset(conn,0,sizeof(*conn));
        uv_close((uv_handle_t *)&client->tcp_handle,close_cb);
        client->online = 0;
        return;
    }
    // log_();
    client->online = 1;
    // uv_timer_init(uv_default_loop(),);
#ifdef CONFIG_MSG
    msg_start_call(client);
#endif
	uv_read_start((uv_stream_t *)&client->tcp_handle, read_alloc_cb, read_cb);
    log_int(client->online);
    return;
}

static void close_walk_cb(uv_handle_t *handle, void *arg)
{
    if (!uv_is_closing(handle))
        uv_close(handle, NULL);
}

void close_all(void)
{
    uv_walk(uv_default_loop(), close_walk_cb, NULL);
    uv_loop_close(uv_default_loop());
}

static void signal_cb(uv_signal_t *handle, int signum)
{
    log_int(signum);
    if (signum == 2)
    {
        uv_signal_stop(handle);
        close_all();
    }
}

static void idle_cb(uv_idle_t *handle)
{
    // log_();
}
// TODO: 客户端关闭时，网络检测恢复为勤奋检测，做好会话层的消息等资源回收
static void check_cb(uv_check_t *handle)
{
    // log_();
}

void close_cb(uv_handle_t *handle)
{
    log_();
}

void read_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    pcore_client_ctx *client = container_of(handle, pcore_client_ctx, tcp_handle);
    log_();
    *buf = uv_buf_init((char*) zmalloc(suggested_size), suggested_size);
    client->recv_buf = buf;
}

void read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    log_();
    pcore_client_ctx *ctx = container_of(stream, pcore_client_ctx, tcp_handle);
    if(ctx == g_client_list->head->value){
        log_printf("this is pcore core client\n");
        log_s(ctx->name);   //will print client
        log_s(ctx->gw);   //will print client
        log_s(ctx->mac);   //will print client
        log_s(ctx->ip);   //will print client
    }else{
        log_printf("another client\n");
    }

    uv_buf_t recved_buf;
    ok(ctx != NULL);
    log_int(nread);
    // log_s(g_server_ctx->name);

    if (nread < 0)
    {
        if (nread != UV_EOF)
            log_printf("Read error %s ,close it\n", uv_err_name(nread));
        uv_close((uv_handle_t *)stream, close_cb);
        log_error("close client\n");
    }
    else if (nread > 0)
    {
        recved_buf.base = buf->base;
        recved_buf.len = nread;
#ifdef CONFIG_MSG
        data_recved_handle(stream, &recved_buf);
#endif
    }

    zfree(buf->base);
}

void client_ctx_free(pcore_client_ctx *client_ctx)
{
    ok(client_ctx != NULL);
    if (!client_ctx)
        return;
    // if(client_ctx->list.next && client_ctx->list.prev)
    //     list_del(&client_ctx->list);
    listDelNode(g_client_list,(void*)client_ctx);
    FREE(client_ctx->name);
    FREE(client_ctx);
}

pcore_client_ctx *client_ctx_alloc(void)
{
    log_();
    pcore_client_ctx *client = (pcore_client_ctx *)zmalloc(sizeof(pcore_client_ctx));
    ok(client != NULL);
    if (!client)
        goto error;
    memset(client, 0, sizeof(*client));
    client->name = strdup("client");
    client->timestamp = uv_hrtime();
    log_lu(client->timestamp);
    // INIT_LIST_HEAD(&client->list);

    return client;

error:
    client_ctx_free(client);
    return NULL;
}

void on_server_mode_connect(uv_stream_t *stream, int status)
{
    if (status < 0)
    {
        log_printf("New connection error %s\n", uv_strerror(status));
        return;
    }
    pcore_server_ctx *server = container_of(stream, pcore_server_ctx, tcp_handle);
    ok(server != NULL);
    log_s(server->name);
    pcore_client_ctx *client = client_ctx_alloc();
    ok(client != NULL);
    if (!client)
        goto error;

    uv_tcp_init(uv_default_loop(), &client->tcp_handle);
    if (uv_accept(stream, (uv_stream_t *)&client->tcp_handle) == 0)
    {
        log_();

        // list_add_tail(&client->list, &server->client_list);
        listAddNodeTail(server->client_list,client);
        uv_read_start((uv_stream_t *)&client->tcp_handle, read_alloc_cb, read_cb);
    }
    else
    {
        log_();
        uv_close((uv_handle_t *)&client->tcp_handle, close_cb);
    }
    return;

error:
    log_error("close client");
    uv_close((uv_handle_t *)&client->tcp_handle, close_cb);
    client_ctx_free(client);
    return;
}


// TODO: 完善网络检测层，自连自回收，实现勤奋检测和懒惰检测的自动切换和被动切换
static void timer_netcheck_cb(uv_timer_t *handle)
{
    pcore_ctx *pcore = container_of(handle, pcore_ctx, timer_netcheck_handle);
    if(pcore->cfg.mode == ELINK_SERVER_MODE) return;

    char * ipstr = get_if_ipstr("wlan0");
    char * macstr = get_if_macstr("wlan0");
    char * gw = get_gw();

    if(!ipstr && pcore->client.online == 1){
        uv_close((uv_handle_t*)&pcore->client.tcp_handle,close_cb);
        pcore->client.online = 0;
        return;
    }
    if(!gw || pcore->client.online == 1)
        return;
    // log_s(ipstr);
    // log_s(gw);
    pcore->client.online = 1;
    pcore->client.ip = "127.0.0.1";
    pcore->client.mac = strdup(macstr);
    pcore->client.gw = "127.0.0.1";
    ok(0 == uv_tcp_init(uv_default_loop(), &pcore->client.tcp_handle));
    ok(0 == uv_ip4_addr("127.0.0.1", ELINK_SERVER_PORT, &pcore->client.addr));
    ok(0 == uv_tcp_connect(&pcore->client.conn,&pcore->client.tcp_handle,(struct sockaddr *)&pcore->client.addr,on_client_mode_connect));

    FREE(ipstr);
    FREE(macstr);
    FREE(gw);
}

int add_layer(pcore_ctx *pcore,pcore_layer_t *layer)
{
    switch(layer->type)
    {
        LAYER_SIGNAL:
            ok(0 == uv_signal_init(uv_default_loop(), (uv_signal_t*)&layer->handle));
            ok(0 == uv_signal_start((uv_signal_t*)&layer->handle, layer->cb.signal, ((int *)layer->data)[0]));
            break;
        LAYER_TIMER:
            ok(0 == uv_timer_init(uv_default_loop(), (uv_timer_t*)&layer->handle));
            ok(0 == uv_timer_start((uv_timer_t*)&layer->handle, layer->cb.timer,((uint64_t*)layer->data)[0], ((uint64_t*)layer->data)[1]));
            break;
        LAYER_CHECK:
            ok(0 == uv_check_init(uv_default_loop(), (uv_check_t*)&layer->handle));
            ok(0 == uv_check_start((uv_check_t*)&layer->handle, layer->cb.check));
            break;
    }
    // ok(0 == dictAdd(pcore->layer_map,layer->name,layer));
    return 0;
}


void start_pcore(pcore_ctx *pcore)
{
    pcore_server_ctx *server = &pcore->server;
    pcore_client_ctx *client = &pcore->client;
    pcore_cfg_t *cfg = &pcore->cfg;

    // ok(0 == uv_idle_init(uv_default_loop(), &pcore->idle_handle));
    // ok(0 == uv_idle_start(&pcore->idle_handle, idle_cb));

    ok(0 == uv_check_init(uv_default_loop(), &pcore->check_handle));
    ok(0 == uv_check_start(&pcore->check_handle, check_cb));

    ok(0 == uv_signal_init(uv_default_loop(), &pcore->signal_handle));
    ok(0 == uv_signal_start(&pcore->signal_handle, signal_cb, SIGINT));

    // ok(0 == uv_signal_start(&signal_handle, signal_cb,SIGPIPE));
    ok(0 == uv_timer_init(uv_default_loop(), &pcore->timer_netcheck_handle));
    ok(0 == uv_timer_start(&pcore->timer_netcheck_handle, timer_netcheck_cb, 1 * 1000, 1 * 1000));

    g_pcore_ctx = pcore;
    g_server_ctx = &pcore->server;
    g_client_list = pcore->server.client_list;

    // pcore->layer_map = dictCreate(NULL,NULL);

    if(cfg->mode == ELINK_SERVER_MODE){
        // set_log_file("/var/pcore_server.log_printf");

        log_printf("pcore in server mode\n");
        ok(0 == uv_tcp_init(uv_default_loop(), &server->tcp_handle));
        ok(0 == uv_ip4_addr(cfg->ip, cfg->port, &server->addr));
        ok(0 == uv_tcp_bind(&server->tcp_handle, (struct sockaddr *)&server->addr, 0));
        ok(0 == uv_listen((uv_stream_t *)&server->tcp_handle, cfg->backlog,on_server_mode_connect));
    } else {
        // set_log_file("/var/pcore_client.log_printf");

        log_printf("pcore in client mode , connect server in timer_netcheck\n");
    }

    ok(0 == uv_run(uv_default_loop(), UV_RUN_DEFAULT));

}


