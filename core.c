#include "server.h"
#include "elink.h"
#include "msg.h"
#include "log.h"

#define DEFAULT_BACKLOG 128


elink_ctx *g_elink_ctx = NULL;
elink_server_ctx *g_server_ctx = NULL;
struct list_head *g_client_list = NULL;

LOG_INIT("elink_server");

struct list_head *get_client_list(void)
{
	log_();
	// INIT_LIST_HEAD(&g_client_list);
	return g_elink_ctx->server->client_list;
}

static void close_walk_cb(uv_handle_t *handle, void *arg)
{
    if (!uv_is_closing(handle))
        uv_close(handle, NULL);
}

static void close_all(void)
{
    uv_walk(uv_default_loop(), close_walk_cb, NULL);
    uv_loop_close(uv_default_loop());
}

static void signal_cb(uv_signal_t *handle, int signum)
{
    log_d(signum);
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

static void check_cb(uv_check_t *handle)
{
    // log_();
}

static void close_cb(uv_handle_t *handle)
{
    log_();
}

static void timer_cb(uv_timer_t *handle)
{

}

elink_ctx *get_elink_ctx(void)
{
    return g_elink_ctx;
}

elink_server_ctx *get_elink_server_ctx(void)
{
    return g_elink_ctx->server;
}

elink_client_ctx *get_elink_client_ctx(void)
{
    return g_elink_ctx->client;
}

void get_if_ip(char *ifname) {
    char buf[512];
    uv_interface_address_t *info;
    int count, i;

    uv_interface_addresses(&info, &count);
    i = count;

    printf("Number of interfaces: %d\n", count);
    while (i--) {
        uv_interface_address_t interface = info[i];

        printf("Name: %s\n", interface.name);
        printf("Internal? %s\n", interface.is_internal ? "Yes" : "No");
        
        if (interface.address.address4.sin_family == AF_INET) {
            uv_ip4_name(&interface.address.address4, buf, sizeof(buf));
            printf("IPv4 address: %s\n", buf);
        }
        else if (interface.address.address4.sin_family == AF_INET6) {
            uv_ip6_name(&interface.address.address6, buf, sizeof(buf));
            printf("IPv6 address: %s\n", buf);
        }

        printf("\n");
    }

    uv_free_interface_addresses(info, count);
}

void read_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    elink_client_ctx *client = container_of(handle, elink_client_ctx, tcp_handle);
    log_();
    *buf = uv_buf_init((char*) malloc(suggested_size), suggested_size);
    // log_s(client->name);
    client->recv_buf = buf;
    // log_p(client->recv_buf->base);
    // log_d(client->recv_buf->len);
}

void on_write(uv_write_t *req, int status)
{
    log_();
    if (status)
    {
        log("Write error %s", uv_strerror(status));
    }
    free(req);
}

void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
#ifndef CONFIG_SERVER
    elink_client_ctx *ctx = container_of(stream, elink_client_ctx, tcp_handle);
#else
    elink_server_ctx *ctx = container_of(stream, elink_server_ctx, tcp_handle);
#endif
    uv_buf_t recved_buf;
    ok(ctx != NULL);
    log_d(nread);
    // log_s(g_server_ctx->name);
    log_s(ctx->name);

    if (nread < 0)
    {
        if (nread != UV_EOF)
            log("Read error %s ,close it", uv_err_name(nread));
        uv_close((uv_handle_t *)stream, NULL);
        log_e("close client");
    }
    else if (nread > 0)
    {
        // log_p(buf->base);
        // log_s(buf->base+ELINK_HEADER_LEN);
        recved_buf.base = buf->base;
        recved_buf.len = nread;
#ifdef CONFIG_MSG
        recved_handle(stream, &recved_buf);
#endif
    }

    if (buf->base)
        free(buf->base);
}

void client_ctx_free(elink_client_ctx *client_ctx)
{
    ok(client_ctx != NULL);
    if (!client_ctx)
        return;
    if(client_ctx->list.next && client_ctx->list.prev)
        list_del(&client_ctx->list);
#ifdef CONFIG_MSG
    FREE(client_ctx->name);
    FREE(client_ctx->ip);
    FREE(client_ctx->mac);
    FREE(client_ctx);
    msg_list_free(&client_ctx->msg_list);
#endif
}

elink_client_ctx *client_ctx_alloc(void)
{
    elink_client_ctx *client = (elink_client_ctx *)malloc(sizeof(elink_client_ctx));
    ok(client != NULL);
    if (!client)
        goto error;
    memset(client, 0, sizeof(*client));
    // client->tcp_handle = tcp_handle;
    client->name = strdup("client");
    INIT_LIST_HEAD(&client->list);
    // log_s(client->name);

    return client;

error:
    client_ctx_free(client);
    return NULL;
}

void on_new_connection(uv_stream_t *stream, int status)
{
    if (status < 0)
    {
        log("New connection error %s", uv_strerror(status));
        return;
    }
    elink_server_ctx *server = container_of(stream, elink_server_ctx, tcp_handle);
    ok(server != NULL);
    log_s(server->name);
    // log_s(g_server_ctx->name);
    // uv_tcp_t *client_tcp_handle = (uv_tcp_t*) malloc(sizeof(uv_tcp_t));
    elink_client_ctx *client = client_ctx_alloc();
    ok(client != NULL);
    if (!client)
        goto error;
    list_add_tail(&client->list, server->client_list);

    uv_tcp_init(uv_default_loop(), &client->tcp_handle);
    // uv_tcp_keepalive(client,1, 10*000);
    if (uv_accept(stream, (uv_stream_t *)&client->tcp_handle) == 0)
    {
        log_();

        uv_read_start((uv_stream_t *)&client->tcp_handle, read_alloc_cb, on_read);
    }
    else
    {
        log_();
        uv_close((uv_handle_t *)&client->tcp_handle, NULL);
    }
    return;

error:
    uv_close((uv_handle_t *)&client->tcp_handle, NULL);
    client_ctx_free(client);
    return;
}

void init_server(elink_server_ctx *server, elink_net_t *net)
{
    struct sockaddr_in addr;
    ok(0 == uv_tcp_init(uv_default_loop(), &server->tcp_handle));
    ok(0 == uv_ip4_addr(net->ip, net->port, &addr));
    ok(0 == uv_tcp_bind(&server->tcp_handle, (struct sockaddr *)&addr, 0));
    ok(0 == uv_listen((uv_stream_t *)&server->tcp_handle, 10, on_new_connection));
}

void init_client(elink_client_ctx *client, elink_net_t *net)
{
    struct sockaddr_in addr;
    ok(0 == uv_tcp_init(uv_default_loop(), &client->tcp_handle));
    ok(0 == uv_ip4_addr(net->ip, net->port, &addr));
    ok(0 == uv_tcp_bind(&client->tcp_handle, (struct sockaddr *)&addr, 0));
    ok(0 == uv_listen((uv_stream_t *)&client->tcp_handle, 10, on_new_connection));
}

int main(int argc, char const *argv[])
{
    elink_server_ctx server_ctx = {
            .ip = "0.0.0.0",
            .name = (char *)argv[0],
        };
    elink_client_ctx client_ctx = {
            // .loop = uv_default_loop(),
            .name = (char *)argv[0],
        };

    elink_ctx elink = {
        .net = {
            .ip = "0.0.0.0",
            .port = ELINK_SERVER_PORT,
        },
        .server = &server_ctx,
        .client = &client_ctx,
        .tcp_handle = &server_ctx.tcp_handle,
    };
    INIT_LIST_HEAD(&client_ctx.list);
#ifdef CONFIG_MSG
    INIT_LIST_HEAD(&client_ctx.msg_list);
    INIT_LIST_HEAD(&server_ctx.msg_list);
#endif
    g_elink_ctx = &elink;
    g_server_ctx = &server_ctx;
    g_client_list = &client_ctx.list;
    server_ctx.client_list = &client_ctx.list;
    log("start_server");

    ok(0 == uv_idle_init(uv_default_loop(), &elink.idle_handle));
    ok(0 == uv_idle_start(&elink.idle_handle, idle_cb));

    ok(0 == uv_check_init(uv_default_loop(), &elink.check_handle));
    ok(0 == uv_check_start(&elink.check_handle, check_cb));

    ok(0 == uv_signal_init(uv_default_loop(), &elink.signal_handle));
    ok(0 == uv_signal_start(&elink.signal_handle, signal_cb, SIGINT));

    // ok(0 == uv_signal_start(&signal_handle, signal_cb,SIGPIPE));
    ok(0 == uv_timer_init(uv_default_loop(), &elink.timer_handle));
    ok(0 == uv_timer_start(&elink.timer_handle, timer_cb, 1 * 1000, 5 * 1000));

    init_server(elink.server, &elink.net);

    ok(0 == uv_run(uv_default_loop(), UV_RUN_DEFAULT));

    close_all();
    return 0;
}
