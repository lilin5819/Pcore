#include <uv.h>
#include <stdlib.h>

void on_connect(uv_connect_t *conn, int status)
{
    if (status < 0)
    {
        printf("New connection error %s\n", uv_strerror(status));
        return;
    }
    printf("on_connect\n");

    // uv_tcp_init(uv_default_loop(), &tcp_handle);
    // // uv_tcp_keepalive(client,1, 10*000);
    // if (uv_accept(stream, (uv_stream_t *)&tcp_handle) == 0)
    // {
    //     uv_read_start((uv_stream_t *)&tcp_handle, read_alloc_cb, on_read);
    // }
    // else
    // {
    //     uv_close((uv_handle_t *)&cp_handle, NULL);
    // }
    return;
}


int main(int argc, char const *argv[])
{
    uv_tcp_t *socket = (uv_tcp_t *)malloc(sizeof(uv_tcp_t));
    uv_tcp_init(uv_default_loop(), socket);

    uv_connect_t *connect = (uv_connect_t *)malloc(sizeof(uv_connect_t));

    struct sockaddr_in dest;
    uv_ip4_addr("192.168.101.1", 80, &dest);

    uv_tcp_connect(connect, socket, (const struct sockaddr *)&dest, on_connect);
    uv_run(uv_default_loop(), UV_RUN_DEFAULT);
    return 0;
}
