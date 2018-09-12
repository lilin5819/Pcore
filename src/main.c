#include "adlist.h"
#include "log.h"
#include "core.h"

LOG_DEF();


int main(int argc, char const *argv[])
{
    set_log_app((char*)argv[0]);
    set_log_level(3);
    set_log_mode(_MODE_VERBOSE);
    pcore_ctx pcore = {
        .cfg = {
            .ip = ELINK_SERVER_IP,
            .port = ELINK_SERVER_PORT,
            .backlog = DEFAULT_BACKLOG,
            .mode = ELINK_MODE,
            .mode_name = ELINK_MODE_NAME,
        },
        .server = {
            //  .ip = ELINK_SERVER_IP,
            .name = (char *)argv[0],
        },
        .client = {
            .name = (char *)argv[0],
        },
    };
    // init_log((char*)argv[0]);
    // INIT_LIST_HEAD(&pcore.client.list);
    // INIT_LIST_HEAD(&pcore.server.client_list);
    // list_add_tail(&pcore.client.list,&pcore.server.client_list);
    // pcore.client.list = listCreate();
    pcore.server.client_list = listCreate();
    listAddNodeTail(pcore.server.client_list,&pcore.client);

    // server_ctx.client_list = &pcore.client.list;
    log_printf("start_pcore\n");
    log_string(pcore.cfg.mode_name);
    log_int(pcore.cfg.mode);

    start_pcore(&pcore);

    close_all();
    return 0;
}
