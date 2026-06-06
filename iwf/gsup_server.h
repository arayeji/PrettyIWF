/*
 * gsup_server.h - TCP GSUP server with multi-IP listen (IPA framing).
 */

#ifndef IWF_GSUP_SERVER_H
#define IWF_GSUP_SERVER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

struct iwf_runtime;

enum gsup_epoll_role {
    GSUP_EPOLL_ROLE_LISTEN = 0x106,
    GSUP_EPOLL_ROLE_CONN   = 0x107,
};

#define GSUP_EPOLL_PACK(role, idx) \
    ((uint64_t)(role) | ((uint64_t)(uint32_t)(idx) << 32))
#define GSUP_EPOLL_ROLE(u64)    ((uint32_t)(u64))
#define GSUP_EPOLL_INDEX(u64)   ((uint32_t)((u64) >> 32))

int  gsup_server_init(struct iwf_runtime *rt, int epfd);
void gsup_server_shutdown(void);
bool gsup_server_enabled(void);

void gsup_server_on_epoll(struct iwf_runtime *rt, uint64_t tag);

int  gsup_server_send(int conn_id, const uint8_t *gsup, size_t len);
const char *gsup_server_conn_bind_ip(int conn_id);
const char *gsup_server_conn_peer(int conn_id);
bool gsup_server_conn_valid(int conn_id);

#endif /* IWF_GSUP_SERVER_H */
