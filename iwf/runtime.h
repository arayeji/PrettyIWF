/*
 * runtime.h - process-wide handles shared between main and translate.
 */

#ifndef IWF_RUNTIME_H
#define IWF_RUNTIME_H

#include "iwf.h"
#include "config.h"

/* Forward decl - actual struct lives in map_iwf.c. The runtime keeps a
 * void pointer so this header doesn't pull libosmo-sigtran into every
 * translation unit. */
struct map_iwf_state;

typedef struct iwf_runtime {
    iwf_config_t       cfg;
    int                v1_sock;            /* GTPv1-C UDP socket */
    int                v2_sock;            /* GTPv2-C UDP socket */
    struct sockaddr_in sgwc_addr;          /* SGW-C peer */
    struct sockaddr_in sgsn_gtp_addr;        /* osmo-sgsn Gn GTP-C (Context Req) */
    struct sockaddr_in mme_gtp_addr;         /* outbound GTPv2-C (Gn→MME SCR relay) */
    uint32_t           local_ipv4_be;      /* our S4 source IP, network order */
    uint32_t           v2_seq;             /* monotonically increasing GTPv2 seq */
    uint32_t           gn_seq;             /* outgoing GTPv1-C sequence (Context Req) */

    /* MAP-IWF (only populated when [map_iwf].enabled = 1).  All fields are
     * managed by map_iwf.c; main.c only reads the fds for epoll dispatch. */
    struct map_iwf_state *map;
} iwf_runtime_t;

int  iwf_send_v1(iwf_runtime_t *rt, const iwf_endpoint_t *to,
                 const uint8_t *buf, size_t len);
int  iwf_send_v2(iwf_runtime_t *rt, const uint8_t *buf, size_t len);
int  iwf_send_v2_addr(iwf_runtime_t *rt, const struct sockaddr_in *to,
                      socklen_t tolen, const uint8_t *buf, size_t len);

#endif /* IWF_RUNTIME_H */
