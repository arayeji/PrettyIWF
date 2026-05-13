/*
 * runtime.h - process-wide handles shared between main and translate.
 */

#ifndef IWF_RUNTIME_H
#define IWF_RUNTIME_H

#include "iwf.h"
#include "config.h"

typedef struct iwf_runtime {
    iwf_config_t       cfg;
    int                v1_sock;            /* GTPv1-C UDP socket */
    int                v2_sock;            /* GTPv2-C UDP socket */
    struct sockaddr_in sgwc_addr;          /* SGW-C peer */
    uint32_t           local_ipv4_be;      /* our S4 source IP, network order */
    uint32_t           v2_seq;             /* monotonically increasing GTPv2 seq */
} iwf_runtime_t;

int  iwf_send_v1(iwf_runtime_t *rt, const iwf_endpoint_t *to,
                 const uint8_t *buf, size_t len);
int  iwf_send_v2(iwf_runtime_t *rt, const uint8_t *buf, size_t len);

#endif /* IWF_RUNTIME_H */
