/*
 * translate.h - the heart of the IWF.
 *
 * One direction is "northbound": GTPv1-C request from osmo-sgsn arrives,
 * IWF builds a GTPv2-C request and sends it to SGW-C.
 *
 * The other direction is "southbound": GTPv2-C response from SGW-C arrives,
 * IWF builds a GTPv1-C response and sends it back to osmo-sgsn.
 *
 * No GTP-U is ever produced.  The SGW-U F-TEID returned in the GTPv2-C
 * Create Session Response is propagated to osmo-sgsn so the RNC will send
 * GTP-U directly to UPG-VPP (Direct Tunnel).
 */

#ifndef IWF_TRANSLATE_H
#define IWF_TRANSLATE_H

#include "iwf.h"
#include "session.h"

struct iwf_runtime;     /* forward */

/* Northbound: handle a parsed GTPv1-C request from osmo-sgsn. */
int translate_v1_request(struct iwf_runtime *rt,
                         const iwf_endpoint_t *from,
                         const iwf_msg_t *v1);

/* Southbound: handle a parsed GTPv2-C response from SGW-C. */
int translate_v2_response(struct iwf_runtime *rt,
                          const iwf_endpoint_t *from,
                          const iwf_msg_t *v2);

#endif /* IWF_TRANSLATE_H */
