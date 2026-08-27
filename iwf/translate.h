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

/* sess_sweep hook: answer the Gn transaction a timed-out session still owes
 * osmo-sgsn, so a silent SGW-C never leaves the SGSN retransmitting. ctx is
 * the iwf_runtime_t*. */
void translate_sess_timeout(sess_t *s, void *ctx);

/* Context-transfer pending lookup for IMSI trace (SGSN Context / Context Req). */
int translate_ctx_trace_imsi_by_gn_seq(uint16_t gn_seq, char *imsi, size_t cap);
int translate_ctx_trace_imsi_by_v2_seq(uint32_t v2_seq24, char *imsi, size_t cap);

#endif /* IWF_TRANSLATE_H */
