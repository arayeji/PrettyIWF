/*
 * gtp_trace.h - per-IMSI GTPv1/v2-C packet trace with session correlation.
 *
 * Resolves IMSI from wire IEs, session TEID indices, pending GTPv2 seq, and
 * context-transfer pending state so responses without an IMSI IE are traced.
 */

#ifndef IWF_GTP_TRACE_H
#define IWF_GTP_TRACE_H

#include "iwf.h"

#include <stddef.h>
#include <stdint.h>

void iwf_gtp_trace_rx_v1(const uint8_t *buf, size_t len, const iwf_msg_t *msg);
void iwf_gtp_trace_rx_v2(const uint8_t *buf, size_t len, const iwf_msg_t *msg);
void iwf_gtp_trace_tx_v1(const uint8_t *buf, size_t len);
void iwf_gtp_trace_tx_v2(const uint8_t *buf, size_t len);

#endif /* IWF_GTP_TRACE_H */
