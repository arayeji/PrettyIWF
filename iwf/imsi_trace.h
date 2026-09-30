/*
 * imsi_trace.h - runtime per-IMSI trace filters and PACKET logging.
 *
 * Filter management mirrors Pretty5GS / Open5GS ogs_trace_filter_*:
 *   prefix match (default) or exact match via ?match=exact on the admin API.
 *
 * When an IMSI matches a filter, DEBUG-level logs and PACKET lines are emitted
 * even if the global log level is error.
 */

#ifndef IWF_IMSI_TRACE_H
#define IWF_IMSI_TRACE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define IWF_IMSI_TRACE_LEN          16
#define IWF_IMSI_TRACE_MAX_FILTERS  32
#define IWF_IMSI_TRACE_PACKET_MAX   4608
#define IWF_IMSI_TRACE_PACKET_PER_S 200

void iwf_imsi_trace_init(void);
void iwf_imsi_trace_shutdown(void);

/* Filter list (thread-safe; main epoll thread + metrics HTTP). */
void iwf_imsi_trace_clear(void);
int  iwf_imsi_trace_add(const char *imsi, bool exact);
int  iwf_imsi_trace_replace(const char *imsi, bool exact);
int  iwf_imsi_trace_remove(const char *imsi);
bool iwf_imsi_trace_match(const char *imsi);
int  iwf_imsi_trace_count(void);
int  iwf_imsi_trace_get(int index, char *buf, size_t buflen, bool *exact_out);

/* Load comma-separated prefixes from config at startup. */
void iwf_imsi_trace_load_config(const char *csv);

/* Admin API query (Pretty5GS-compatible). Returns HTTP status. */
typedef struct {
    const char *imsi;
    const char *match;   /* "exact" or NULL */
    int         remove;
    int         replace;
    int         force;
} iwf_imsi_trace_query_t;

int iwf_imsi_trace_admin(const iwf_imsi_trace_query_t *q,
                         char *body, size_t body_cap, size_t *body_len);

/* PACKET line:
 *   [IMSI:<imsi>] PACKET: proto=<name> dir=<rx|tx> len=<n> [frame=ipv4]
 *                 [trunc=1] b64=<base64>
 *
 * frame=ipv4: b64 is a rebuilt IPv4 packet (see trace_frame.h) and len is
 * its length. Without it, b64 is the application payload only.
 */
void iwf_imsi_trace_packet(const char *imsi, const char *proto, const char *dir,
                           const void *data, size_t len);
void iwf_imsi_trace_packet_frame(const char *imsi, const char *proto,
                                 const char *dir, const void *frame, size_t len);

/* [logging] trace_packet_layer: true = ip (default), false = app. */
void iwf_imsi_trace_set_frames(bool on);
/* True when a filter is active and the layer is ip; gate frame building. */
bool iwf_imsi_trace_frames_wanted(void);

/* Transport hooks. A TX frame is used for the next "tx" PACKET of proto
 * whose payload equals app. The RX frame is used for "rx" PACKETs of proto
 * whose payload lies inside frame[payload_off, payload_off+payload_len),
 * until iwf_imsi_trace_clear_rx_frame(). */
void iwf_imsi_trace_offer_tx_frame(const char *proto,
                                   const void *app, size_t app_len,
                                   const void *frame, size_t frame_len);
void iwf_imsi_trace_offer_rx_frame(const char *proto,
                                   const void *frame, size_t frame_len,
                                   size_t payload_off, size_t payload_len);
void iwf_imsi_trace_clear_rx_frame(void);

/* Defer RX trace until IMSI is known (BEGIN decode, MSISDN lookup, or
 * TCAP/Diameter correlation of an answer that carries no IMSI). The bind
 * copies the PDU so it still works if the handler returns before flush. */
void iwf_imsi_trace_bind_rx(const char *proto, const void *data, size_t len);
void iwf_imsi_trace_flush_rx(const char *imsi);
void iwf_imsi_trace_drop_rx(void);

/* Remember a TCAP transaction id or Diameter hop-by-hop id for a traced
 * IMSI so later answers (result/error, AIA, …) still attach to the filter. */
void iwf_imsi_trace_remember_tcap(uint32_t tid, const char *imsi);
void iwf_imsi_trace_remember_diam_hbh(uint32_t hbh, const char *imsi);
int  iwf_imsi_trace_imsi_for_tcap(uint32_t tid, char *imsi_out, size_t cap);
int  iwf_imsi_trace_imsi_for_diam_hbh(uint32_t hbh, char *imsi_out, size_t cap);

/* Park the current RX bind (or an outbound PDU) under a TCAP tid when IMSI
 * is not known yet (SRI-SM waiting on GSUP, outbound SRI-SM, …). */
void iwf_imsi_trace_park_rx(uint32_t tid);
void iwf_imsi_trace_park_pdu(uint32_t tid, const char *proto, const char *dir,
                             const void *data, size_t len);
void iwf_imsi_trace_flush_parked(uint32_t tid, const char *imsi);

/* Finish an RX: emit bind/parked PDUs if imsi is known or correlated,
 * otherwise park under dtid/otid. */
void iwf_imsi_trace_finish_rx(uint32_t dtid, bool have_dtid,
                               uint32_t otid, bool have_otid,
                               const char *imsi);

/* MSISDN-only packets (SIP INVITE, ISUP IAM, CAP IDP, SMPP). Resolves
 * through the same map/HSS lookup as SRI. No-op when unknown. */
int  iwf_imsi_trace_imsi_for_msisdn(const char *msisdn,
                                    char *imsi_out, size_t cap);
void iwf_imsi_trace_packet_msisdn(const char *msisdn, const char *proto,
                                  const char *dir, const void *data, size_t len);

#endif /* IWF_IMSI_TRACE_H */
