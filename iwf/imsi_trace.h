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
#define IWF_IMSI_TRACE_PACKET_MAX   2048
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
 *   [IMSI:<imsi>] PACKET: proto=<name> dir=<rx|tx> len=<n> [trunc=1] b64=<base64>
 */
void iwf_imsi_trace_packet(const char *imsi, const char *proto, const char *dir,
                           const void *data, size_t len);

/* Defer RX trace until IMSI is known (BEGIN decode or session lookup). */
void iwf_imsi_trace_bind_rx(const char *proto, const void *data, size_t len);
void iwf_imsi_trace_flush_rx(const char *imsi);

#endif /* IWF_IMSI_TRACE_H */
