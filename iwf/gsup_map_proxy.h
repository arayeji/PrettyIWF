/*
 * gsup_map_proxy.h - GSUP request routing + MAP/Diameter interworking.
 */

#ifndef IWF_GSUP_MAP_PROXY_H
#define IWF_GSUP_MAP_PROXY_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include "tcap.h"
#include "ss7_link.h"
#include "map_session.h"

void gsup_map_proxy_init(struct iwf_runtime *rt);
void gsup_map_proxy_shutdown(void);
void gsup_map_proxy_on_conn_closed(int conn_id);

void gsup_map_proxy_on_gsup(struct iwf_runtime *rt, int conn_id,
                            const uint8_t *gsup, size_t len);

void gsup_map_proxy_finish_sai(struct iwf_runtime *rt, struct map_session *s);
void gsup_map_proxy_finish_ugl(struct iwf_runtime *rt, struct map_session *s);
void gsup_map_proxy_abort_ugl(struct iwf_runtime *rt, struct map_session *s);
int  gsup_map_proxy_send_isd(struct iwf_runtime *rt, struct map_session *s);
void gsup_map_proxy_on_timeout(struct iwf_runtime *rt, struct map_session *s);
void gsup_map_proxy_diameter_error(struct iwf_runtime *rt,
                                   struct map_session *s,
                                   uint32_t diameter_result_code);

bool gsup_map_proxy_on_tcap(struct iwf_runtime *rt,
                            const ss7_sccp_addr_t *calling,
                            const tcap_msg_t *tmsg);

void gsup_map_proxy_sweep(struct iwf_runtime *rt, time_t now);

/* HSS-initiated Diameter CLR -> GSUP Location-Cancel.
 * cn_domain: GSUP_CN_DOMAIN_CS, GSUP_CN_DOMAIN_PS, or 0 = both.
 * Returns true if at least one LOC-CANCEL was sent. */
bool gsup_map_proxy_hss_clr(struct iwf_runtime *rt, const char *imsi,
                            uint8_t cancel_type, uint8_t cn_domain);

/* HSS-initiated Diameter IDR Subscription-Data -> GSUP ISD toward MSC/SGSN.
 * cn_domain must be CS or PS. Returns true if ISD_REQ was sent. */
bool gsup_map_proxy_hss_idr(struct iwf_runtime *rt, const char *imsi,
                            uint8_t cn_domain, const char *msisdn,
                            const map_ula_apn_entry_t *apns, size_t n_apns);

/* True if IMSI has a live tracked GSUP connection for cn_domain (or either
 * if cn_domain == 0). */
bool gsup_map_proxy_imsi_known(const char *imsi, uint8_t cn_domain);

/* Tracked CS-domain GSUP conn for IMSI (MT-SMS delivery), or -1. */
int gsup_map_proxy_cs_conn_for_imsi(const char *imsi);

/* Remember the MSISDN learned for an attached IMSI (from ISD) so inbound
 * sendRoutingInformation can resolve called-MSISDN -> IMSI. */
void gsup_map_proxy_note_msisdn(const char *imsi, const char *msisdn);

/* Reverse lookup: MSISDN digits (any common normalization) -> IMSI.
 * Returns 0 and fills imsi_out on hit, -1 when unknown. */
int gsup_map_proxy_imsi_for_msisdn(const char *msisdn,
                                   char *imsi_out, size_t cap);

/* HSS IDR(URRP-MME): report UE reachability via S6a NOR. */
void gsup_map_proxy_on_urrp(struct iwf_runtime *rt, const char *imsi,
                            const char *diam_origin_host);

#endif /* IWF_GSUP_MAP_PROXY_H */
