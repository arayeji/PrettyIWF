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

/* HSS-initiated Diameter CLR -> GSUP Location-Cancel toward osmo-sgsn. */
bool gsup_map_proxy_hss_clr(struct iwf_runtime *rt, const char *imsi,
                            uint8_t cancel_type);

#endif /* IWF_GSUP_MAP_PROXY_H */
