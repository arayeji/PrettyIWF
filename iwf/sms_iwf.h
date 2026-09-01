#ifndef IWF_SMS_IWF_H
#define IWF_SMS_IWF_H

#include <stdint.h>
#include <stdbool.h>

#include "ss7_link.h"
#include "tcap.h"
#include "gsup_proto.h"

struct iwf_runtime;

enum sms_iwf_epoll_role {
    SMS_EPOLL_ROLE_SMPP_SRV  = 0x201,
    SMS_EPOLL_ROLE_SMPP_CONN = 0x202,
    SMS_EPOLL_ROLE_GSUP_SOCK   = 0x203,
    SMS_EPOLL_ROLE_SMS_TIMER   = 0x204,
    SMS_EPOLL_ROLE_GSUP_TIMER  = 0x205,
};

int  sms_iwf_init(struct iwf_runtime *rt, int epfd);
void sms_iwf_shutdown(struct iwf_runtime *rt);
bool sms_iwf_enabled(const struct iwf_runtime *rt);

/* Inbound MT-SMS delivery (partner SMSC -> our roamer): MAP [mt-]forwardSM
 * BEGIN dispatched from map_iwf, delivered to osmo-msc via GSUP
 * MT-ForwardSM (requires `sms-over-gsup` on the MSC). */
void sms_iwf_on_mt_fsm(struct iwf_runtime *rt,
                       const ss7_sccp_addr_t *calling,
                       const tcap_msg_t *tmsg,
                       const tcap_component_t *c);
void sms_iwf_on_gsup_mt_resp(const gsup_parsed_t *msg);
/* A CS Location Update finished: release any MT-SMS parked for that IMSI. */
void sms_iwf_on_cs_lu_done(const char *imsi);

/* Outbound MO-SMS relay (our subscriber -> home SMSC): GSUP MO-ForwardSM
 * from osmo-msc (sms-over-gsup) -> MAP mo-ForwardSM BEGIN
 * (shortMsgMO-RelayContext-v3) to the SMSC in SM-RP-DA -> GSUP MO
 * result/error back to the MSC. */
void sms_iwf_on_gsup_mo_req(int conn_id, const gsup_parsed_t *msg);
/* READY-FOR-SM from osmo-msc (UE reachable / memory available again):
 * relay MAP readyForSM to the home HLR so its SMSC retries waiting SMs. */
void sms_iwf_on_gsup_ready_for_sm(int conn_id, const gsup_parsed_t *msg);
/* Returns true if the CONTINUE/END belonged to an MO-SMS or readyForSM
 * dialogue. */
bool sms_iwf_on_mo_tcap(struct iwf_runtime *rt, const tcap_msg_t *tmsg);

/* SS7 dispatch is via ss7_link HLR recv callback registered at init. */
void sms_iwf_on_smpp_srv_readable(void);
void sms_iwf_on_smpp_conn_readable(void);
void sms_iwf_on_gsup_readable(void);
void sms_iwf_on_gsup_keepalive(void);
void sms_iwf_on_timer(void);

#endif /* IWF_SMS_IWF_H */
