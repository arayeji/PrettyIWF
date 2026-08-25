/*
 * ussd_iwf.h - USSD relay between GSUP (osmo-msc session-based SS) and
 * MAP networkUnstructuredSsContext-v2 dialogues toward partner HLRs.
 *
 *   MO USSD:  roamer on our MSC dials *xxx#  ->  GSUP PROC_SS (BEGIN)
 *             -> MAP TCAP BEGIN processUnstructuredSS-Request toward the
 *             subscriber's home HLR (E.214/hlr_gt route), responses are
 *             relayed back as GSUP PROC_SS_RESULT.
 *
 *   NI USSD:  partner HLR/USSD-GW sends unstructuredSS-Request/-Notify
 *             for a roamer attached to our MSC -> GSUP PROC_SS toward
 *             the MSC, phone's answer goes back on the TCAP dialogue.
 *
 * The GSM 04.80 facility (the TCAP component) is relayed opaquely in the
 * GSUP SS_INFO IE - no USSD string decoding in the IWF.
 */

#ifndef IWF_USSD_IWF_H
#define IWF_USSD_IWF_H

#include <stdbool.h>
#include "gsup_proto.h"
#include "ss7_link.h"
#include "tcap.h"

struct iwf_runtime;

/* GSUP PROC_SS_{REQ,RES,ERR} received from the MSC. */
void ussd_iwf_on_gsup_ss(struct iwf_runtime *rt, int conn_id,
                         const gsup_parsed_t *m);

/* Inbound TCAP BEGIN with unstructuredSS-Request/-Notify (network
 * initiated USSD toward a roamer on our network). */
void ussd_iwf_on_ni_begin(struct iwf_runtime *rt,
                          const ss7_sccp_addr_t *calling,
                          const tcap_msg_t *tmsg,
                          const tcap_component_t *c);

/* TCAP CONTINUE/END/ABORT routing: returns true if the dtid belongs to a
 * USSD session (message consumed). */
bool ussd_iwf_on_tcap(struct iwf_runtime *rt,
                      const ss7_sccp_addr_t *calling,
                      const tcap_msg_t *tmsg);

/* Answer an inbound USSD BEGIN we cannot serve with TCAP END returnError
 * (e.g. processUnstructuredSS-Request for a home subscriber - no USSD
 * application behind the IWF). */
void ussd_iwf_reject_begin(struct iwf_runtime *rt,
                           const ss7_sccp_addr_t *calling,
                           const tcap_msg_t *tmsg,
                           const tcap_component_t *c, int map_err);

#endif /* IWF_USSD_IWF_H */
