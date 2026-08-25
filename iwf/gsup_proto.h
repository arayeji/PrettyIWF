/*
 * gsup_proto.h - Osmocom GSUP + IPA framing helpers (server-side proxy).
 *
 * IPA: [u16 BE len][proto=0xEE][ext=0x05][gsup_body...]
 * GSUP body: [msg_type][TLV IEs...]
 */

#ifndef IWF_GSUP_PROTO_H
#define IWF_GSUP_PROTO_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "map_session.h"

#define GSUP_IPA_PROTO_OSMO     0xEE
#define GSUP_IPA_EXT_GSUP       0x05

#define GSUP_MSG_UL_REQ         0x04
#define GSUP_MSG_UL_ERR         0x05   /* OSMO_GSUP_MSGT_UPDATE_LOCATION_ERROR */
#define GSUP_MSG_UL_RES         0x06
#define GSUP_MSG_SAI_REQ        0x08
#define GSUP_MSG_SAI_RES        0x0a
#define GSUP_MSG_SAI_ERR        0x09   /* OSMO_GSUP_MSGT_SEND_AUTH_INFO_ERROR (not 0x0b AUTH_FAIL_REPORT) */
#define GSUP_MSG_ISD_REQ        0x10
#define GSUP_MSG_ISD_ERR        0x11
#define GSUP_MSG_ISD_RES        0x12
#define GSUP_MSG_LOC_CANCEL_REQ 0x1c
/* SS/USSD over GSUP (osmo session-based supplementary services). */
#define GSUP_MSG_PROC_SS_REQ    0x20
#define GSUP_MSG_PROC_SS_ERR    0x21
#define GSUP_MSG_PROC_SS_RES    0x22
/* SMS over GSUP (osmo-msc `sms-over-gsup`). */
#define GSUP_MSG_MO_FSM_REQ     0x24
#define GSUP_MSG_MO_FSM_ERR     0x25
#define GSUP_MSG_MO_FSM_RES     0x26
#define GSUP_MSG_MT_FSM_REQ     0x28
#define GSUP_MSG_MT_FSM_ERR     0x29
#define GSUP_MSG_MT_FSM_RES     0x2a

#define GSUP_IE_IMSI            0x01
#define GSUP_IE_CAUSE           0x02
#define GSUP_IE_AUTH_TUPLE      0x03
#define GSUP_IE_PDP_INFO_COMPL  0x04
#define GSUP_IE_PDP_INFO        0x05
#define GSUP_IE_CANCEL_TYPE     0x06
#define GSUP_IE_MSISDN          0x08
#define GSUP_IE_HLR_NUMBER      0x09
#define GSUP_IE_NUM_VECTORS     0x0a
#define GSUP_IE_PDP_CONTEXT_ID  0x10
#define GSUP_IE_PDP_ADDRESS     0x11
#define GSUP_IE_APN             0x12
#define GSUP_IE_PDP_QOS         0x13
#define GSUP_IE_CN_DOMAIN       0x28
#define GSUP_IE_RAND            0x20   /* osmo GSUP resync (top-level IE) */
#define GSUP_IE_AUTS            0x26
#define GSUP_IE_NUM_VECTORS_REQ 0x52   /* OSMO_GSUP_NUM_VECTORS_REQ_IE */
/* SMS over GSUP IEs (osmo gsup_sms). */
#define GSUP_IE_SM_RP_MR        0x40   /* message reference (1 byte)      */
#define GSUP_IE_SM_RP_DA        0x41   /* [id-type][addr]; 0x01 = IMSI    */
#define GSUP_IE_SM_RP_OA        0x42   /* [id-type][addr]; 0x03 = SMSC    */
#define GSUP_IE_SM_RP_UI        0x43   /* SM TPDU                          */
#define GSUP_IE_SM_RP_CAUSE     0x44   /* GSM 04.11 RP cause               */
#define GSUP_IE_SM_RP_MMS       0x45   /* more messages to send            */
/* Session IEs (osmo GSUP session-based messages, e.g. SS/USSD). */
#define GSUP_IE_SESSION_ID      0x30   /* 4 bytes BE                       */
#define GSUP_IE_SESSION_STATE   0x31   /* 1 byte                           */
#define GSUP_IE_SS_INFO         0x35   /* raw GSM 04.80 facility component */

#define GSUP_SESSION_STATE_NONE     0x00
#define GSUP_SESSION_STATE_BEGIN    0x01
#define GSUP_SESSION_STATE_CONTINUE 0x02
#define GSUP_SESSION_STATE_END      0x03

#define GSUP_RESYNC_RAND_LEN    16
#define GSUP_RESYNC_AUTS_LEN    14

/* GSUP cause = GSM 04.08 GMM cause. IMSI-unknown is a *permanent* reject
 * (UE marks the SIM invalid); use NET_FAIL for transient failures. */
#define GSUP_CAUSE_IMSI_UNKNOWN    0x02
#define GSUP_CAUSE_PLMN_NOTALLOWED 0x0b
#define GSUP_CAUSE_ROAM_NOTALLOWED 0x0d
#define GSUP_CAUSE_NET_FAIL        0x11

#define GSUP_AUTH_UMTS          0x01
#define GSUP_AUTH_GSM           0x02

#define GSUP_CN_DOMAIN_PS       0x01
#define GSUP_CN_DOMAIN_CS       0x02

typedef struct {
    uint8_t  msg_type;
    char     imsi[16];
    bool     have_imsi;
    uint8_t  num_vectors;
    bool     have_num_vectors;
    uint8_t  cn_domain;
    bool     have_cn_domain;
    uint8_t  resync_rand[GSUP_RESYNC_RAND_LEN];
    uint8_t  resync_auts[GSUP_RESYNC_AUTS_LEN];
    bool     have_resync_rand;
    bool     have_resync_auts;
    uint8_t  sm_rp_mr;
    bool     have_sm_rp_mr;
    uint8_t  sm_rp_cause;
    bool     have_sm_rp_cause;
    /* Raw SM-RP-DA/OA as carried in GSUP: [id-type][address bytes]. */
    uint8_t  sm_rp_da[24];
    uint8_t  sm_rp_da_len;
    uint8_t  sm_rp_oa[24];
    uint8_t  sm_rp_oa_len;
    uint8_t  sm_rp_ui[256];
    uint16_t sm_rp_ui_len;
    /* SS/USSD session (PROC_SS_*). */
    uint32_t session_id;
    bool     have_session_id;
    uint8_t  session_state;
    bool     have_session_state;
    uint8_t  ss_info[512];
    uint16_t ss_info_len;
} gsup_parsed_t;

#define gsup_parsed_have_resync(p) \
    ((p) && (p)->have_resync_rand && (p)->have_resync_auts)

int  gsup_parse_payload(const uint8_t *body, size_t len, gsup_parsed_t *out);
int  gsup_imsi_from_payload(const uint8_t *body, size_t len,
                            char *imsi_out, size_t cap);

int  gsup_build_sai_res(const char *imsi,
                        const map_auth_vector_t *vec, size_t n_vec,
                        uint8_t *out, size_t cap);
int  gsup_build_sai_err(const char *imsi, uint8_t cause,
                        uint8_t *out, size_t cap);
int  gsup_build_ul_res(const char *imsi, const char *msisdn,
                       const map_ula_apn_entry_t *apns, size_t n_apns,
                       uint8_t cn_domain, const char *hlr_number,
                       uint8_t *out, size_t cap);
int  gsup_build_ul_err(const char *imsi, uint8_t cause,
                       uint8_t *out, size_t cap);
int  gsup_build_isd_req(const char *imsi, const char *msisdn,
                        const map_ula_apn_entry_t *apns, size_t n_apns,
                        uint8_t cn_domain, const char *hlr_number,
                        uint8_t *out, size_t cap);
int  gsup_build_loc_cancel_req(const char *imsi, uint8_t cancel_type,
                               uint8_t *out, size_t cap);
/* MT-ForwardSM req toward osmo-msc. sc_addr = MAP AddressString
 * (TON/NPI byte + TBCD digits) of the originating SMSC. */
int  gsup_build_mt_fsm_req(const char *imsi, uint8_t sm_rp_mr,
                           const uint8_t *sc_addr, size_t sc_addr_len,
                           const uint8_t *tpdu, size_t tpdu_len,
                           int more_to_send,
                           uint8_t *out, size_t cap);
/* MO-ForwardSM outcome toward osmo-msc (relay result from home SMSC). */
int  gsup_build_mo_fsm_res(const char *imsi, uint8_t sm_rp_mr,
                           uint8_t *out, size_t cap);
int  gsup_build_mo_fsm_err(const char *imsi, uint8_t sm_rp_mr,
                           uint8_t rp_cause, uint8_t *out, size_t cap);

/* SS/USSD session message (PROC_SS_REQ/RES/ERR). ss_info may be NULL for
 * a bare state transition (e.g. ERROR/END without payload). */
int  gsup_build_proc_ss(uint8_t msg_type, const char *imsi,
                        uint32_t session_id, uint8_t session_state,
                        const uint8_t *ss_info, size_t ss_info_len,
                        uint8_t *out, size_t cap);

int  gsup_ipa_wrap(const uint8_t *gsup, size_t gsup_len,
                   uint8_t *out, size_t cap);

#endif /* IWF_GSUP_PROTO_H */
