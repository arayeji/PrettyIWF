/*
 * map_codec.h - MAP (3GPP TS 29.002) BER codec for the IWF.
 *
 * We handle only the operations our IWF cares about:
 *
 *   SendAuthenticationInfo       opcode 56  (Authentication info retrieval)
 *   UpdateGprsLocation           opcode 23  (Mobility management)
 *   UpdateLocation               opcode  2  (MAP-C)
 *   InsertSubscriberData         opcode  7  (Subscriber-data insertion)
 *   CancelLocation               opcode  3
 *   PurgeMS                      opcode 67
 *   ProvideRoamingNumber         opcode  4  (MSRN allocation)
 *
 * Each operation has a Req struct populated by the decoder and an Encoder
 * helper to build the ReturnResult parameters going back. The "raw" message
 * payload is the value of the Invoke/Result Component's parameters field.
 *
 * MAP application contexts referenced (3GPP TS 29.002 §17.5):
 *   infoRetrievalContext-v3        1.3.12.0.0.4.401.0.0.1.13.3
 *   gprsLocationUpdateContext-v3   1.3.12.0.0.4.401.0.0.1.32.3
 *   subscriberDataMngtContext-v3   1.3.12.0.0.4.401.0.0.1.16.3
 *   locationCancellationContext-v3 1.3.12.0.0.4.401.0.0.1.2.3
 *   gprsLocationCancellationCtx-v3 1.3.12.0.0.4.401.0.0.1.7.3
 *   msPurgingContext-v3            1.3.12.0.0.4.401.0.0.1.27.3
 *
 * The codec stores the application context OID for outgoing dialogues
 * so the AARQ/AARE in the dialogue portion can be emitted correctly.
 */

#ifndef IWF_MAP_CODEC_H
#define IWF_MAP_CODEC_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "map_session.h"

/* MAP operation codes (TS 29.002 §17.5 - "local value" form). */
#define MAP_OP_CODE_UPDATE_LOCATION         2
#define MAP_OP_CODE_CANCEL_LOCATION         3
#define MAP_OP_CODE_PROVIDE_ROAMING_NUMBER  4
#define MAP_OP_CODE_INSERT_SUBSCRIBER_DATA  7
#define MAP_OP_CODE_SEND_ROUTING_INFO       22  /* sendRoutingInformation (MT call) */
#define MAP_OP_CODE_UPDATE_GPRS_LOCATION    23
#define MAP_OP_CODE_SEND_AUTH_INFO          56
#define MAP_OP_CODE_PURGE_MS                67
#define MAP_OP_CODE_SEND_ROUTING_INFO_SM    45
#define MAP_OP_CODE_MT_FORWARD_SM           46  /* forwardSM (v1/v2) / mo-forwardSM (v3) */
#define MAP_OP_CODE_MT_FORWARD_SM_V3        44  /* mt-forwardSM (MAP v3) */
#define MAP_OP_CODE_PROVIDE_SUBSCRIBER_INFO 70
#define MAP_OP_CODE_READY_FOR_SM            66  /* VLR -> HLR MW alert */
/* USSD (TS 29.002 supplementary services). */
#define MAP_OP_CODE_PROCESS_USS_REQ         59  /* processUnstructuredSS-Request */
#define MAP_OP_CODE_USS_REQUEST             60  /* unstructuredSS-Request (NI)   */
#define MAP_OP_CODE_USS_NOTIFY              61  /* unstructuredSS-Notify (NI)    */

/* MAP error codes we may receive/send (TS 29.002 §17.6). */
#define MAP_ERR_UNKNOWN_SUBSCRIBER          1
#define MAP_ERR_ABSENT_SUBSCRIBER_SM        6   /* MAP v3 SMS */
#define MAP_ERR_ABSENT_SUBSCRIBER           27  /* MAP v1/v2 SMS */
#define MAP_ERR_ROAMING_NOT_ALLOWED         8
#define MAP_ERR_FACILITY_NOT_SUPPORTED      21
#define MAP_ERR_DELIVERY_FAILURE            32
#define MAP_ERR_SYSTEM_FAILURE              34
#define MAP_ERR_DATA_MISSING                35
#define MAP_ERR_UNEXPECTED_DATA_VALUE       36
#define MAP_ERR_NO_ROAMING_NUMBER_AVAILABLE 39
#define MAP_ERR_AUTHENTICATION_FAILURE      52

/* ----- decoded request views -------------------------------------- */

typedef struct {
    uint8_t  imsi_bcd[8];
    uint8_t  imsi_bcd_len;
    char     imsi_str[16];

    /* Optional sgsn-Address (TBCD IPv4 or v6).  Stored verbatim. */
    uint8_t  sgsn_addr[16];
    uint8_t  sgsn_addr_len;

    /* requestedVectors (default 1, max 5). */
    uint8_t  num_vectors;

    /* requestingNodeType (TS 29.002): 0=vlr, 1=sgsn ...  */
    uint8_t  requesting_node_type;
    bool     have_requesting_node_type;

    /* sgsn-Number (BCD E.164, MSC/SGSN GT).  Lets us derive the PLMN. */
    uint8_t  sgsn_number_bcd[8];
    uint8_t  sgsn_number_bcd_len;
} map_sai_req_t;

typedef struct {
    uint8_t  imsi_bcd[8];
    uint8_t  imsi_bcd_len;
    char     imsi_str[16];
    uint8_t  sgsn_number_bcd[8];
    uint8_t  sgsn_number_bcd_len;
    /* sgsn-Address (TS 29.002 GSN-Address; IPv4 is 4 bytes after BCD len). */
    uint8_t  sgsn_addr[16];
    uint8_t  sgsn_addr_len;
} map_ugl_req_t;

/* MAP-C UpdateLocationArg (networkLocUpContext). */
typedef struct {
    uint8_t  imsi_bcd[8];
    uint8_t  imsi_bcd_len;
    char     imsi_str[16];
    char     msc_number[24];   /* E.164 digits from msc-Number */
    char     vlr_number[24];   /* E.164 digits from vlr-Number */
} map_ul_req_t;

typedef struct {
    uint8_t  imsi_bcd[8];
    uint8_t  imsi_bcd_len;
    char     imsi_str[16];
    /* CancellationType: 0=updateProcedure, 1=subscriptionWithdraw. */
    uint8_t  cancellation_type;
} map_cl_req_t;

typedef struct {
    uint8_t  imsi_bcd[8];
    uint8_t  imsi_bcd_len;
    char     imsi_str[16];
} map_purge_req_t;

typedef struct {
    uint8_t  imsi_bcd[8];
    uint8_t  imsi_bcd_len;
    char     imsi_str[16];
    char     msc_number[24];            /* E.164 digits */
    char     msisdn[24];                /* optional */
    bool     suppression_of_announcement;
    bool     have_gsm_bearer_cap;       /* present but not fully decoded */
} map_prn_req_t;

/* ----- decoders ----------------------------------------------------- */

int map_decode_sai_arg     (const uint8_t *p, size_t n, map_sai_req_t *out);
int map_decode_ugl_arg     (const uint8_t *p, size_t n, map_ugl_req_t *out);
int map_decode_ul_arg      (const uint8_t *p, size_t n, map_ul_req_t  *out);
int map_decode_cl_arg      (const uint8_t *p, size_t n, map_cl_req_t  *out);
int map_decode_purge_arg   (const uint8_t *p, size_t n, map_purge_req_t *out);
int map_decode_prn_arg     (const uint8_t *p, size_t n, map_prn_req_t *out);

/* ProvideRoamingNumberRes: roamingNumber ISDN-AddressString. */
int map_encode_prn_res(const char *msrn_digits, uint8_t *out, size_t out_cap);

/* sendRoutingInformation (opcode 22, MT voice call).
 * Arg decoder extracts only msisdn [0]; Res encoder emits the MAP v3
 * [3] SEQUENCE { imsi [9], roamingNumber } form. */
int map_decode_sri_arg(const uint8_t *p, size_t n,
                       char *msisdn_out, size_t cap);
int map_encode_sri_res(const char *imsi_str, const char *msrn_digits,
                       uint8_t *out, size_t out_cap);

/* MAP SMS (TS 29.002) — used by sms_iwf when SMS_IWF_ENABLED. */
int map_decode_sri_sm_arg(const uint8_t *p, size_t n, char *msisdn_out, size_t cap);
int map_decode_sri_sm_res(const uint8_t *p, size_t n,
                          uint8_t *imsi_bcd, size_t *imsi_bcd_len,
                          char *vmsc_gt_out, size_t vmsc_cap);
int map_encode_sri_sm_arg(const char *msisdn_digits,
                          uint8_t *out, size_t out_cap);
int map_encode_sri_sm_res(const char *imsi_digits, const char *msc_gt_digits,
                          uint8_t *out, size_t out_cap);
int map_encode_mt_fwd_sm_arg(const char *imsi_digits, const char *smsc_gt_digits,
                             const uint8_t *tpdu, size_t tpdu_len,
                             uint8_t *out, size_t out_cap);
/* Decode inbound MT-ForwardSM-Arg / ForwardSM-Arg (delivery to our roamer):
 * sm-RP-DA imsi [0], sm-RP-OA serviceCentreAddressOA [4] (raw AddressString
 * incl. TON/NPI byte), sm-RP-UI OCTET STRING, moreMessagesToSend NULL. */
int map_decode_mt_fsm_arg(const uint8_t *p, size_t n,
                          char *imsi_out, size_t imsi_cap,
                          uint8_t *sc_addr, size_t sc_cap, size_t *sc_len,
                          const uint8_t **ui, size_t *ui_len,
                          int *more);
/* MO submission relay: [MO-]ForwardSM-Arg with sm-RP-DA =
 * serviceCentreAddressDA, sm-RP-OA = msisdn, sm-RP-UI = SMS-SUBMIT TPDU. */
int map_encode_mo_fwd_sm_arg(const char *smsc_digits, const char *oa_msisdn,
                             const uint8_t *tpdu, size_t tpdu_len,
                             uint8_t *out, size_t out_cap);

/* ReadyForSM-Arg (our VLR -> home HLR): imsi [0], alertReason ENUMERATED
 * (0 = ms-Present, 1 = memoryAvailable). */
int map_encode_ready_for_sm_arg(const char *imsi_str, uint8_t alert_reason,
                                uint8_t *out, size_t out_cap);

/* provideSubscriberInfo (HLR/gsmSCF -> our VLR). */
int map_decode_psi_arg(const uint8_t *p, size_t n,
                       char *imsi_out, size_t imsi_cap);
int map_encode_psi_res(int reachable, uint8_t not_reach_reason,
                       uint8_t *out, size_t out_cap);

/* ----- encoders (for the IWF -> SGSN direction) ------------------- */

/* MAP SendAuthenticationInfo Invoke/ReturnResult (IWF -> foreign HLR). */
int map_encode_sai_arg(const char *imsi_str, uint8_t num_vectors,
                       uint8_t *out, size_t out_cap);
int map_decode_sai_res(const uint8_t *p, size_t n,
                       map_auth_vector_t *vec, size_t vec_cap, size_t *n_vec);

/* MAP SendAuthenticationInfo ReturnResult, AuthenticationSetList of vectors. */
int map_encode_sai_res(const map_auth_vector_t *vec, size_t n_vec,
                       uint8_t *out, size_t out_cap);

/* MAP UpdateLocation Invoke (IWF/VLR -> foreign HLR, MAP-C).
 * msc_gt / vlr_gt are E.164 digit strings (ISDN-AddressString with 0x91). */
int map_encode_ul_arg(const char *imsi_str,
                      const char *msc_gt_digits,
                      const char *vlr_gt_digits,
                      uint8_t *out, size_t out_cap);
/* UpdateLocationRes — same hlr-Number shape as UGL Res. */
int map_decode_ul_res(const uint8_t *p, size_t n,
                      uint8_t *hlr_bcd, size_t hlr_cap, size_t *hlr_len,
                      char *hlr_digits, size_t hlr_digits_cap);

/* MAP InsertSubscriberData Invoke from HLR (inbound on networkLocUp). */
int map_decode_isd_arg(const uint8_t *p, size_t n,
                       char *imsi_out, size_t imsi_cap,
                       char *msisdn_out, size_t msisdn_cap);

/* MAP UpdateGprsLocation Invoke (IWF -> foreign HLR). */
int map_encode_ugl_arg(const char *imsi_str,
                       const uint8_t *sgsn_number_bcd, size_t sgsn_num_len,
                       const uint8_t *sgsn_addr, size_t sgsn_addr_len,
                       uint8_t *out, size_t out_cap);
int map_decode_ugl_res(const uint8_t *p, size_t n,
                       uint8_t *hlr_bcd, size_t hlr_cap, size_t *hlr_len);

/* MAP UpdateGprsLocation ReturnResult: hlr-Number + optional extensions. */
int map_encode_ugl_res(const uint8_t *hlr_number_bcd, size_t hlr_len,
                       uint8_t *out, size_t out_cap);

/* MAP InsertSubscriberData Invoke argument (sent toward SGSN as a separate
 * dialogue between ULA and UGL response). Carries MSISDN + full GPRS PDP
 * list (gprsSubscriptionData) built from the ULA APN-Configuration list. */
int map_encode_isd_arg(const char *imsi_str,
                       const char *msisdn_str,
                       const map_ula_apn_entry_t *apns,
                       size_t n_apns,
                       uint8_t default_context_id,
                       bool cs_vlr_isd,
                       uint8_t *out, size_t out_cap);

/* Diameter / MAP MSISDN AVP → digit string (TBCD or ASCII). */
void map_msisdn_avp_to_str(const uint8_t *data, size_t n,
                           char *out, size_t cap);

/* Normalize MSISDN digits for MAP ISDN-AddressString (E.164, Iran 98…). */
void map_normalize_msisdn_digits(const char *in, char *out, size_t cap);

/* MAP CancelLocation Invoke argument (HSS-originated CLR -> we Invoke CL). */
int map_encode_cl_arg(const uint8_t *imsi_bcd, size_t imsi_bcd_len,
                      uint8_t cancellation_type,
                      uint8_t *out, size_t out_cap);

/* MAP PurgeMS ReturnResult (FreezeTMSI/FreezePtmsi flags). */
int map_encode_purge_res(bool freeze_ptmsi,
                         uint8_t *out, size_t out_cap);

/* MAP ReturnError parameter encoding for SystemFailure-style errors:
 * just the diagnostic (optional).  Caller provides the error code separately
 * via tcap_enc_return_error(). */
int map_encode_systemfailure_diag(uint8_t network_resource,
                                  uint8_t *out, size_t out_cap);

/* ----- BCD helpers (TS 24.008 §10.5.1.3 etc.) --------------------- */

void map_bcd_to_str  (const uint8_t *bcd, size_t bcd_len, char *out, size_t cap);
int  map_str_to_bcd  (const char *digits, uint8_t *out, size_t out_cap);
/* Visited-PLMN-Id is 3 BCD octets: MCC + MNC packed per TS 24.008. */
int  map_plmn_pack   (uint16_t mcc, uint16_t mnc, uint8_t out[3]);
int  map_plmn_unpack (const uint8_t in[3], uint16_t *mcc, uint16_t *mnc);
/* Home PLMN (MCC 432 + configured MNC) for Visited-PLMN-Id on S6d. */
int  map_plmn_pack_home(const char *mnc_digits, uint8_t out[3]);
/* 3GPP Diameter realm from PLMN: mncXXX.mccYYY.3gppnetwork.org */
int  map_plmn_to_diam_realm(uint16_t mcc, uint16_t mnc, char *out, size_t cap);

/* ----- AARQ/AARE dialogue portion helpers ------------------------- */

/* Application Context Name OIDs used in our MAP dialogues.  Caller passes
 * the operation we are initiating; we return the matching OID bytes. */
typedef enum {
    MAP_AC_INFO_RETRIEVAL_V3        = 1, /* sendAuthInfo                   */
    MAP_AC_GPRS_LOCATION_UPDATE_V3  = 2, /* updateGprsLocation             */
    MAP_AC_SUBSCRIBER_DATA_MGMT_V3  = 3, /* insertSubscriberData           */
    MAP_AC_GPRS_LOCATION_CANCEL_V3  = 4, /* cancelLocation over Gr         */
    MAP_AC_MS_PURGING_V3            = 5, /* purgeMS                        */
    MAP_AC_NETWORK_LOC_UP_V3        = 6, /* updateLocation (MAP-C)         */
    MAP_AC_ROAMING_NUMBER_ENQUIRY_V3 = 7, /* provideRoamingNumber           */
    MAP_AC_SHORT_MSG_MO_RELAY_V2    = 8, /* forwardSM (MO submit, v2)      */
    MAP_AC_NETWORK_UNSTRUCTURED_SS_V2 = 9, /* processUnstructuredSS (USSD) */
    MAP_AC_MWD_MNGT_V2              = 10, /* readyForSM (MW alerting)       */
} map_app_ctx_t;

int map_encode_aarq(map_app_ctx_t ac, uint8_t *out, size_t out_cap);
int map_encode_aare(map_app_ctx_t ac, uint8_t *out, size_t out_cap);
int map_decode_aarq_ac(const uint8_t *p, size_t n, map_app_ctx_t *out);
/* Extract the raw application-context OID from an AARQ dialogue blob, and
 * build an AARE (accepted) echoing an arbitrary AC OID - used to answer
 * dialogues whose AC we don't model (e.g. shortMsgMT-Relay v1/v2/v3). */
int map_decode_aarq_ac_raw(const uint8_t *p, size_t n,
                           uint8_t *oid_out, size_t cap, size_t *oid_len);
int map_encode_aare_oid(const uint8_t *ac_oid, size_t ac_oid_len,
                        uint8_t *out, size_t out_cap);
/* Target IMSI from the MAP-open destinationReference (network-initiated
 * USSD). Returns 0 and fills imsi_out on success. */
int map_decode_dialogue_dest_ref(const uint8_t *p, size_t n,
                                 char *imsi_out, size_t cap);

#endif /* IWF_MAP_CODEC_H */
