/*
 * map_codec.h - MAP (3GPP TS 29.002) BER codec for the IWF.
 *
 * We handle only the five operations our IWF cares about:
 *
 *   SendAuthenticationInfo       opcode 56  (Authentication info retrieval)
 *   UpdateGprsLocation           opcode 23  (Mobility management)
 *   InsertSubscriberData         opcode  7  (Subscriber-data insertion)
 *   CancelLocation               opcode  3
 *   PurgeMS                      opcode 67
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
#define MAP_OP_CODE_CANCEL_LOCATION         3
#define MAP_OP_CODE_INSERT_SUBSCRIBER_DATA  7
#define MAP_OP_CODE_UPDATE_GPRS_LOCATION    23
#define MAP_OP_CODE_SEND_AUTH_INFO          56
#define MAP_OP_CODE_PURGE_MS                67
#define MAP_OP_CODE_SEND_ROUTING_INFO_SM    45
#define MAP_OP_CODE_MT_FORWARD_SM           46

/* MAP error codes we may receive/send (TS 29.002 §17.6). */
#define MAP_ERR_UNKNOWN_SUBSCRIBER          1
#define MAP_ERR_ROAMING_NOT_ALLOWED         8
#define MAP_ERR_SYSTEM_FAILURE              34
#define MAP_ERR_DATA_MISSING                35
#define MAP_ERR_UNEXPECTED_DATA_VALUE       36
#define MAP_ERR_AUTHENTICATION_FAILURE      52
#define MAP_ERR_DELIVERY_FAILURE            32

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

/* ----- decoders ----------------------------------------------------- */

int map_decode_sai_arg     (const uint8_t *p, size_t n, map_sai_req_t *out);
int map_decode_ugl_arg     (const uint8_t *p, size_t n, map_ugl_req_t *out);
int map_decode_cl_arg      (const uint8_t *p, size_t n, map_cl_req_t  *out);
int map_decode_purge_arg   (const uint8_t *p, size_t n, map_purge_req_t *out);

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

/* ----- encoders (for the IWF -> SGSN direction) ------------------- */

/* MAP SendAuthenticationInfo Invoke/ReturnResult (IWF -> foreign HLR). */
int map_encode_sai_arg(const char *imsi_str, uint8_t num_vectors,
                       uint8_t *out, size_t out_cap);
int map_decode_sai_res(const uint8_t *p, size_t n,
                       map_auth_vector_t *vec, size_t vec_cap, size_t *n_vec);

/* MAP SendAuthenticationInfo ReturnResult, AuthenticationSetList of vectors. */
int map_encode_sai_res(const map_auth_vector_t *vec, size_t n_vec,
                       uint8_t *out, size_t out_cap);

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
                       uint8_t *out, size_t out_cap);

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

/* ----- AARQ/AARE dialogue portion helpers ------------------------- */

/* Application Context Name OIDs used in our MAP dialogues.  Caller passes
 * the operation we are initiating; we return the matching OID bytes. */
typedef enum {
    MAP_AC_INFO_RETRIEVAL_V3        = 1, /* sendAuthInfo                   */
    MAP_AC_GPRS_LOCATION_UPDATE_V3  = 2, /* updateGprsLocation             */
    MAP_AC_SUBSCRIBER_DATA_MGMT_V3  = 3, /* insertSubscriberData           */
    MAP_AC_GPRS_LOCATION_CANCEL_V3  = 4, /* cancelLocation over Gr         */
    MAP_AC_MS_PURGING_V3            = 5, /* purgeMS                        */
} map_app_ctx_t;

int map_encode_aarq(map_app_ctx_t ac, uint8_t *out, size_t out_cap);
int map_encode_aare(map_app_ctx_t ac, uint8_t *out, size_t out_cap);
int map_decode_aarq_ac(const uint8_t *p, size_t n, map_app_ctx_t *out);

#endif /* IWF_MAP_CODEC_H */
