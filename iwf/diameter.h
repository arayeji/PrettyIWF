/*
 * diameter.h - Diameter base protocol (RFC 6733) + S6d (3GPP TS 29.272).
 *
 * Single-peer client. We open exactly one TCP connection to PyHSS, run
 * CER/CEA at startup, DWR every Tw seconds, and DPR on shutdown. All
 * application messages travel on this one connection.
 *
 * The S6d application uses:
 *   Application-Id = 16777251
 *   Auth-Application-Id = 16777251 (advertised in CER)
 *   Command codes:
 *     Authentication-Information-Request / Answer   318  (AIR/AIA)
 *     Update-Location-Request           / Answer   316  (ULR/ULA)
 *     Cancel-Location-Request           / Answer   317  (CLR/CLA)
 *     Purge-UE-Request                  / Answer   321  (PUR/PUA)
 *
 * Vendor-Id 3GPP = 10415; the V flag is set on all 3GPP AVPs we encode.
 *
 * Pending-transaction table is keyed by hop-by-hop id (the only correlator
 * RFC 6733 guarantees for unrelated requests on a shared peer connection).
 */

#ifndef IWF_DIAMETER_H
#define IWF_DIAMETER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <time.h>

struct iwf_runtime;
struct map_session;

#define DIAMETER_PORT_DEFAULT           3868
#define DIAMETER_VERSION                1

#define DIAMETER_APP_BASE               0
#define DIAMETER_APP_S6D                16777251U
#define DIAMETER_VENDOR_3GPP            10415U

/* Diameter command codes (RFC 6733 + TS 29.272). */
#define DIAMETER_CMD_CER                257
#define DIAMETER_CMD_DWR                280
#define DIAMETER_CMD_DPR                282
#define DIAMETER_CMD_ULR                316
#define DIAMETER_CMD_CLR                317
#define DIAMETER_CMD_AIR                318
#define DIAMETER_CMD_IDR                319
#define DIAMETER_CMD_PUR                321
#define DIAMETER_CMD_NOR                323

/* Diameter header flags. */
#define DIAM_HDR_FLAG_REQUEST           0x80
#define DIAM_HDR_FLAG_PROXYABLE         0x40
#define DIAM_HDR_FLAG_ERROR             0x20
#define DIAM_HDR_FLAG_RETRANSMITTED     0x10

/* AVP flags. */
#define DIAM_AVP_FLAG_VENDOR            0x80
#define DIAM_AVP_FLAG_MANDATORY         0x40
#define DIAM_AVP_FLAG_PROTECTED         0x20

/* Base AVP codes (RFC 6733). */
#define AVP_USER_NAME                   1
#define AVP_HOST_IP_ADDRESS             257
#define AVP_AUTH_APPLICATION_ID         258
#define AVP_VENDOR_SPECIFIC_APP_ID      260
#define AVP_SESSION_ID                  263
#define AVP_ORIGIN_HOST                 264
#define AVP_VENDOR_ID                   266
#define AVP_PRODUCT_NAME                269
#define AVP_RESULT_CODE                 268
#define AVP_DISCONNECT_CAUSE            273
#define AVP_AUTH_SESSION_STATE          277
#define AVP_ORIGIN_STATE_ID             278
#define AVP_DESTINATION_REALM           283
#define AVP_DESTINATION_HOST            293
#define AVP_ORIGIN_REALM                296
#define AVP_EXPERIMENTAL_RESULT         297
#define AVP_EXPERIMENTAL_RESULT_CODE    298
#define AVP_SUPPORTED_VENDOR_ID         265
#define AVP_FIRMWARE_REVISION           267

/* 3GPP AVP codes (TS 29.272 §7.3 - all carry vendor-id 10415). */
#define AVP_3GPP_VISITED_PLMN_ID                1407
#define AVP_3GPP_REQ_EUTRAN_AUTH_INFO           1408
#define AVP_3GPP_REQ_UTRAN_GERAN_AUTH_INFO      1409  /* TS 29.272 §7.3.12; not 1441 (IDA-Flags) */
#define AVP_3GPP_NUM_REQ_VECTORS                1410
#define AVP_3GPP_RE_SYNCHRONIZATION_INFO        1411
#define AVP_3GPP_IMMEDIATE_RESPONSE_PREFERRED   1412
#define AVP_3GPP_AUTHENTICATION_INFO            1413
#define AVP_3GPP_E_UTRAN_VECTOR                 1414
#define AVP_3GPP_UTRAN_VECTOR                   1415
#define AVP_3GPP_GERAN_VECTOR                   1416
#define AVP_3GPP_RAND                           1447
#define AVP_3GPP_XRES                           1448
#define AVP_3GPP_AUTN                           1449
#define AVP_3GPP_KASME                          1450
#define AVP_3GPP_CK                             625    /* Confidentiality-Key (29.229) */
#define AVP_3GPP_IK                             626    /* Integrity-Key (29.229); not 1520/1522 */
#define AVP_3GPP_SUBSCRIPTION_DATA              1400
#define AVP_3GPP_MSISDN                          701
#define AVP_3GPP_APN_CONFIGURATION_PROFILE      1429
#define AVP_3GPP_APN_CONFIGURATION              1430
#define AVP_3GPP_CONTEXT_IDENTIFIER             1423
#define AVP_3GPP_ALL_APN_CONFIGS_INCLUDED       1428
#define AVP_3GPP_PDN_TYPE                       1456
#define AVP_3GPP_SERVED_PARTY_IP_ADDRESS        848
#define AVP_3GPP_SERVICE_SELECTION              493
#define AVP_3GPP_AMBR                           1435
#define AVP_3GPP_MAX_REQUESTED_BANDWIDTH_UL     516
#define AVP_3GPP_MAX_REQUESTED_BANDWIDTH_DL     515
#define AVP_3GPP_ULR_FLAGS                      1405
#define AVP_3GPP_ULA_FLAGS                      1406
#define AVP_3GPP_SGSN_NUMBER                    1489   /* TS 29.272 §7.3.102; CS VLR GT via IWF */
#define AVP_3GPP_CANCELLATION_TYPE              1420
#define AVP_3GPP_PUR_FLAGS                      1635
#define AVP_3GPP_PUA_FLAGS                      1442
#define AVP_3GPP_RAT_TYPE                       1032
#define AVP_3GPP_TERMINAL_INFORMATION           1401
#define AVP_3GPP_KC                             1453     /* GERAN-Vector inner */
#define AVP_3GPP_SRES                           1454
#define AVP_3GPP_IDR_FLAGS                      1490
#define AVP_3GPP_NOR_FLAGS                      1443
#define AVP_3GPP_UE_REACHABILITY                1614

/* IDR-Flags (TS 29.272 §7.3.30) bit 0 = URRP-MME (arm UE-reachability report). */
#define IDR_FLAG_UE_REACHABILITY                0x00000001U
/* NOR-Flags (TS 29.272 §7.3.83) bit 0 = UE-Reachability-Report. */
#define NOR_FLAG_UE_REACHABILITY                0x00000001U
/* UE-Reachability (TS 29.272 §7.3.164). */
#define UE_REACHABILITY_UNREACHABLE             0
#define UE_REACHABILITY_REACHABLE               1

/* Diameter Result-Code values we care about. */
#define DIAM_RC_SUCCESS                         2001
#define DIAM_RC_LIMITED_SUCCESS                 2002
#define DIAM_RC_COMMAND_UNSUPPORTED             3001
#define DIAM_RC_TOO_BUSY                        3004
#define DIAM_RC_AUTH_REJECTED                   4001
#define DIAM_RC_UNABLE_TO_DELIVER               3002

/* Experimental-Result-Code (3GPP, vendor 10415). */
#define DIAM_EXP_RC_USER_UNKNOWN                5001
#define DIAM_EXP_RC_AUTH_DATA_UNAVAILABLE       4181
#define DIAM_RC_INVALID_AVP_LENGTH              5014  /* e.g. grouped AVP sent as IDA-Flags (1441) */
#define DIAM_EXP_RC_RAT_NOT_ALLOWED             5421
#define DIAM_EXP_RC_ROAMING_NOT_ALLOWED         5004

/* RAT-Type (TS 29.272 §7.3.2). The user spec equates GPRS = 1001. */
#define DIAM_RAT_TYPE_GPRS                      1001
#define DIAM_RAT_TYPE_UTRAN                     1000
#define DIAM_RAT_TYPE_EUTRAN                    1004

/* ULR-Flags (TS 29.272 §7.3.7).  Bit1: set=S6a/MME, clear=S6d/SGSN. */
#define ULR_FLAG_SINGLE_REGISTRATION            0x00000001
#define ULR_FLAG_S6A_S6D_INDICATOR              0x00000002 /* 1=MME/S6a      */
#define ULR_FLAG_SKIP_SUBSCRIBER_DATA           0x00000004
#define ULR_FLAG_GPRS_SUBSCRIPTION_REQ          0x00000008 /* GPRS-Sub in ULA */
#define ULR_FLAG_NODE_TYPE_INDICATOR            0x00000020

/* ----- Module API used by main.c + map_iwf.c ---------------------- */

int  diameter_init(struct iwf_runtime *rt);
void diameter_shutdown(struct iwf_runtime *rt);

int  diameter_get_fd(const struct iwf_runtime *rt);
int  diameter_get_dwa_timer_fd(const struct iwf_runtime *rt);

void diameter_on_readable(struct iwf_runtime *rt);
void diameter_on_dwa_tick(struct iwf_runtime *rt);

bool diameter_is_open(const struct iwf_runtime *rt);

/* Send the four S6d requests. Each transmits a Diameter Request and stores
 * the hop-by-hop id in `s->diameter_hop_by_hop` so the response can be
 * routed back. Returns 0 on success; -1 if the connection is down (caller
 * should respond to the SGSN with a MAP SystemFailure). */
int  diameter_send_air(struct iwf_runtime *rt, struct map_session *s);
int  diameter_send_ulr(struct iwf_runtime *rt, struct map_session *s);
int  diameter_send_clr(struct iwf_runtime *rt, struct map_session *s);
int  diameter_send_pur(struct iwf_runtime *rt, struct map_session *s);

/* ----- AVP iteration (used by map_iwf.c response handlers) -------- */

typedef struct {
    uint32_t code;
    uint8_t  flags;
    uint32_t vendor_id;        /* 0 if no V flag */
    const uint8_t *data;
    size_t   data_len;
} diameter_avp_t;

int  diameter_avp_first(const uint8_t *buf, size_t len, diameter_avp_t *it);
int  diameter_avp_next (const uint8_t *buf, size_t len, diameter_avp_t *it);
int  diameter_avp_find (const uint8_t *buf, size_t len,
                        uint32_t code, uint32_t vendor_id,
                        diameter_avp_t *out);
int  diameter_avp_find_recursive(const uint8_t *buf, size_t len,
                                 uint32_t code, uint32_t vendor_id,
                                 diameter_avp_t *out);

/* 3GPP AVP lookup: match code and vendor 10415, or code with no V flag. */
int  diameter_avp_find_3gpp(const uint8_t *buf, size_t len,
                            uint32_t code, diameter_avp_t *out);
int  diameter_avp_find_3gpp_recursive(const uint8_t *buf, size_t len,
                                      uint32_t code, diameter_avp_t *out);

/* Convenience: extract Result-Code (or Experimental-Result-Code if present)
 * and the textual Session-Id from an answer body. */
int  diameter_get_result_code  (const uint8_t *body, size_t len,
                                uint32_t *out_rc);
int  diameter_get_session_id   (const uint8_t *body, size_t len,
                                char *out, size_t out_cap);
int  diameter_get_user_name    (const uint8_t *body, size_t len,
                                char *out, size_t out_cap);
int  diameter_get_uint32_avp   (const uint8_t *body, size_t len,
                                uint32_t code, uint32_t vendor_id,
                                uint32_t *out_val);

/* Answer an inbound Cancel-Location-Request (HSS -> IWF). */
int  diameter_send_cla_answer  (struct iwf_runtime *rt,
                                uint32_t hop_by_hop, uint32_t end_to_end,
                                const char *session_id, uint32_t result_code);

/* Answer an inbound Insert-Subscriber-Data-Request (HSS -> IWF). */
int  diameter_send_ida_answer (struct iwf_runtime *rt,
                               uint32_t hop_by_hop, uint32_t end_to_end,
                               const char *session_id, uint32_t result_code,
                               const char *origin_host);

/* Notify HSS that a UE became reachable (S6a NOR after URRP-MME). */
int  diameter_send_nor        (struct iwf_runtime *rt,
                               const char *imsi, const char *origin_host,
                               uint32_t ue_reachability);

int  diameter_get_os_avp      (const uint8_t *body, size_t len,
                               uint32_t code, uint32_t vendor_id,
                               char *out, size_t out_cap);

#endif /* IWF_DIAMETER_H */
