/*
 * iwf.h - common types and constants for the GTPv1-C <-> GTPv2-C IWF
 *
 * Architecture: osmo-sgsn (Gn, GTPv1-C) <--> IWF <--> Open5GS SGW-C (S4, GTPv2-C)
 *               User plane (GTP-U) flows directly RNC <-> UPG-VPP (Direct Tunnel).
 *               The IWF is signaling-only: it never sees a GTP-U packet.
 */

#ifndef IWF_H
#define IWF_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <ctype.h>
#include <netinet/in.h>
#include <time.h>

#define IWF_VERSION             "1.0.0"

#define GTP_PORT                2123
#define IWF_MAX_PKT             4096
#define IWF_MAX_EVENTS          64
#define IWF_T3_RESPONSE_MS      3000   /* GTPv2-C T3 timer */
#define IWF_N3_RETRIES          4
#define IWF_SESSION_TIMEOUT_S   3600

/* Default QCI/ARP mapped from GTPv1 QoS Profile (best-effort fallback). */
#define IWF_DEFAULT_QCI         9
#define IWF_DEFAULT_ARP_PVI     0
#define IWF_DEFAULT_ARP_PCI     0
#define IWF_DEFAULT_ARP_PL      15

/* ------------------------------------------------------------------- */
/* GTPv1-C message types (TS 29.060 §7.1)                              */
/* ------------------------------------------------------------------- */
#define GTPV1_ECHO_REQUEST                 1
#define GTPV1_ECHO_RESPONSE                2
#define GTPV1_CREATE_PDP_CONTEXT_REQUEST   16
#define GTPV1_CREATE_PDP_CONTEXT_RESPONSE  17
#define GTPV1_UPDATE_PDP_CONTEXT_REQUEST   18
#define GTPV1_UPDATE_PDP_CONTEXT_RESPONSE  19
#define GTPV1_DELETE_PDP_CONTEXT_REQUEST   20
#define GTPV1_DELETE_PDP_CONTEXT_RESPONSE  21

/* GTPv1-C IE types (selected) */
#define GTPV1_IE_CAUSE                     1
#define GTPV1_IE_IMSI                      2
#define GTPV1_IE_RAI                       3
#define GTPV1_IE_RECOVERY                  14
#define GTPV1_IE_SELECTION_MODE            15
#define GTPV1_IE_TEID_DATA_I               16
#define GTPV1_IE_TEID_CTRL_PLANE           17
#define GTPV1_IE_NSAPI                     20
#define GTPV1_IE_CHARGING_CHARACTERISTICS  26
#define GTPV1_IE_CHARGING_ID               127
#define GTPV1_IE_END_USER_ADDRESS          128
#define GTPV1_IE_ACCESS_POINT_NAME         131
#define GTPV1_IE_PCO                       132
#define GTPV1_IE_GSN_ADDRESS               133
#define GTPV1_IE_MSISDN                    134
#define GTPV1_IE_QOS_PROFILE               135
#define GTPV1_IE_COMMON_FLAGS              148
#define GTPV1_IE_APN_RESTRICTION           149
#define GTPV1_IE_RAT_TYPE                  151
#define GTPV1_IE_ULI                       152
#define GTPV1_IE_MS_TIME_ZONE              153
#define GTPV1_IE_IMEISV                    154
#define GTPV1_IE_PRIVATE_EXTENSION         255

/* GTPv1 cause values (TS 29.060 §7.7.1) */
#define GTPV1_CAUSE_REQUEST_ACCEPTED       128
#define GTPV1_CAUSE_NON_EXISTENT           192
#define GTPV1_CAUSE_INVALID_MESSAGE        193
#define GTPV1_CAUSE_NO_RESOURCES           199
#define GTPV1_CAUSE_SERVICE_NOT_SUPPORTED  200
#define GTPV1_CAUSE_SYSTEM_FAILURE         204
/* "Unknown PDP address or PDP type" — osmo-sgsn maps this to SM cause 28
 * (gtp2sm_cause_map in sgsn_libgtp.c). Per TS 24.008 §6.1.3.1.5, an MS that
 * receives SM cause 28 in response to a *secondary* Activate-PDP for the
 * complementary IP version stops the second activation but keeps the primary
 * PDP alive — exactly the behaviour we need when rejecting the IPv4v6
 * fallback request that Open5GS SMF cannot honour today (one PDN per
 * (IMSI, APN)). Sending cause 199 (No Resources) instead maps to SM cause 26
 * which UEs interpret as overload and detach. */
#define GTPV1_CAUSE_UNKNOWN_PDP_ADDR_TYPE  220

/* PDP Type Number (TS 29.060 §7.7.27 / TS 24.008 §10.5.6.4); only the
 * "IETF allocated" organization (1) is used by 3GPP networks. */
#define GTPV1_PDP_TYPE_IPV4                0x21
#define GTPV1_PDP_TYPE_IPV6                0x57
#define GTPV1_PDP_TYPE_IPV4V6              0x8d

/* ------------------------------------------------------------------- */
/* GTPv2-C message types (TS 29.274 §7.1.1)                            */
/* ------------------------------------------------------------------- */
#define GTPV2_ECHO_REQUEST                 1
#define GTPV2_ECHO_RESPONSE                2
#define GTPV2_CREATE_SESSION_REQUEST       32
#define GTPV2_CREATE_SESSION_RESPONSE      33
#define GTPV2_MODIFY_BEARER_REQUEST        34
#define GTPV2_MODIFY_BEARER_RESPONSE       35
#define GTPV2_DELETE_SESSION_REQUEST       36
#define GTPV2_DELETE_SESSION_RESPONSE      37
#define GTPV2_CONTEXT_REQUEST              130
#define GTPV2_CONTEXT_RESPONSE             131

#define GTPV1_SGSN_CONTEXT_REQUEST         50
#define GTPV1_SGSN_CONTEXT_RESPONSE        51

/* GTPv1 IE — MM / PDP Context (TS 29.060 §7.7) */
#define GTPV1_IE_MM_CONTEXT                129
#define GTPV1_IE_PDP_CONTEXT               130

/* GTPv2-C IE types (TS 29.274 §8.1) */
#define GTPV2_IE_IMSI                      1
#define GTPV2_IE_CAUSE                     2
#define GTPV2_IE_RECOVERY                  3
#define GTPV2_IE_APN                       71
#define GTPV2_IE_AMBR                      72
#define GTPV2_IE_EBI                       73
#define GTPV2_IE_IP_ADDRESS                74
#define GTPV2_IE_MEI                       75
#define GTPV2_IE_MSISDN                    76
#define GTPV2_IE_INDICATION                77
#define GTPV2_IE_PCO                       78
#define GTPV2_IE_PAA                       79
#define GTPV2_IE_BEARER_QOS                80
#define GTPV2_IE_RAT_TYPE                  82
#define GTPV2_IE_SERVING_NETWORK           83
#define GTPV2_IE_ULI                       86
#define GTPV2_IE_FTEID                     87
#define GTPV2_IE_BEARER_CONTEXT            93
#define GTPV2_IE_CHARGING_ID               94
#define GTPV2_IE_CHARGING_CHARACTERISTICS  95
#define GTPV2_IE_PDN_TYPE                  99
#define GTPV2_IE_UE_TIME_ZONE              114
#define GTPV2_IE_APN_RESTRICTION           127
#define GTPV2_IE_SELECTION_MODE            128
#define GTPV2_IE_FQ_CSID                   132
#define GTPV2_IE_PDN_CONNECTION            109
/* MM Context variants (TS 29.274 Table 8.1-1) */
#define GTPV2_IE_MM_CONTEXT_GSM_KEY_TRIP   103
#define GTPV2_IE_MM_CONTEXT_UMTS_KEY_QUINT 104
#define GTPV2_IE_MM_CONTEXT_GSM_KEY_QUINT 105
#define GTPV2_IE_MM_CONTEXT_UMTS_KEY_QUINT2 106

/* GTPv2 cause values */
#define GTPV2_CAUSE_REQUEST_ACCEPTED       16
#define GTPV2_CAUSE_CONTEXT_NOT_FOUND      64
#define GTPV2_CAUSE_SYSTEM_FAILURE         72

/* F-TEID interface types (TS 29.274 §8.22 Table) */
#define FTEID_IFACE_S1U_ENB_GTPU           0
#define FTEID_IFACE_S1U_SGW_GTPU           1
#define FTEID_IFACE_S5S8_SGW_GTPU          4
#define FTEID_IFACE_S5S8_PGW_GTPU          5
#define FTEID_IFACE_S5S8_SGW_GTPC          6
#define FTEID_IFACE_S5S8_PGW_GTPC          7
#define FTEID_IFACE_S11_MME_GTPC           10
#define FTEID_IFACE_S11_S4_SGW_GTPC        11
#define FTEID_IFACE_S4_SGSN_GTPU           15
#define FTEID_IFACE_S4_SGW_GTPU            16
#define FTEID_IFACE_S4_SGSN_GTPC           17
#define FTEID_IFACE_S11_SGW_GTPU           39

/* RAT types */
#define GTPV2_RAT_UTRAN                    1
#define GTPV2_RAT_GERAN                    2
#define GTPV2_RAT_WLAN                     3
#define GTPV2_RAT_EUTRAN                   6

/* PDN type */
#define GTPV2_PDN_TYPE_IPV4                1
#define GTPV2_PDN_TYPE_IPV6                2
#define GTPV2_PDN_TYPE_IPV4V6              3

/* ------------------------------------------------------------------- */
/* Generic decoded message representation                              */
/* ------------------------------------------------------------------- */

/* A pointer-into-buffer view of one IE - zero-copy parsing. */
typedef struct {
    uint8_t  type;
    uint8_t  instance;     /* GTPv2 only; 0 for GTPv1 */
    uint16_t length;
    const uint8_t *value;
} iwf_ie_t;

#define IWF_MAX_IES        32

typedef struct {
    uint8_t  version;      /* 1 or 2 */
    uint8_t  msg_type;
    uint32_t teid;
    uint32_t seq;          /* 16-bit on v1, 24-bit on v2 */
    iwf_ie_t ies[IWF_MAX_IES];
    size_t   n_ies;
    const uint8_t *raw;
    size_t   raw_len;
} iwf_msg_t;

/* ------------------------------------------------------------------- */
/* Network endpoint                                                    */
/* ------------------------------------------------------------------- */
typedef struct {
    struct sockaddr_in addr;
    socklen_t          addrlen;
} iwf_endpoint_t;

/* Convenience to grab a 32-bit IPv4 from an IE. */
static inline uint32_t iwf_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}
static inline uint16_t iwf_be16(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}
static inline uint32_t iwf_be24(const uint8_t *p) {
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[2];
}
static inline void iwf_put_be16(uint8_t *p, uint16_t v) {
    p[0] = (v >> 8) & 0xff; p[1] = v & 0xff;
}
static inline void iwf_put_be24(uint8_t *p, uint32_t v) {
    p[0] = (v >> 16) & 0xff; p[1] = (v >> 8) & 0xff; p[2] = v & 0xff;
}
static inline void iwf_put_be32(uint8_t *p, uint32_t v) {
    p[0] = (v >> 24) & 0xff; p[1] = (v >> 16) & 0xff;
    p[2] = (v >> 8)  & 0xff; p[3] =  v        & 0xff;
}

/* TS 23.003: APN/DNN labels are case-insensitive. Canonicalize to lowercase
 * on decode so internal lookups and S4 Create-Session always use one form
 * (matches Open5GS smf.yaml / PFCP subnet dnn and avoids UPF mismatches). */
static inline void iwf_apn_normalize(char *apn)
{
    if (!apn)
        return;
    for (char *p = apn; *p; p++)
        *p = (char)tolower((unsigned char)*p);
}

#endif /* IWF_H */
