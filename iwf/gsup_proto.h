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
#define GSUP_MSG_UL_ERR         0x07
#define GSUP_MSG_UL_RES         0x06
#define GSUP_MSG_SAI_REQ        0x08
#define GSUP_MSG_SAI_RES        0x0a
#define GSUP_MSG_SAI_ERR        0x0b
#define GSUP_MSG_ISD_REQ        0x10
#define GSUP_MSG_ISD_ERR        0x11
#define GSUP_MSG_ISD_RES        0x12
#define GSUP_MSG_LOC_CANCEL_REQ 0x1c

#define GSUP_IE_IMSI            0x01
#define GSUP_IE_CAUSE           0x02
#define GSUP_IE_AUTH_TUPLE      0x03
#define GSUP_IE_PDP_INFO_COMPL  0x04
#define GSUP_IE_PDP_INFO        0x05
#define GSUP_IE_CANCEL_TYPE     0x06
#define GSUP_IE_MSISDN          0x08
#define GSUP_IE_NUM_VECTORS     0x0a
#define GSUP_IE_PDP_CONTEXT_ID  0x10
#define GSUP_IE_PDP_ADDRESS     0x11
#define GSUP_IE_APN             0x12
#define GSUP_IE_PDP_QOS         0x13
#define GSUP_IE_CN_DOMAIN       0x28

#define GSUP_CAUSE_IMSI_UNKNOWN 0x02

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
} gsup_parsed_t;

int  gsup_parse_payload(const uint8_t *body, size_t len, gsup_parsed_t *out);
int  gsup_imsi_from_payload(const uint8_t *body, size_t len,
                            char *imsi_out, size_t cap);

int  gsup_build_sai_res(const char *imsi,
                        const map_auth_vector_t *vec, size_t n_vec,
                        uint8_t *out, size_t cap);
int  gsup_build_sai_err(const char *imsi, uint8_t cause,
                        uint8_t *out, size_t cap);
int  gsup_build_ul_res(const char *imsi, const char *msisdn, uint8_t cn_domain,
                       uint8_t *out, size_t cap);
int  gsup_build_ul_err(const char *imsi, uint8_t cause,
                       uint8_t *out, size_t cap);
int  gsup_build_isd_req(const char *imsi, const char *msisdn,
                        const map_ula_apn_entry_t *apns, size_t n_apns,
                        uint8_t cn_domain,
                        uint8_t *out, size_t cap);
int  gsup_build_loc_cancel_req(const char *imsi, uint8_t cancel_type,
                               uint8_t *out, size_t cap);

int  gsup_ipa_wrap(const uint8_t *gsup, size_t gsup_len,
                   uint8_t *out, size_t cap);

#endif /* IWF_GSUP_PROTO_H */
