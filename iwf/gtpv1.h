/*
 * gtpv1.h - GTPv1-C wire format encoder/decoder (TS 29.060)
 *
 * Header (octets):
 *   1: Version(3) PT(1) *(1) E(1) S(1) PN(1)
 *   2: Message Type
 *   3-4: Length (payload after the mandatory 8-byte header)
 *   5-8: TEID
 *   9-10: Sequence Number  (if S=1 in oct1 - GTPv1-C always sets S)
 *   11: N-PDU Number       (if PN=1)
 *   12: Next Ext Header    (if E=1)
 *
 * IE format depends on type:
 *   TV (fixed-length): high bit of type = 0
 *   TLV: high bit of type = 1, followed by 2-byte length, then value
 */

#ifndef IWF_GTPV1_H
#define IWF_GTPV1_H

#include "iwf.h"

int  gtpv1_parse(const uint8_t *buf, size_t len, iwf_msg_t *msg);

/* Locate an IE in a parsed message; returns NULL if absent. */
const iwf_ie_t *gtpv1_find_ie(const iwf_msg_t *msg, uint8_t type);

/* Last IE 133 (GSN Address) in wire order — Create PDP Req lists Control
 * Plane then User Traffic (TS 29.060 Table 7.3.1-1); the SGSN GTP-U source
 * is the user-plane address (second IE when both present). */
int gtpv1_last_gsn_addr_ipv4(const iwf_msg_t *msg, uint32_t *ipv4);

/* IE-specific decoders.  All return 0 on success, -1 on malformed input. */
int gtpv1_decode_imsi(const iwf_ie_t *ie, char *imsi_str, size_t cap);
int gtpv1_decode_msisdn(const iwf_ie_t *ie, char *msisdn_str, size_t cap);
int gtpv1_decode_apn(const iwf_ie_t *ie, char *apn_str, size_t cap);
int gtpv1_decode_nsapi(const iwf_ie_t *ie, uint8_t *nsapi);
int gtpv1_decode_teid(const iwf_ie_t *ie, uint32_t *teid);
int gtpv1_decode_rat_type(const iwf_ie_t *ie, uint8_t *rat);
int gtpv1_decode_eua(const iwf_ie_t *ie,
                     uint8_t *pdp_org, uint8_t *pdp_type,
                     uint32_t *ipv4);   /* IPv4 only for now */
int gtpv1_decode_gsn_addr(const iwf_ie_t *ie, uint32_t *ipv4);

/* Encoder context. */
typedef struct {
    uint8_t *buf;
    size_t   cap;
    size_t   pos;       /* current write offset */
    int      err;
} gtpv1_enc_t;

void gtpv1_enc_init(gtpv1_enc_t *e, uint8_t *buf, size_t cap);

/* Begin a response. Writes the 12-byte header (S=1, no E/PN). */
int  gtpv1_enc_begin(gtpv1_enc_t *e, uint8_t msg_type,
                     uint32_t teid, uint16_t seq);

/* Finalise: patches the length field. Returns total bytes written or -1. */
int  gtpv1_enc_finish(gtpv1_enc_t *e);

/* Encoders for IEs we produce in responses. */
int gtpv1_enc_tv_u8(gtpv1_enc_t *e, uint8_t type, uint8_t v);
int gtpv1_enc_tv_u32(gtpv1_enc_t *e, uint8_t type, uint32_t v);
int gtpv1_enc_tlv(gtpv1_enc_t *e, uint8_t type,
                  const uint8_t *val, uint16_t len);
/* TV type 2, 8-byte TBCD IMSI (TS 29.060 §7.7.2). */
int gtpv1_enc_imsi_tv(gtpv1_enc_t *e, const char *digits);
/* TV type 3, 6 octets PLMN+LAC+RAC (TS 29.060 §7.7.3). */
int gtpv1_enc_rai_tv(gtpv1_enc_t *e, const uint8_t rai6[6]);
int gtpv1_enc_cause(gtpv1_enc_t *e, uint8_t cause);
int gtpv1_enc_eua_ipv4(gtpv1_enc_t *e, uint32_t ipv4);
int gtpv1_enc_gsn_addr_ipv4(gtpv1_enc_t *e, uint32_t ipv4);
int gtpv1_enc_qos_profile(gtpv1_enc_t *e, const uint8_t *qos, size_t len);
int gtpv1_enc_charging_id(gtpv1_enc_t *e, uint32_t cid);

#endif /* IWF_GTPV1_H */
