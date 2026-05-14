/*
 * gtpv2.h - GTPv2-C wire format encoder/decoder (TS 29.274)
 *
 * Header (octets), when T=1:
 *   1: Version(3)=2 | P | T | Spare(2)
 *   2: Message Type
 *   3-4: Length (whole message excluding the first 4 bytes)
 *   5-8: TEID
 *   9-11: Sequence Number (24-bit)
 *   12: Spare
 *
 * When T=0 (Echo etc) there is no TEID; sequence number follows directly.
 *
 * IEs are TLIV: Type(1) Length(2) Spare/Instance(1) Value(N)
 */

#ifndef IWF_GTPV2_H
#define IWF_GTPV2_H

#include "iwf.h"

int gtpv2_parse(const uint8_t *buf, size_t len, iwf_msg_t *msg);

const iwf_ie_t *gtpv2_find_ie(const iwf_msg_t *msg,
                              uint8_t type, uint8_t instance);
/* Walk a grouped IE (Bearer Context). */
int gtpv2_parse_grouped(const iwf_ie_t *grp,
                        iwf_ie_t *out, size_t cap, size_t *n_out);

/* Decoders. */
int gtpv2_decode_cause(const iwf_ie_t *ie, uint8_t *cause);
/* Cause at message level or inside Bearer Context (Open5GS CSRsp shape). */
int gtpv2_find_cause_value(const iwf_msg_t *msg, uint8_t *cause_out);
int gtpv2_decode_fteid(const iwf_ie_t *ie,
                       uint8_t *iface, uint32_t *teid,
                       uint32_t *ipv4);
int gtpv2_decode_paa_ipv4(const iwf_ie_t *ie, uint8_t *pdn_type, uint32_t *ipv4);
int gtpv2_decode_ebi(const iwf_ie_t *ie, uint8_t *ebi);
int gtpv2_decode_imsi(const iwf_ie_t *ie, char *digits, size_t cap);

/* Encoder. */
typedef struct {
    uint8_t *buf;
    size_t   cap;
    size_t   pos;
    int      err;
} gtpv2_enc_t;

void gtpv2_enc_init(gtpv2_enc_t *e, uint8_t *buf, size_t cap);
int  gtpv2_enc_begin(gtpv2_enc_t *e, uint8_t msg_type,
                     uint32_t teid, uint32_t seq);
/* T=1 when teid_present; T=0 omits TEID octets (Echo / some requests). */
int  gtpv2_enc_begin_tf(gtpv2_enc_t *e, uint8_t msg_type,
                        uint32_t teid, uint32_t seq, int teid_present);
int  gtpv2_enc_finish(gtpv2_enc_t *e);

/* Raw TLIV. */
int gtpv2_enc_tlv(gtpv2_enc_t *e, uint8_t type, uint8_t instance,
                  const uint8_t *val, uint16_t len);

/* Convenience encoders. */
int gtpv2_enc_imsi_bcd(gtpv2_enc_t *e, const char *imsi_digits);
int gtpv2_enc_msisdn_bcd(gtpv2_enc_t *e, const char *digits);
int gtpv2_enc_apn(gtpv2_enc_t *e, const char *apn);
int gtpv2_enc_rat_type(gtpv2_enc_t *e, uint8_t rat);
int gtpv2_enc_pdn_type(gtpv2_enc_t *e, uint8_t pdn_type);
int gtpv2_enc_paa_ipv4(gtpv2_enc_t *e, uint32_t ipv4);
int gtpv2_enc_ebi(gtpv2_enc_t *e, uint8_t instance, uint8_t ebi);
int gtpv2_enc_ambr(gtpv2_enc_t *e, uint32_t ul_kbps, uint32_t dl_kbps);
int gtpv2_enc_indication(gtpv2_enc_t *e, uint8_t b1, uint8_t b2,
                         uint8_t b3, uint8_t b4);
int gtpv2_enc_selection_mode(gtpv2_enc_t *e, uint8_t mode);
int gtpv2_enc_apn_restriction(gtpv2_enc_t *e, uint8_t restr);
int gtpv2_enc_serving_network(gtpv2_enc_t *e,
                              uint16_t mcc, uint16_t mnc);
int gtpv2_enc_cause(gtpv2_enc_t *e, uint8_t cause);
/* GTP IE 74 — IPv4 only (network byte order in val). */
int gtpv2_enc_ipv4_ip_address(gtpv2_enc_t *e, uint8_t instance, uint32_t ipv4_be);
/* ULI with RAI only, from 6-octet GTPv1 / TS 24.008 RAI (PLMN+LAC+RAC). */
int gtpv2_enc_uli_from_v1_rai(gtpv2_enc_t *e, const uint8_t rai6[6]);
/* Same wire shape, PLMN from MCC/MNC and LAC=RAC=0 (lab fallback when Gn has no RAI). */
int gtpv2_enc_uli_synthetic_plmn(gtpv2_enc_t *e, uint16_t mcc, uint16_t mnc);
int gtpv2_enc_fteid_ipv4(gtpv2_enc_t *e, uint8_t instance,
                         uint8_t iface, uint32_t teid, uint32_t ipv4);

/* Bearer QoS = QCI + ARP + MBR/GBR (5 + 4*5 = 22 bytes). */
int gtpv2_enc_bearer_qos(gtpv2_enc_t *e,
                         uint8_t pci, uint8_t pl, uint8_t pvi,
                         uint8_t qci,
                         uint64_t mbr_ul, uint64_t mbr_dl,
                         uint64_t gbr_ul, uint64_t gbr_dl);

/* Start/finish a grouped IE (Bearer Context). */
int gtpv2_enc_group_begin(gtpv2_enc_t *e, uint8_t type, uint8_t instance,
                          size_t *patch_pos);
int gtpv2_enc_group_finish(gtpv2_enc_t *e, size_t patch_pos);

#endif /* IWF_GTPV2_H */
