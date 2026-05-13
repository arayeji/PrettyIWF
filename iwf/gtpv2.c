#include "gtpv2.h"
#include "logging.h"

#include <string.h>
#include <ctype.h>

int gtpv2_parse(const uint8_t *buf, size_t len, iwf_msg_t *msg)
{
    memset(msg, 0, sizeof(*msg));
    if (len < 4) return -1;

    uint8_t flags   = buf[0];
    uint8_t version = (flags >> 5) & 0x07;
    uint8_t t_flag  = (flags >> 3) & 0x01;
    if (version != 2) return -1;

    msg->version  = 2;
    msg->msg_type = buf[1];
    uint16_t total_len = iwf_be16(buf + 2);
    size_t   wire_end  = 4 + total_len;
    if (wire_end > len) return -1;

    size_t off;
    if (t_flag) {
        if (wire_end < 12) return -1;
        msg->teid = iwf_be32(buf + 4);
        msg->seq  = iwf_be24(buf + 8);
        off = 12;
    } else {
        if (wire_end < 8) return -1;
        msg->teid = 0;
        msg->seq  = iwf_be24(buf + 4);
        off = 8;
    }

    msg->raw = buf;
    msg->raw_len = wire_end;

    while (off < wire_end && msg->n_ies < IWF_MAX_IES) {
        if (off + 4 > wire_end) return -1;
        uint8_t  type = buf[off];
        uint16_t l    = iwf_be16(buf + off + 1);
        uint8_t  inst = buf[off + 3] & 0x0f;
        if (off + 4 + l > wire_end) return -1;

        iwf_ie_t *ie = &msg->ies[msg->n_ies++];
        ie->type     = type;
        ie->instance = inst;
        ie->length   = l;
        ie->value    = buf + off + 4;
        off += 4 + l;
    }
    return 0;
}

const iwf_ie_t *gtpv2_find_ie(const iwf_msg_t *msg,
                              uint8_t type, uint8_t instance)
{
    for (size_t i = 0; i < msg->n_ies; i++) {
        if (msg->ies[i].type == type &&
            msg->ies[i].instance == instance) {
            return &msg->ies[i];
        }
    }
    return NULL;
}

int gtpv2_parse_grouped(const iwf_ie_t *grp,
                        iwf_ie_t *out, size_t cap, size_t *n_out)
{
    if (!grp) return -1;
    const uint8_t *p   = grp->value;
    size_t         end = grp->length;
    size_t         off = 0;
    size_t         n   = 0;

    while (off < end && n < cap) {
        if (off + 4 > end) return -1;
        uint8_t  type = p[off];
        uint16_t l    = iwf_be16(p + off + 1);
        uint8_t  inst = p[off + 3] & 0x0f;
        if (off + 4 + l > end) return -1;

        out[n].type     = type;
        out[n].instance = inst;
        out[n].length   = l;
        out[n].value    = p + off + 4;
        n++;
        off += 4 + l;
    }
    *n_out = n;
    return 0;
}

/* ------------------------------------------------------------------- */
/* Decoders                                                            */
/* ------------------------------------------------------------------- */

int gtpv2_decode_cause(const iwf_ie_t *ie, uint8_t *cause)
{
    if (!ie || ie->length < 1) return -1;
    *cause = ie->value[0];
    return 0;
}

int gtpv2_find_cause_value(const iwf_msg_t *msg, uint8_t *cause_out)
{
    if (!msg || !cause_out) return -1;

    uint8_t first_top = 0xff;
    uint8_t first_bc  = 0xff;

    for (size_t i = 0; i < msg->n_ies; i++) {
        if (msg->ies[i].type != GTPV2_IE_CAUSE) continue;
        uint8_t c;
        if (gtpv2_decode_cause(&msg->ies[i], &c) != 0) continue;
        if (c == GTPV2_CAUSE_REQUEST_ACCEPTED) {
            *cause_out = c;
            return 0;
        }
        if (first_top == 0xff) first_top = c;
    }

    for (size_t i = 0; i < msg->n_ies; i++) {
        if (msg->ies[i].type != GTPV2_IE_BEARER_CONTEXT) continue;
        iwf_ie_t inner[IWF_MAX_IES];
        size_t n = 0;
        if (gtpv2_parse_grouped(&msg->ies[i], inner, IWF_MAX_IES, &n) != 0)
            continue;
        for (size_t j = 0; j < n; j++) {
            if (inner[j].type != GTPV2_IE_CAUSE) continue;
            uint8_t c;
            if (gtpv2_decode_cause(&inner[j], &c) != 0) continue;
            if (c == GTPV2_CAUSE_REQUEST_ACCEPTED) {
                *cause_out = c;
                return 0;
            }
            if (first_bc == 0xff) first_bc = c;
        }
    }

    if (first_top != 0xff) {
        *cause_out = first_top;
        return 0;
    }
    if (first_bc != 0xff) {
        *cause_out = first_bc;
        return 0;
    }
    return -1;
}

int gtpv2_decode_fteid(const iwf_ie_t *ie,
                       uint8_t *iface, uint32_t *teid, uint32_t *ipv4)
{
    if (!ie || ie->length < 5) return -1;
    uint8_t flags = ie->value[0];
    uint8_t v4 = (flags >> 7) & 0x01;
    *iface = flags & 0x3f;
    *teid  = iwf_be32(ie->value + 1);
    *ipv4  = 0;
    if (v4) {
        if (ie->length < 9) return -1;
        *ipv4 = iwf_be32(ie->value + 5);
    }
    return 0;
}

int gtpv2_decode_paa_ipv4(const iwf_ie_t *ie, uint8_t *pdn_type, uint32_t *ipv4)
{
    if (!ie || ie->length < 1) return -1;
    uint8_t pt = ie->value[0] & 0x07;
    *pdn_type = pt;
    *ipv4 = 0;
    /* For PDN type IPv4, the IPv4 address is 4 bytes following the PDN type. */
    if (pt == GTPV2_PDN_TYPE_IPV4 && ie->length >= 5) {
        *ipv4 = iwf_be32(ie->value + 1);
    } else if (pt == GTPV2_PDN_TYPE_IPV4V6 && ie->length >= 22) {
        /* Order per TS 29.274: IPv6 prefix length, IPv6, then IPv4. */
        *ipv4 = iwf_be32(ie->value + 1 + 1 + 16);
    }
    return 0;
}

int gtpv2_decode_ebi(const iwf_ie_t *ie, uint8_t *ebi)
{
    if (!ie || ie->length < 1) return -1;
    *ebi = ie->value[0] & 0x0f;
    return 0;
}

/* ------------------------------------------------------------------- */
/* Encoder                                                             */
/* ------------------------------------------------------------------- */

void gtpv2_enc_init(gtpv2_enc_t *e, uint8_t *buf, size_t cap)
{
    e->buf = buf; e->cap = cap; e->pos = 0; e->err = 0;
}

static int v2_need(gtpv2_enc_t *e, size_t n)
{
    if (e->err) return -1;
    if (e->pos + n > e->cap) { e->err = 1; return -1; }
    return 0;
}

int gtpv2_enc_begin(gtpv2_enc_t *e, uint8_t msg_type,
                    uint32_t teid, uint32_t seq)
{
    if (v2_need(e, 12) < 0) return -1;
    /* Version=2, T=1 -> 0b010_0_1_000 = 0x48 */
    e->buf[0] = 0x48;
    e->buf[1] = msg_type;
    e->buf[2] = 0; e->buf[3] = 0;        /* length patched later */
    iwf_put_be32(e->buf + 4, teid);
    iwf_put_be24(e->buf + 8, seq & 0xffffff);
    e->buf[11] = 0;
    e->pos = 12;
    return 0;
}

int gtpv2_enc_finish(gtpv2_enc_t *e)
{
    if (e->err) return -1;
    uint16_t total = (uint16_t)(e->pos - 4);
    iwf_put_be16(e->buf + 2, total);
    return (int)e->pos;
}

int gtpv2_enc_tlv(gtpv2_enc_t *e, uint8_t type, uint8_t instance,
                  const uint8_t *val, uint16_t len)
{
    if (v2_need(e, 4 + (size_t)len) < 0) return -1;
    e->buf[e->pos++] = type;
    iwf_put_be16(e->buf + e->pos, len); e->pos += 2;
    e->buf[e->pos++] = instance & 0x0f;
    if (len) memcpy(e->buf + e->pos, val, len);
    e->pos += len;
    return 0;
}

/* Encode an IMSI as packed BCD, low-nibble first, 0xF pad on odd length. */
static int bcd_encode(const char *digits, uint8_t *out, size_t cap)
{
    size_t n = strlen(digits);
    size_t b = (n + 1) / 2;
    if (b > cap) return -1;
    for (size_t i = 0; i < b; i++) {
        uint8_t lo = (uint8_t)(digits[2 * i] - '0') & 0x0f;
        uint8_t hi = 0x0f;
        if (2 * i + 1 < n) hi = (uint8_t)(digits[2 * i + 1] - '0') & 0x0f;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)b;
}

int gtpv2_enc_imsi_bcd(gtpv2_enc_t *e, const char *digits)
{
    uint8_t buf[16];
    int n = bcd_encode(digits, buf, sizeof(buf));
    if (n < 0) return -1;
    return gtpv2_enc_tlv(e, GTPV2_IE_IMSI, 0, buf, (uint16_t)n);
}

int gtpv2_enc_msisdn_bcd(gtpv2_enc_t *e, const char *digits)
{
    uint8_t buf[16];
    int n = bcd_encode(digits, buf, sizeof(buf));
    if (n < 0) return -1;
    return gtpv2_enc_tlv(e, GTPV2_IE_MSISDN, 0, buf, (uint16_t)n);
}

int gtpv2_enc_apn(gtpv2_enc_t *e, const char *apn)
{
    uint8_t buf[128];
    size_t  off = 0;
    const char *p = apn;
    while (*p && off < sizeof(buf) - 1) {
        const char *dot = strchr(p, '.');
        size_t lab = dot ? (size_t)(dot - p) : strlen(p);
        if (lab > 63 || off + 1 + lab > sizeof(buf)) return -1;
        buf[off++] = (uint8_t)lab;
        memcpy(buf + off, p, lab);
        off += lab;
        if (!dot) break;
        p = dot + 1;
    }
    return gtpv2_enc_tlv(e, GTPV2_IE_APN, 0, buf, (uint16_t)off);
}

int gtpv2_enc_rat_type(gtpv2_enc_t *e, uint8_t rat)
{
    return gtpv2_enc_tlv(e, GTPV2_IE_RAT_TYPE, 0, &rat, 1);
}

int gtpv2_enc_pdn_type(gtpv2_enc_t *e, uint8_t pdn_type)
{
    uint8_t v = pdn_type & 0x07;
    return gtpv2_enc_tlv(e, GTPV2_IE_PDN_TYPE, 0, &v, 1);
}

int gtpv2_enc_paa_ipv4(gtpv2_enc_t *e, uint32_t ipv4)
{
    uint8_t v[5];
    v[0] = GTPV2_PDN_TYPE_IPV4;
    iwf_put_be32(v + 1, ipv4);
    return gtpv2_enc_tlv(e, GTPV2_IE_PAA, 0, v, sizeof(v));
}

int gtpv2_enc_ebi(gtpv2_enc_t *e, uint8_t instance, uint8_t ebi)
{
    uint8_t v = ebi & 0x0f;
    return gtpv2_enc_tlv(e, GTPV2_IE_EBI, instance, &v, 1);
}

int gtpv2_enc_ambr(gtpv2_enc_t *e, uint32_t ul_kbps, uint32_t dl_kbps)
{
    uint8_t v[8];
    iwf_put_be32(v, ul_kbps);
    iwf_put_be32(v + 4, dl_kbps);
    return gtpv2_enc_tlv(e, GTPV2_IE_AMBR, 0, v, sizeof(v));
}

int gtpv2_enc_indication(gtpv2_enc_t *e, uint8_t b1, uint8_t b2,
                         uint8_t b3, uint8_t b4)
{
    uint8_t v[4] = { b1, b2, b3, b4 };
    return gtpv2_enc_tlv(e, GTPV2_IE_INDICATION, 0, v, sizeof(v));
}

int gtpv2_enc_selection_mode(gtpv2_enc_t *e, uint8_t mode)
{
    uint8_t v = mode & 0x03;
    return gtpv2_enc_tlv(e, GTPV2_IE_SELECTION_MODE, 0, &v, 1);
}

int gtpv2_enc_apn_restriction(gtpv2_enc_t *e, uint8_t restr)
{
    return gtpv2_enc_tlv(e, GTPV2_IE_APN_RESTRICTION, 0, &restr, 1);
}

/* Encode 3-digit MCC + 2 or 3 digit MNC into 3 BCD octets per TS 24.008. */
static void mccmnc_encode(uint16_t mcc, uint16_t mnc, uint8_t out[3])
{
    uint8_t m1 = (mcc / 100) % 10;
    uint8_t m2 = (mcc / 10)  % 10;
    uint8_t m3 =  mcc        % 10;
    uint8_t n1, n2, n3;
    if (mnc >= 100) {
        n1 = (mnc / 100) % 10;
        n2 = (mnc / 10)  % 10;
        n3 =  mnc        % 10;
    } else {
        n1 = 0x0f;
        n2 = (mnc / 10) % 10;
        n3 =  mnc       % 10;
    }
    out[0] = (uint8_t)((m2 << 4) | m1);
    out[1] = (uint8_t)((n1 << 4) | m3);
    out[2] = (uint8_t)((n3 << 4) | n2);
}

int gtpv2_enc_serving_network(gtpv2_enc_t *e, uint16_t mcc, uint16_t mnc)
{
    uint8_t v[3];
    mccmnc_encode(mcc, mnc, v);
    return gtpv2_enc_tlv(e, GTPV2_IE_SERVING_NETWORK, 0, v, sizeof(v));
}

int gtpv2_enc_cause(gtpv2_enc_t *e, uint8_t cause)
{
    uint8_t v[2] = { cause, 0 };
    return gtpv2_enc_tlv(e, GTPV2_IE_CAUSE, 0, v, sizeof(v));
}

int gtpv2_enc_fteid_ipv4(gtpv2_enc_t *e, uint8_t instance,
                         uint8_t iface, uint32_t teid, uint32_t ipv4)
{
    uint8_t v[9];
    v[0] = 0x80 | (iface & 0x3f);    /* V4 = 1 */
    iwf_put_be32(v + 1, teid);
    iwf_put_be32(v + 5, ipv4);
    return gtpv2_enc_tlv(e, GTPV2_IE_FTEID, instance, v, sizeof(v));
}

/* Bearer-QoS encoding (TS 29.274 §8.15):
 *   Octet 5: spare(1) PCI(1) PL(4) spare(1) PVI(1)
 *   Octet 6: QCI
 *   7-11: MBR UL (40-bit)
 *   12-16: MBR DL
 *   17-21: GBR UL
 *   22-26: GBR DL
 */
static void put_40(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)((v >> 32) & 0xff);
    p[1] = (uint8_t)((v >> 24) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)((v >> 8)  & 0xff);
    p[4] = (uint8_t)( v        & 0xff);
}

int gtpv2_enc_bearer_qos(gtpv2_enc_t *e,
                         uint8_t pci, uint8_t pl, uint8_t pvi,
                         uint8_t qci,
                         uint64_t mbr_ul, uint64_t mbr_dl,
                         uint64_t gbr_ul, uint64_t gbr_dl)
{
    uint8_t v[22];
    v[0] = (uint8_t)(((pci & 1) << 6) | ((pl & 0x0f) << 2) | (pvi & 1));
    v[1] = qci;
    put_40(v + 2,  mbr_ul);
    put_40(v + 7,  mbr_dl);
    put_40(v + 12, gbr_ul);
    put_40(v + 17, gbr_dl);
    return gtpv2_enc_tlv(e, GTPV2_IE_BEARER_QOS, 0, v, sizeof(v));
}

int gtpv2_enc_group_begin(gtpv2_enc_t *e, uint8_t type, uint8_t instance,
                          size_t *patch_pos)
{
    if (v2_need(e, 4) < 0) return -1;
    e->buf[e->pos++] = type;
    *patch_pos = e->pos;
    e->buf[e->pos++] = 0; e->buf[e->pos++] = 0;     /* length, patched later */
    e->buf[e->pos++] = instance & 0x0f;
    return 0;
}

int gtpv2_enc_group_finish(gtpv2_enc_t *e, size_t patch_pos)
{
    if (e->err) return -1;
    /* The group's length covers everything after the 4-byte IE header. */
    uint16_t len = (uint16_t)(e->pos - (patch_pos + 3));
    iwf_put_be16(e->buf + patch_pos, len);
    return 0;
}
