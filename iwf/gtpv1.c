#include "gtpv1.h"
#include "logging.h"

#include <string.h>

/*
 * GTPv1 IE lengths for TV (Type-Value) IEs (high bit of type = 0).
 * Length is implied by the type per TS 29.060 §7.7.
 */
static int gtpv1_tv_length(uint8_t type)
{
    switch (type) {
    case 1:   return 1;   /* Cause */
    case 2:   return 8;   /* IMSI */
    case 3:   return 6;   /* RAI */
    case 4:   return 4;   /* TLLI */
    case 5:   return 4;   /* P-TMSI */
    case 8:   return 1;   /* Reordering Required */
    case 9:   return 28;  /* Authentication Triplet */
    case 11:  return 1;   /* MAP Cause */
    case 12:  return 3;   /* P-TMSI Signature */
    case 13:  return 1;   /* MS Validated */
    case 14:  return 1;   /* Recovery */
    case 15:  return 1;   /* Selection Mode */
    case 16:  return 4;   /* TEID Data I */
    case 17:  return 4;   /* TEID Control Plane */
    case 18:  return 5;   /* TEID Data II */
    case 19:  return 1;   /* Teardown Ind */
    case 20:  return 1;   /* NSAPI */
    case 21:  return 1;   /* RANAP Cause */
    case 22:  return 9;   /* RAB Context */
    case 23:  return 1;   /* Radio Priority SMS */
    case 24:  return 1;   /* Radio Priority */
    case 25:  return 2;   /* Packet Flow Id */
    case 26:  return 2;   /* Charging Characteristics */
    case 27:  return 2;   /* Trace Reference */
    case 28:  return 2;   /* Trace Type */
    case 29:  return 1;   /* MS Not Reachable Reason */
    case 127: return 4;   /* Charging ID */
    default: break;
    }
    return -1; /* not a known TV; the caller must treat the type as TLV. */
}

int gtpv1_parse(const uint8_t *buf, size_t len, iwf_msg_t *msg)
{
    memset(msg, 0, sizeof(*msg));
    if (len < 8) return -1;

    uint8_t flags = buf[0];
    uint8_t version = (flags >> 5) & 0x07;
    uint8_t pt      = (flags >> 4) & 0x01;
    uint8_t e_flag  = (flags >> 2) & 0x01;
    uint8_t s_flag  = (flags >> 1) & 0x01;
    uint8_t pn_flag =  flags       & 0x01;

    if (version != 1 || pt != 1) return -1;

    msg->version  = 1;
    msg->msg_type = buf[1];
    uint16_t pay_len = iwf_be16(buf + 2);
    msg->teid     = iwf_be32(buf + 4);

    size_t off = 8;
    if (s_flag || e_flag || pn_flag) {
        if (len < 12) return -1;
        msg->seq = iwf_be16(buf + 8);
        off = 12;
        /* skip extension headers */
        if (e_flag) {
            uint8_t next = buf[11];
            while (next != 0 && off + 1 < len) {
                uint8_t ext_len = buf[off];          /* in 4-byte units */
                if (ext_len == 0) return -1;
                size_t bytes = (size_t)ext_len * 4;
                if (off + bytes > len) return -1;
                next = buf[off + bytes - 1];
                off += bytes;
            }
        }
    }

    if ((size_t)(8 + pay_len) > len) {
        LOGW("gtpv1", "truncated message: hdr_len=%u, buf_len=%zu", pay_len + 8, len);
        return -1;
    }
    size_t end = 8 + pay_len;
    msg->raw = buf; msg->raw_len = end;

    /* Walk IEs. */
    while (off < end && msg->n_ies < IWF_MAX_IES) {
        uint8_t type = buf[off];
        iwf_ie_t *ie = &msg->ies[msg->n_ies];
        ie->type = type;
        ie->instance = 0;

        if ((type & 0x80) == 0) {
            int tv_len = gtpv1_tv_length(type);
            if (tv_len < 0) {
                LOGW("gtpv1", "unknown TV IE type=%u at off=%zu", type, off);
                return -1;
            }
            if (off + 1 + (size_t)tv_len > end) return -1;
            ie->length = (uint16_t)tv_len;
            ie->value  = buf + off + 1;
            off += 1 + tv_len;
        } else {
            if (off + 3 > end) return -1;
            uint16_t l = iwf_be16(buf + off + 1);
            if (off + 3 + l > end) return -1;
            ie->length = l;
            ie->value  = buf + off + 3;
            off += 3 + l;
        }
        msg->n_ies++;
    }
    return 0;
}

const iwf_ie_t *gtpv1_find_ie(const iwf_msg_t *msg, uint8_t type)
{
    for (size_t i = 0; i < msg->n_ies; i++) {
        if (msg->ies[i].type == type) return &msg->ies[i];
    }
    return NULL;
}

/* ------------------------------------------------------------------- */
/* Decoders                                                            */
/* ------------------------------------------------------------------- */

/* IMSI is BCD, 8 octets, low nibble first within each octet. 0xF = pad. */
static int bcd_to_str(const uint8_t *p, size_t n, char *out, size_t cap)
{
    if (!out || cap < 1) return -1;
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t lo = p[i] & 0x0f;
        uint8_t hi = (p[i] >> 4) & 0x0f;
        if (lo == 0x0f) break;
        if (k + 1 >= cap) return -1;
        out[k++] = (char)('0' + lo);
        if (hi == 0x0f) break;
        if (k + 1 >= cap) return -1;
        out[k++] = (char)('0' + hi);
    }
    out[k] = '\0';
    return (int)k;
}

int gtpv1_decode_imsi(const iwf_ie_t *ie, char *out, size_t cap)
{
    if (!ie || ie->length < 8) return -1;
    return bcd_to_str(ie->value, 8, out, cap);
}

int gtpv1_decode_msisdn(const iwf_ie_t *ie, char *out, size_t cap)
{
    if (!ie || ie->length < 2) return -1;
    /* First octet is the Numbering Plan / Type Of Number, then BCD digits. */
    return bcd_to_str(ie->value + 1, ie->length - 1, out, cap);
}

int gtpv1_decode_apn(const iwf_ie_t *ie, char *out, size_t cap)
{
    if (!ie || ie->length == 0 || cap == 0) return -1;
    /* APN is RFC 1035 label-encoded. */
    size_t k = 0;
    size_t i = 0;
    while (i < ie->length && k + 1 < cap) {
        uint8_t lab = ie->value[i++];
        if (lab == 0 || i + lab > ie->length) break;
        if (k > 0 && k + 1 < cap) out[k++] = '.';
        for (uint8_t j = 0; j < lab && k + 1 < cap; j++) {
            out[k++] = (char)ie->value[i++];
        }
    }
    out[k] = '\0';
    return (int)k;
}

int gtpv1_decode_nsapi(const iwf_ie_t *ie, uint8_t *nsapi)
{
    if (!ie || ie->length < 1) return -1;
    *nsapi = ie->value[0] & 0x0f;
    return 0;
}

int gtpv1_decode_teid(const iwf_ie_t *ie, uint32_t *teid)
{
    if (!ie || ie->length < 4) return -1;
    *teid = iwf_be32(ie->value);
    return 0;
}

int gtpv1_decode_rat_type(const iwf_ie_t *ie, uint8_t *rat)
{
    if (!ie || ie->length < 1) return -1;
    *rat = ie->value[0];   /* 1=UTRAN, 2=GERAN, ... */
    return 0;
}

int gtpv1_decode_eua(const iwf_ie_t *ie,
                     uint8_t *pdp_org, uint8_t *pdp_type, uint32_t *ipv4)
{
    if (!ie || ie->length < 2) return -1;
    *pdp_org  = ie->value[0] & 0x0f;
    *pdp_type = ie->value[1];
    *ipv4 = 0;
    if (ie->length >= 6 && *pdp_type == 0x21 /* IPv4 */) {
        *ipv4 = iwf_be32(ie->value + 2);
    }
    return 0;
}

int gtpv1_decode_gsn_addr(const iwf_ie_t *ie, uint32_t *ipv4)
{
    if (!ie || ie->length < 4) return -1;
    *ipv4 = iwf_be32(ie->value);
    return 0;
}

/* ------------------------------------------------------------------- */
/* Encoder                                                             */
/* ------------------------------------------------------------------- */

void gtpv1_enc_init(gtpv1_enc_t *e, uint8_t *buf, size_t cap)
{
    e->buf = buf;
    e->cap = cap;
    e->pos = 0;
    e->err = 0;
}

static int need(gtpv1_enc_t *e, size_t n)
{
    if (e->err) return -1;
    if (e->pos + n > e->cap) { e->err = 1; return -1; }
    return 0;
}

int gtpv1_enc_begin(gtpv1_enc_t *e, uint8_t msg_type,
                    uint32_t teid, uint16_t seq)
{
    if (need(e, 12) < 0) return -1;
    /* Version=1, PT=1, S=1, others=0 -> 0b001_1_0_0_1_0 = 0x32 */
    e->buf[0] = 0x32;
    e->buf[1] = msg_type;
    e->buf[2] = 0; e->buf[3] = 0;          /* length, patched in _finish */
    iwf_put_be32(e->buf + 4, teid);
    iwf_put_be16(e->buf + 8, seq);
    e->buf[10] = 0;
    e->buf[11] = 0;
    e->pos = 12;
    return 0;
}

int gtpv1_enc_finish(gtpv1_enc_t *e)
{
    if (e->err) return -1;
    uint16_t pay_len = (uint16_t)(e->pos - 8);
    iwf_put_be16(e->buf + 2, pay_len);
    return (int)e->pos;
}

int gtpv1_enc_tv_u8(gtpv1_enc_t *e, uint8_t type, uint8_t v)
{
    if (need(e, 2) < 0) return -1;
    e->buf[e->pos++] = type;
    e->buf[e->pos++] = v;
    return 0;
}

int gtpv1_enc_tv_u32(gtpv1_enc_t *e, uint8_t type, uint32_t v)
{
    if (need(e, 5) < 0) return -1;
    e->buf[e->pos++] = type;
    iwf_put_be32(e->buf + e->pos, v);
    e->pos += 4;
    return 0;
}

int gtpv1_enc_tlv(gtpv1_enc_t *e, uint8_t type,
                  const uint8_t *val, uint16_t len)
{
    if (need(e, 3 + (size_t)len) < 0) return -1;
    e->buf[e->pos++] = type | 0x80;
    iwf_put_be16(e->buf + e->pos, len);
    e->pos += 2;
    if (len) memcpy(e->buf + e->pos, val, len);
    e->pos += len;
    return 0;
}

int gtpv1_enc_cause(gtpv1_enc_t *e, uint8_t cause)
{
    return gtpv1_enc_tv_u8(e, GTPV1_IE_CAUSE, cause);
}

int gtpv1_enc_eua_ipv4(gtpv1_enc_t *e, uint32_t ipv4)
{
    uint8_t v[6];
    v[0] = 0xf1;            /* PDP Org = IETF, spare bits set */
    v[1] = 0x21;            /* PDP Type Number = IPv4 */
    iwf_put_be32(v + 2, ipv4);
    return gtpv1_enc_tlv(e, GTPV1_IE_END_USER_ADDRESS, v, sizeof(v));
}

int gtpv1_enc_gsn_addr_ipv4(gtpv1_enc_t *e, uint32_t ipv4)
{
    uint8_t v[4];
    iwf_put_be32(v, ipv4);
    return gtpv1_enc_tlv(e, GTPV1_IE_GSN_ADDRESS, v, sizeof(v));
}

int gtpv1_enc_qos_profile(gtpv1_enc_t *e, const uint8_t *qos, size_t len)
{
    return gtpv1_enc_tlv(e, GTPV1_IE_QOS_PROFILE, qos, (uint16_t)len);
}

int gtpv1_enc_charging_id(gtpv1_enc_t *e, uint32_t cid)
{
    return gtpv1_enc_tv_u32(e, GTPV1_IE_CHARGING_ID, cid);
}
