/*
 * isup_codec.c — Q.763 encode/decode. No libosmo dependency.
 *
 * Digit packing matches map_str_to_bcd: low nibble first, 0xF filler.
 */

#include "isup_codec.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

const char *isup_msg_name(uint8_t type)
{
    switch (type) {
    case ISUP_MT_IAM:  return "IAM";
    case ISUP_MT_ACM:  return "ACM";
    case ISUP_MT_CPG:  return "CPG";
    case ISUP_MT_ANM:  return "ANM";
    case ISUP_MT_REL:  return "REL";
    case ISUP_MT_RLC:  return "RLC";
    case ISUP_MT_RSC:  return "RSC";
    case ISUP_MT_BLO:  return "BLO";
    case ISUP_MT_UBL:  return "UBL";
    case ISUP_MT_BLA:  return "BLA";
    case ISUP_MT_UBA:  return "UBA";
    case ISUP_MT_GRS:  return "GRS";
    case ISUP_MT_GRA:  return "GRA";
    case ISUP_MT_CGB:  return "CGB";
    case ISUP_MT_CGU:  return "CGU";
    case ISUP_MT_CGBA: return "CGBA";
    case ISUP_MT_CGUA: return "CGUA";
    case ISUP_MT_APM:  return "APM";
    default:           return "UNK";
    }
}

void isup_put_cic(uint8_t out[2], uint16_t cic)
{
    out[0] = (uint8_t)(cic & 0xff);
    out[1] = (uint8_t)((cic >> 8) & 0x0f);
}

uint16_t isup_get_cic(const uint8_t in[2])
{
    return (uint16_t)(in[0] | ((in[1] & 0x0f) << 8));
}

static int str_to_tbcd(const char *digits, uint8_t *out, size_t cap, int *odd)
{
    if (!digits || !out) return -1;
    size_t n = 0;
    char tmp[ISUP_NUM_DIGITS_MAX];
    for (const char *p = digits; *p && n + 1 < sizeof(tmp); p++) {
        if (*p == '+' || *p == ' ') continue;
        if (!isdigit((unsigned char)*p)) return -1;
        tmp[n++] = *p;
    }
    tmp[n] = '\0';
    *odd = (int)(n & 1);
    size_t need = (n + 1) / 2;
    if (need > cap) return -1;
    memset(out, 0xff, need);
    for (size_t i = 0; i < n; i++) {
        uint8_t d = (uint8_t)(tmp[i] - '0');
        uint8_t *b = &out[i / 2];
        if ((i & 1) == 0)
            *b = (*b & 0xf0) | (d & 0x0f);
        else
            *b = (uint8_t)((*b & 0x0f) | ((d & 0x0f) << 4));
    }
    return (int)need;
}

static void tbcd_to_str(const uint8_t *bcd, size_t bcd_len, int odd,
                        char *out, size_t cap)
{
    if (!out || !cap) return;
    size_t o = 0;
    size_t digits = bcd_len * 2;
    if (odd && digits) digits--;
    for (size_t i = 0; i < digits && o + 1 < cap; i++) {
        uint8_t nibble = (i & 1) ? ((bcd[i / 2] >> 4) & 0x0f)
                                 : (bcd[i / 2] & 0x0f);
        if (nibble > 9) break;
        out[o++] = (char)('0' + nibble);
    }
    out[o] = '\0';
}

void isup_number_from_digits(isup_number_t *n, const char *digits,
                             uint8_t nai, int pres_restricted)
{
    memset(n, 0, sizeof(*n));
    n->nai = nai ? nai : ISUP_NAI_INTERNATIONAL;
    n->npi = ISUP_NPI_ISDN;
    n->inn = 1;
    n->presentation = pres_restricted ? ISUP_PRES_RESTRICTED
                                      : ISUP_PRES_ALLOWED;
    n->screening = ISUP_SCREEN_NETWORK_PROVIDED;
    if (digits) {
        size_t o = 0;
        const char *p = digits;
        if (*p == '+') p++;
        for (; *p && o + 1 < sizeof(n->digits); p++) {
            if (isdigit((unsigned char)*p))
                n->digits[o++] = *p;
        }
        n->digits[o] = '\0';
        n->odd = (int)(o & 1);
    }
}

int isup_enc_number(uint8_t *out, size_t cap, const isup_number_t *n,
                    int with_pres)
{
    if (!out || !n) return -1;
    uint8_t tbcd[16];
    int odd = 0;
    int nb = str_to_tbcd(n->digits, tbcd, sizeof(tbcd), &odd);
    if (nb < 0) return -1;
    size_t hdr = with_pres ? 2 : 2;
    if (cap < hdr + (size_t)nb) return -1;
    uint8_t nai = n->nai & 0x7f;
    out[0] = (uint8_t)((odd ? 0x80 : 0x00) | nai);
    uint8_t inn = n->inn ? 0x80 : 0x00;
    uint8_t npi = (uint8_t)((n->npi & 0x07) << 4);
    if (with_pres) {
        uint8_t pres = (uint8_t)((n->presentation & 0x03) << 2);
        uint8_t scr  = (uint8_t)(n->screening & 0x03);
        out[1] = (uint8_t)(inn | npi | pres | scr);
    } else {
        out[1] = (uint8_t)(inn | npi);
    }
    memcpy(out + 2, tbcd, (size_t)nb);
    return (int)(2 + nb);
}

int isup_dec_number(const uint8_t *in, size_t len, isup_number_t *n,
                    int with_pres)
{
    if (!in || !n || len < 2) return -1;
    memset(n, 0, sizeof(*n));
    n->odd = (in[0] & 0x80) ? 1 : 0;
    n->nai = (uint8_t)(in[0] & 0x7f);
    n->inn = (in[1] & 0x80) ? 1 : 0;
    n->npi = (uint8_t)((in[1] >> 4) & 0x07);
    if (with_pres) {
        n->presentation = (uint8_t)((in[1] >> 2) & 0x03);
        n->screening = (uint8_t)(in[1] & 0x03);
    }
    tbcd_to_str(in + 2, len - 2, n->odd, n->digits, sizeof(n->digits));
    return 0;
}

int isup_enc_ipbcp(char *out, size_t cap, const char *ip, uint16_t port)
{
    if (!out || !cap) return -1;
    const char *a = (ip && ip[0]) ? ip : "0.0.0.0";
    int n = snprintf(out, cap,
                     "v=0\r\n"
                     "o=- 0 0 IN IP4 %s\r\n"
                     "s=-\r\n"
                     "c=IN IP4 %s\r\n"
                     "t=0 0\r\n"
                     "m=audio %u RTP/AVP 8\r\n",
                     a, a, (unsigned)port);
    if (n < 0 || (size_t)n >= cap) return -1;
    return n;
}

int isup_dec_ipbcp(const char *sdp, size_t len, char *ip, size_t ip_cap,
                    uint16_t *port)
{
    if (ip && ip_cap) ip[0] = '\0';
    if (port) *port = 0;
    if (!sdp || !len) return -1;
    const char *end = sdp + len;
    const char *p = sdp;
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t llen = nl ? (size_t)(nl - p) : (size_t)(end - p);
        if (llen && p[llen - 1] == '\r') llen--;
        if (llen >= 7 && !strncmp(p, "c=IN IP4 ", 9) && ip && ip_cap) {
            size_t n = llen - 9;
            if (n >= ip_cap) n = ip_cap - 1;
            memcpy(ip, p + 9, n);
            ip[n] = '\0';
        } else if (llen >= 8 && !strncmp(p, "m=audio ", 8) && port) {
            unsigned po = 0;
            const char *q = p + 8;
            while (q < p + llen && *q >= '0' && *q <= '9')
                po = po * 10u + (unsigned)(*q++ - '0');
            *port = (uint16_t)po;
        }
        p = nl ? nl + 1 : end;
    }
    return (ip && ip[0]) ? 0 : -1;
}

static int put_opt(uint8_t *out, size_t cap, size_t *off,
                   uint8_t name, const uint8_t *val, size_t vlen)
{
    if (*off + 2 + vlen > cap) return -1;
    out[(*off)++] = name;
    out[(*off)++] = (uint8_t)vlen;
    memcpy(out + *off, val, vlen);
    *off += vlen;
    return 0;
}

static int enc_cause(uint8_t *out, size_t cap, uint8_t cause, uint8_t loc)
{
    if (cap < 2) return -1;
    out[0] = (uint8_t)(0x80 | (loc & 0x0f)); /* ext=1, ITU, location */
    out[1] = (uint8_t)(0x80 | (cause & 0x7f));
    return 2;
}

static int enc_atp_ipbcp(uint8_t *out, size_t cap,
                         const char *ip, uint16_t port)
{
    char sdp[ISUP_IPBCP_MAX];
    int sl = isup_enc_ipbcp(sdp, sizeof(sdp), ip, port);
    if (sl < 0) return -1;
    /* Q.765 Application Transport: ACI=2 (IPBCP), ATII, then PDU. */
    if (cap < 3 + (size_t)sl) return -1;
    out[0] = 2;          /* ACI IPBCP */
    out[1] = 0x00;       /* ATII: send notification, no release */
    out[2] = 0x00;       /* APM segmentation / spare */
    memcpy(out + 3, sdp, (size_t)sl);
    return 3 + sl;
}

int isup_encode(const isup_msg_t *m, uint8_t *out, size_t cap)
{
    if (!m || !out || cap < 3) return -1;
    isup_put_cic(out, m->cic);
    out[2] = m->type;
    size_t off = 3;

    switch (m->type) {
    case ISUP_MT_IAM: {
        if (cap < 10) return -1;
        out[off++] = m->nci;
        out[off++] = (uint8_t)(m->fci & 0xff);
        out[off++] = (uint8_t)((m->fci >> 8) & 0xff);
        out[off++] = m->cpc;
        out[off++] = m->tmr;
        /* pointers: called, optional */
        size_t ptr_called_at = off;
        out[off++] = 0;
        size_t ptr_opt_at = off;
        out[off++] = 0;

        uint8_t called[40];
        int cl = isup_enc_number(called, sizeof(called), &m->called, 0);
        if (cl < 0) return -1;
        out[ptr_called_at] = (uint8_t)(off - ptr_called_at);
        if (off + 1 + (size_t)cl > cap) return -1;
        out[off++] = (uint8_t)cl;
        memcpy(out + off, called, (size_t)cl);
        off += (size_t)cl;

        size_t opt_start = off;
        if (m->have_calling) {
            uint8_t cg[40];
            int gl = isup_enc_number(cg, sizeof(cg), &m->calling, 1);
            if (gl < 0) return -1;
            if (put_opt(out, cap, &off, ISUP_P_CALLING_PARTY_NUM,
                        cg, (size_t)gl) < 0)
                return -1;
        }
        if (m->have_ipbcp || (m->ipbcp_ip[0] && m->ipbcp_port)) {
            uint8_t atp[ISUP_IPBCP_MAX + 8];
            int al = enc_atp_ipbcp(atp, sizeof(atp), m->ipbcp_ip,
                                    m->ipbcp_port);
            if (al < 0) return -1;
            if (put_opt(out, cap, &off, ISUP_P_APP_TRANSPORT,
                        atp, (size_t)al) < 0)
                return -1;
        }
        if (off > opt_start) {
            if (off >= cap) return -1;
            out[off++] = 0x00; /* end of optional */
            out[ptr_opt_at] = (uint8_t)(opt_start - ptr_opt_at);
        } else {
            out[ptr_opt_at] = 0;
        }
        break;
    }
    case ISUP_MT_ACM: {
        size_t ptr_opt_at = off;
        if (off + 1 > cap) return -1;
        out[off++] = 0;
        if (m->have_bci) {
            uint8_t b[2] = { (uint8_t)(m->bci & 0xff),
                             (uint8_t)((m->bci >> 8) & 0xff) };
            size_t opt = off;
            if (put_opt(out, cap, &off, ISUP_P_BACKWARD_CALL_IND, b, 2) < 0)
                return -1;
            if (off >= cap) return -1;
            out[off++] = 0x00;
            out[ptr_opt_at] = (uint8_t)(opt - ptr_opt_at);
        }
        break;
    }
    case ISUP_MT_CPG: {
        if (off + 2 > cap) return -1;
        out[off++] = m->event_info ? m->event_info : 0x02; /* alerting */
        size_t ptr_opt_at = off;
        out[off++] = 0;
        (void)ptr_opt_at;
        break;
    }
    case ISUP_MT_REL: {
        uint8_t cause[4];
        int cl = enc_cause(cause, sizeof(cause),
                           m->have_cause ? m->cause : 16,
                           m->cause_location);
        if (cl < 0) return -1;
        if (off + 3 + (size_t)cl > cap) return -1;
        out[off++] = 2; /* pointer to cause (skip optional pointer) */
        out[off++] = 0; /* no optional */
        out[off++] = (uint8_t)cl;
        memcpy(out + off, cause, (size_t)cl);
        off += (size_t)cl;
        break;
    }
    case ISUP_MT_GRS:
    case ISUP_MT_GRA:
    case ISUP_MT_CGB:
    case ISUP_MT_CGU:
    case ISUP_MT_CGBA:
    case ISUP_MT_CGUA: {
        uint8_t rs[2] = { m->range ? m->range : 0, 0 };
        if (off + 4 > cap) return -1;
        out[off++] = 1; /* pointer to range (next octet is the param) */
        out[off++] = (uint8_t)(1 + 1); /* length of range-and-status body */
        out[off++] = rs[0];
        if (m->type == ISUP_MT_CGB || m->type == ISUP_MT_CGU ||
            m->type == ISUP_MT_CGBA || m->type == ISUP_MT_CGUA)
            out[off++] = 0x00; /* status bits unused for empty group */
        break;
    }
    case ISUP_MT_ANM:
    case ISUP_MT_RLC:
    case ISUP_MT_RSC:
    case ISUP_MT_BLO:
    case ISUP_MT_UBL:
    case ISUP_MT_BLA:
    case ISUP_MT_UBA:
        break;
    default:
        return -1;
    }
    return (int)off;
}

static int walk_optional(const uint8_t *in, size_t len, isup_msg_t *out)
{
    size_t off = 0;
    while (off < len) {
        uint8_t name = in[off++];
        if (name == 0x00) break;
        if (off >= len) return -1;
        uint8_t plen = in[off++];
        if (off + plen > len) return -1;
        const uint8_t *v = in + off;
        off += plen;
        switch (name) {
        case ISUP_P_CALLING_PARTY_NUM:
            if (isup_dec_number(v, plen, &out->calling, 1) == 0)
                out->have_calling = 1;
            break;
        case ISUP_P_BACKWARD_CALL_IND:
            if (plen >= 2) {
                out->bci = (uint16_t)(v[0] | (v[1] << 8));
                out->have_bci = 1;
            }
            break;
        case ISUP_P_CAUSE_INDICATORS:
            if (plen >= 2) {
                out->cause_location = (uint8_t)(v[0] & 0x0f);
                out->cause = (uint8_t)(v[1] & 0x7f);
                out->have_cause = 1;
            }
            break;
        case ISUP_P_APP_TRANSPORT:
            if (plen > 3 && v[0] == 2) {
                if (isup_dec_ipbcp((const char *)v + 3, plen - 3,
                                    out->ipbcp_ip, sizeof(out->ipbcp_ip),
                                    &out->ipbcp_port) == 0)
                    out->have_ipbcp = 1;
            }
            break;
        case ISUP_P_EVENT_INFO:
            if (plen >= 1) out->event_info = v[0];
            break;
        case ISUP_P_RANGE_AND_STATUS:
            if (plen >= 1) {
                out->range = v[0];
                out->have_range = 1;
            }
            break;
        default:
            break;
        }
    }
    return 0;
}

int isup_decode(const uint8_t *in, size_t len, isup_msg_t *out)
{
    if (!in || !out || len < 3) return -1;
    memset(out, 0, sizeof(*out));
    if (len > sizeof(out->raw)) len = sizeof(out->raw);
    memcpy(out->raw, in, len);
    out->raw_len = len;
    out->cic = isup_get_cic(in);
    out->type = in[2];
    size_t off = 3;

    switch (out->type) {
    case ISUP_MT_IAM: {
        if (len < 10) return -1;
        out->nci = in[off++];
        out->fci = (uint16_t)(in[off] | (in[off + 1] << 8));
        off += 2;
        out->cpc = in[off++];
        out->tmr = in[off++];
        if (off + 2 > len) return -1;
        uint8_t ptr_called = in[off];
        size_t called_at = off + ptr_called;
        uint8_t ptr_opt = in[off + 1];
        size_t opt_at = ptr_opt ? (off + 1 + ptr_opt) : 0;
        off += 2;
        if (!ptr_called || called_at >= len) return -1;
        uint8_t clen = in[called_at];
        if (called_at + 1 + clen > len) return -1;
        if (isup_dec_number(in + called_at + 1, clen, &out->called, 0) == 0)
            out->have_called = 1;
        if (ptr_opt && opt_at < len)
            walk_optional(in + opt_at, len - opt_at, out);
        break;
    }
    case ISUP_MT_ACM: {
        if (off >= len) break;
        uint8_t ptr_opt = in[off];
        if (ptr_opt) {
            size_t opt_at = off + ptr_opt;
            if (opt_at < len)
                walk_optional(in + opt_at, len - opt_at, out);
        }
        break;
    }
    case ISUP_MT_CPG:
        if (off < len) out->event_info = in[off++];
        if (off < len) {
            uint8_t ptr_opt = in[off];
            if (ptr_opt) {
                size_t opt_at = off + ptr_opt;
                if (opt_at < len)
                    walk_optional(in + opt_at, len - opt_at, out);
            }
        }
        break;
    case ISUP_MT_REL: {
        if (off + 2 > len) return -1;
        uint8_t ptr_cause = in[off];
        uint8_t ptr_opt = in[off + 1];
        size_t cause_at = off + ptr_cause;
        if (!ptr_cause || cause_at >= len) return -1;
        uint8_t clen = in[cause_at];
        if (cause_at + 1 + clen > len) return -1;
        const uint8_t *cv = in + cause_at + 1;
        if (clen >= 2) {
            out->cause_location = (uint8_t)(cv[0] & 0x0f);
            out->cause = (uint8_t)(cv[1] & 0x7f);
            out->have_cause = 1;
        }
        if (ptr_opt) {
            size_t opt_at = off + 1 + ptr_opt;
            if (opt_at < len)
                walk_optional(in + opt_at, len - opt_at, out);
        }
        break;
    }
    case ISUP_MT_GRS:
    case ISUP_MT_GRA:
    case ISUP_MT_CGB:
    case ISUP_MT_CGU:
    case ISUP_MT_CGBA:
    case ISUP_MT_CGUA:
        if (off < len) {
            uint8_t ptr = in[off];
            size_t at = off + ptr;
            if (ptr && at < len) {
                uint8_t rlen = in[at];
                if (at + 1 + rlen <= len && rlen >= 1) {
                    out->range = in[at + 1];
                    out->have_range = 1;
                }
            }
        }
        break;
    case ISUP_MT_ANM:
    case ISUP_MT_RLC:
    case ISUP_MT_RSC:
    case ISUP_MT_BLO:
    case ISUP_MT_UBL:
    case ISUP_MT_BLA:
    case ISUP_MT_UBA:
        if (off < len && in[off]) {
            size_t opt_at = off + in[off];
            if (opt_at < len)
                walk_optional(in + opt_at, len - opt_at, out);
        }
        break;
    default:
        return -1;
    }
    return 0;
}

static void iam_defaults(isup_msg_t *m, uint16_t cic)
{
    memset(m, 0, sizeof(*m));
    m->cic = cic;
    m->type = ISUP_MT_IAM;
    m->nci = 0x00;
    /* International, ISUP preferred, ISDN user part all the way. */
    m->fci = 0x0120;
    m->cpc = 0x0A;
    m->tmr = 0x00; /* speech */
}

int isup_enc_iam(uint8_t *out, size_t cap, uint16_t cic,
                  const isup_number_t *called, const isup_number_t *calling,
                  const char *rtp_ip, uint16_t rtp_port)
{
    isup_msg_t m;
    iam_defaults(&m, cic);
    if (called) {
        m.called = *called;
        m.have_called = 1;
    }
    if (calling && calling->digits[0]) {
        m.calling = *calling;
        m.have_calling = 1;
    }
    if (rtp_ip && rtp_ip[0]) {
        snprintf(m.ipbcp_ip, sizeof(m.ipbcp_ip), "%s", rtp_ip);
        m.ipbcp_port = rtp_port;
        m.have_ipbcp = 1;
    }
    return isup_encode(&m, out, cap);
}

int isup_enc_acm(uint8_t *out, size_t cap, uint16_t cic, uint16_t bci)
{
    isup_msg_t m;
    memset(&m, 0, sizeof(m));
    m.cic = cic;
    m.type = ISUP_MT_ACM;
    m.bci = bci;
    m.have_bci = 1;
    return isup_encode(&m, out, cap);
}

int isup_enc_cpg(uint8_t *out, size_t cap, uint16_t cic, uint8_t event)
{
    isup_msg_t m;
    memset(&m, 0, sizeof(m));
    m.cic = cic;
    m.type = ISUP_MT_CPG;
    m.event_info = event;
    return isup_encode(&m, out, cap);
}

int isup_enc_anm(uint8_t *out, size_t cap, uint16_t cic)
{
    isup_msg_t m;
    memset(&m, 0, sizeof(m));
    m.cic = cic;
    m.type = ISUP_MT_ANM;
    return isup_encode(&m, out, cap);
}

int isup_enc_rel(uint8_t *out, size_t cap, uint16_t cic, uint8_t cause)
{
    isup_msg_t m;
    memset(&m, 0, sizeof(m));
    m.cic = cic;
    m.type = ISUP_MT_REL;
    m.cause = cause;
    m.have_cause = 1;
    return isup_encode(&m, out, cap);
}

int isup_enc_rlc(uint8_t *out, size_t cap, uint16_t cic)
{
    return isup_enc_empty(out, cap, cic, ISUP_MT_RLC);
}

int isup_enc_blo(uint8_t *out, size_t cap, uint16_t cic)
{
    return isup_enc_empty(out, cap, cic, ISUP_MT_BLO);
}

int isup_enc_bla(uint8_t *out, size_t cap, uint16_t cic)
{
    return isup_enc_empty(out, cap, cic, ISUP_MT_BLA);
}

int isup_enc_ubl(uint8_t *out, size_t cap, uint16_t cic)
{
    return isup_enc_empty(out, cap, cic, ISUP_MT_UBL);
}

int isup_enc_uba(uint8_t *out, size_t cap, uint16_t cic)
{
    return isup_enc_empty(out, cap, cic, ISUP_MT_UBA);
}

int isup_enc_rsc(uint8_t *out, size_t cap, uint16_t cic)
{
    return isup_enc_empty(out, cap, cic, ISUP_MT_RSC);
}

int isup_enc_empty(uint8_t *out, size_t cap, uint16_t cic, uint8_t type)
{
    isup_msg_t m;
    memset(&m, 0, sizeof(m));
    m.cic = cic;
    m.type = type;
    return isup_encode(&m, out, cap);
}

int isup_enc_grs(uint8_t *out, size_t cap, uint16_t cic, uint8_t range)
{
    isup_msg_t m;
    memset(&m, 0, sizeof(m));
    m.cic = cic;
    m.type = ISUP_MT_GRS;
    m.range = range;
    m.have_range = 1;
    return isup_encode(&m, out, cap);
}

int isup_enc_gra(uint8_t *out, size_t cap, uint16_t cic, uint8_t range)
{
    isup_msg_t m;
    memset(&m, 0, sizeof(m));
    m.cic = cic;
    m.type = ISUP_MT_GRA;
    m.range = range;
    m.have_range = 1;
    return isup_encode(&m, out, cap);
}

int isup_cause_to_sip(uint8_t cause)
{
    switch (cause) {
    case 16: return 200; /* normal clearing — north BYE, not a 2xx to INVITE */
    case 17: return 486;
    case 18:
    case 19: return 480;
    case 21: return 403;
    case 27: return 404;
    case 31: return 480;
    case 34: return 503;
    case 41: return 503;
    case 42: return 503;
    case 44: return 503;
    case 1:  return 404;
    case 22: return 410;
    case 28: return 484;
    default: return 503;
    }
}
