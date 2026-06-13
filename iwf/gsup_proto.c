#include "gsup_proto.h"
#include "map_codec.h"

#include <string.h>

static int gsup_put_ie(uint8_t *out, size_t cap, size_t *off,
                       uint8_t tag, const uint8_t *val, size_t vlen)
{
    if (*off + 2 + vlen > cap) return -1;
    out[(*off)++] = tag;
    out[(*off)++] = (uint8_t)vlen;
    memcpy(out + *off, val, vlen);
    *off += vlen;
    return 0;
}

static int gsup_put_imsi_ie(uint8_t *out, size_t cap, size_t *off,
                            const char *imsi)
{
    uint8_t bcd[8];
    int bl = map_str_to_bcd(imsi, bcd, sizeof(bcd));
    if (bl < 0) return -1;
    return gsup_put_ie(out, cap, off, GSUP_IE_IMSI, bcd, (size_t)bl);
}

int gsup_imsi_from_payload(const uint8_t *body, size_t len,
                           char *imsi_out, size_t cap)
{
    gsup_parsed_t p;
    if (gsup_parse_payload(body, len, &p) < 0 || !p.have_imsi)
        return -1;
    if (!imsi_out || cap == 0) return -1;
    strncpy(imsi_out, p.imsi, cap - 1);
    imsi_out[cap - 1] = '\0';
    return 0;
}

int gsup_parse_payload(const uint8_t *body, size_t len, gsup_parsed_t *out)
{
    if (!body || len < 1 || !out) return -1;
    memset(out, 0, sizeof(*out));
    out->msg_type = body[0];
    size_t off = 1;
    while (off + 2 <= len) {
        uint8_t tag = body[off++];
        uint8_t l   = body[off++];
        if (off + l > len) return -1;
        const uint8_t *v = body + off;
        switch (tag) {
        case GSUP_IE_IMSI:
            map_bcd_to_str(v, l, out->imsi, sizeof(out->imsi));
            out->have_imsi = out->imsi[0] != '\0';
            break;
        case GSUP_IE_NUM_VECTORS:
        case GSUP_IE_NUM_VECTORS_REQ:
            if (l >= 1) {
                out->num_vectors = v[0];
                out->have_num_vectors = true;
            }
            break;
        case GSUP_IE_RAND:
            if (l == GSUP_RESYNC_RAND_LEN) {
                memcpy(out->resync_rand, v, GSUP_RESYNC_RAND_LEN);
                out->have_resync_rand = true;
            }
            break;
        case GSUP_IE_AUTS:
            if (l == GSUP_RESYNC_AUTS_LEN) {
                memcpy(out->resync_auts, v, GSUP_RESYNC_AUTS_LEN);
                out->have_resync_auts = true;
            }
            break;
        case GSUP_IE_CN_DOMAIN:
            if (l >= 1) {
                out->cn_domain = v[0];
                out->have_cn_domain = true;
            }
            break;
        default:
            break;
        }
        off += l;
    }
    return 0;
}

/* Osmocom GSUP auth-tuple sub-IE tags — from libosmocore gsm/gsup.h
 * (verified against installed /usr/include/osmocom/gsm/gsup.h v1.14) */
#define GSUP_AUTH_IE_RAND   0x20  /* OSMO_GSUP_RAND_IE  */
#define GSUP_AUTH_IE_SRES   0x21  /* OSMO_GSUP_SRES_IE  */
#define GSUP_AUTH_IE_KC     0x22  /* OSMO_GSUP_KC_IE    */
#define GSUP_AUTH_IE_IK     0x23  /* OSMO_GSUP_IK_IE    */
#define GSUP_AUTH_IE_CK     0x24  /* OSMO_GSUP_CK_IE    */
#define GSUP_AUTH_IE_AUTN   0x25  /* OSMO_GSUP_AUTN_IE  */
#define GSUP_AUTH_IE_AUTS   0x26  /* OSMO_GSUP_AUTS_IE  */
#define GSUP_AUTH_IE_XRES   0x27  /* OSMO_GSUP_RES_IE   */

static int gsup_put_sub(uint8_t *t, size_t cap, size_t *off,
                        uint8_t tag, const uint8_t *v, size_t vlen)
{
    if (*off + 2 + vlen > cap) return -1;
    t[(*off)++] = tag;
    t[(*off)++] = (uint8_t)vlen;
    memcpy(t + *off, v, vlen);
    *off += vlen;
    return 0;
}

static void gsup_prep_auth_vector(map_auth_vector_t *v)
{
    if (!v || !v->have_quintuplet)
        return;
    if (v->xres_len > 0) {
        size_t n = v->xres_len > 4 ? 4 : v->xres_len;
        memcpy(v->sres, v->xres, n);
    }
    /* GSM Kc for interworking: first 8 octets of CK (3GPP TS 33.102 A.4). */
    for (int i = 0; i < 16; i++) {
        if (v->ck[i]) {
            memcpy(v->kc, v->ck, 8);
            break;
        }
    }
}

static int gsup_auth_ck_nonzero(const map_auth_vector_t *v)
{
    for (int i = 0; i < 16; i++)
        if (v->ck[i]) return 1;
    return 0;
}

static int gsup_auth_ik_nonzero(const map_auth_vector_t *v)
{
    for (int i = 0; i < 16; i++)
        if (v->ik[i]) return 1;
    return 0;
}

static int gsup_enc_msisdn_ie(uint8_t *out, size_t cap, size_t *off,
                              const char *msisdn);

static int gsup_enc_auth_tuple(const map_auth_vector_t *v,
                               uint8_t *out, size_t cap, size_t *off)
{
    uint8_t tuple[256];
    size_t to = 0;

    if (v->have_quintuplet) {
        /* UMTS quintuplet for OsmoMSC/OsmoSGSN:
         *   RAND(16) + SRES(4) + Kc(8) + [IK][CK] + AUTN(16) + XRES(actual len)
         *
         * SRES/Kc are derived from XRES/CK for GSM fallback (gsup_prep_auth_vector).
         * Include IK/CK when the HSS AIA carries them (UTRAN-Vector); Open5GS
         * E-UTRAN-Vector omits CK/IK — RES length fix is still required for 3G.
         */
        if (gsup_put_sub(tuple, sizeof(tuple), &to, GSUP_AUTH_IE_RAND, v->rand, 16) < 0)
            return -1;
        /* SRES + Kc always present for GSM fallback */
        if (gsup_put_sub(tuple, sizeof(tuple), &to, GSUP_AUTH_IE_SRES, v->sres, 4) < 0)
            return -1;
        if (gsup_put_sub(tuple, sizeof(tuple), &to, GSUP_AUTH_IE_KC, v->kc, 8) < 0)
            return -1;
        if (gsup_auth_ik_nonzero(v)) {
            if (gsup_put_sub(tuple, sizeof(tuple), &to, GSUP_AUTH_IE_IK, v->ik, 16) < 0)
                return -1;
        }
        if (gsup_auth_ck_nonzero(v)) {
            if (gsup_put_sub(tuple, sizeof(tuple), &to, GSUP_AUTH_IE_CK, v->ck, 16) < 0)
                return -1;
        }
        if (gsup_put_sub(tuple, sizeof(tuple), &to, GSUP_AUTH_IE_AUTN, v->autn, 16) < 0)
            return -1;
        /* XRES: send actual length (Milenage/Open5GS typically 8). OsmoSGSN on
         * UTRAN requires res_len == vec->res_len; zero-padding to 16 breaks
         * the post-resync auth response (first attempt often fails earlier on
         * SQN sync before RES is compared). */
        if (v->xres_len == 0)
            return -1;
        if (gsup_put_sub(tuple, sizeof(tuple), &to, GSUP_AUTH_IE_XRES,
                         v->xres, v->xres_len) < 0)
            return -1;
    } else if (v->have_triplet) {
        /* GSM triplet: RAND + SRES + Kc */
        if (gsup_put_sub(tuple, sizeof(tuple), &to, GSUP_AUTH_IE_RAND, v->rand, 16) < 0)
            return -1;
        if (gsup_put_sub(tuple, sizeof(tuple), &to, GSUP_AUTH_IE_SRES, v->sres, 4) < 0)
            return -1;
        if (gsup_put_sub(tuple, sizeof(tuple), &to, GSUP_AUTH_IE_KC, v->kc, 8) < 0)
            return -1;
    } else {
        return -1;
    }
    return gsup_put_ie(out, cap, off, GSUP_IE_AUTH_TUPLE, tuple, to);
}

int gsup_build_sai_res(const char *imsi,
                       const map_auth_vector_t *vec, size_t n_vec,
                       uint8_t *out, size_t cap)
{
    if (!imsi || !vec || !out || n_vec == 0) return -1;
    map_auth_vector_t av[MAP_AUTH_VECTOR_MAX];
    if (n_vec > MAP_AUTH_VECTOR_MAX) return -1;
    memcpy(av, vec, n_vec * sizeof(av[0]));
    for (size_t i = 0; i < n_vec; i++)
        gsup_prep_auth_vector(&av[i]);
    size_t off = 0;
    if (cap < 4) return -1;
    out[off++] = GSUP_MSG_SAI_RES;
    if (gsup_put_imsi_ie(out, cap, &off, imsi) < 0) return -1;
    for (size_t i = 0; i < n_vec; i++) {
        if (gsup_enc_auth_tuple(&av[i], out, cap, &off) < 0)
            return -1;
    }
    return (int)off;
}

int gsup_build_sai_err(const char *imsi, uint8_t cause,
                       uint8_t *out, size_t cap)
{
    if (!imsi || !out) return -1;
    size_t off = 0;
    out[off++] = GSUP_MSG_SAI_ERR;
    if (gsup_put_imsi_ie(out, cap, &off, imsi) < 0) return -1;
    if (gsup_put_ie(out, cap, &off, GSUP_IE_CAUSE, &cause, 1) < 0)
        return -1;
    return (int)off;
}

int gsup_build_ul_err(const char *imsi, uint8_t cause,
                      uint8_t *out, size_t cap)
{
    if (!imsi || !out) return -1;
    size_t off = 0;
    out[off++] = GSUP_MSG_UL_ERR;
    if (gsup_put_imsi_ie(out, cap, &off, imsi) < 0) return -1;
    if (gsup_put_ie(out, cap, &off, GSUP_IE_CAUSE, &cause, 1) < 0)
        return -1;
    return (int)off;
}

int gsup_build_loc_cancel_req(const char *imsi, uint8_t cancel_type,
                              uint8_t *out, size_t cap)
{
    if (!imsi || !out) return -1;
    size_t off = 0;
    out[off++] = GSUP_MSG_LOC_CANCEL_REQ;
    if (gsup_put_imsi_ie(out, cap, &off, imsi) < 0) return -1;
    if (cancel_type != 0) {
        if (gsup_put_ie(out, cap, &off, GSUP_IE_CANCEL_TYPE,
                        &cancel_type, 1) < 0)
            return -1;
    }
    return (int)off;
}

/* gsm48_encode_bcd_number(h_len=0): [L][TBCD digits], no TON/NPI — same as
 * osmo-hlr osmo_gsup_create_insert_subscriber_data_msg().  osmo-msc decodes
 * with gsm48_decode_bcd_number2(..., h_len=0). */
static int gsup_enc_bcd_digits_gsm48(uint8_t *out, size_t cap, const char *digits)
{
    if (!digits || !digits[0]) return 0;

    char num[24];
    size_t n = 0;
    for (size_t k = 0; digits[k] && n + 1 < sizeof(num); k++) {
        if (digits[k] >= '0' && digits[k] <= '9')
            num[n++] = digits[k];
    }
    if (n == 0) return 0;

    uint8_t bcd_len = (uint8_t)(n / 2 + (n & 1));
    if ((size_t)1 + bcd_len > cap) return -1;

    out[0] = bcd_len;
    size_t pos = 1;
    for (size_t i = 0; i < n; i++) {
        uint8_t d = (uint8_t)(num[i] - '0');
        if ((i & 1) == 0)
            out[pos + i / 2] = d;
        else
            out[pos + i / 2] = (uint8_t)(out[pos + i / 2] | (d << 4));
    }
    if (n & 1)
        out[pos + n / 2] = (uint8_t)(out[pos + n / 2] | 0xf0);

    return (int)(1 + bcd_len);
}

static int gsup_enc_isdn_addr_ie(uint8_t *out, size_t cap, size_t *off,
                                 uint8_t tag, const char *digits)
{
    if (!digits || !digits[0]) return 0;

    /* HLR-Number: MAP AddressString with TON/NPI (international ISDN). */
    uint8_t val[16];
    size_t pos = 0;
    val[pos++] = 0x91;

    int di = 0;
    for (size_t k = 0; digits[k] && pos < sizeof(val); k++) {
        if (digits[k] < '0' || digits[k] > '9') continue;
        uint8_t d = (uint8_t)(digits[k] - '0');
        size_t boff = pos + (size_t)(di / 2);
        if (boff >= sizeof(val)) break;
        if ((di & 1) == 0)
            val[boff] = d;
        else
            val[boff] = (uint8_t)(val[boff] | (d << 4));
        di++;
    }
    if (di == 0) return 0;
    if (di & 1) {
        size_t boff = pos + (size_t)(di / 2);
        if (boff >= sizeof(val)) return -1;
        val[boff] = (uint8_t)((val[boff] & 0x0f) | 0xf0);
    }
    pos += (size_t)((di + 1) / 2);
    if (pos > sizeof(val)) return -1;
    return gsup_put_ie(out, cap, off, tag, val, pos);
}

static int gsup_enc_msisdn_ie(uint8_t *out, size_t cap, size_t *off,
                              const char *msisdn)
{
    if (!msisdn || !msisdn[0]) return 0;

    uint8_t val[16];
    int n = gsup_enc_bcd_digits_gsm48(val, sizeof(val), msisdn);
    if (n <= 0) return n;
    return gsup_put_ie(out, cap, off, GSUP_IE_MSISDN, val, (size_t)n);
}

static int gsup_enc_apn_wire(const char *apn, uint8_t *out, size_t cap)
{
    size_t off = 0;
    const char *seg = apn;
    while (*seg && off + 2 < cap) {
        const char *dot = strchr(seg, '.');
        size_t lab = dot ? (size_t)(dot - seg) : strlen(seg);
        if (lab == 0 || lab > 63 || off + 1 + lab > cap)
            return -1;
        out[off++] = (uint8_t)lab;
        memcpy(out + off, seg, lab);
        off += lab;
        if (!dot) break;
        seg = dot + 1;
    }
    return (int)off;
}

static int gsup_enc_pdp_info(uint8_t *out, size_t cap, size_t *off,
                             const map_ula_apn_entry_t *e, size_t idx)
{
    uint8_t pdp[256];
    size_t po = 0;
    uint8_t ctx = e->context_id ? e->context_id : (uint8_t)(idx + 1);

    if (gsup_put_sub(pdp, sizeof(pdp), &po, GSUP_IE_PDP_CONTEXT_ID,
                     &ctx, 1) < 0)
        return -1;

    uint8_t pdp_addr[22];
    size_t pdp_addr_len = 2;
    uint8_t pdn_type = e->pdn_type_nr ? e->pdn_type_nr : GTPV1_PDP_TYPE_IPV4;

    pdp_addr[0] = 0xF1;
    pdp_addr[1] = pdn_type;

    if (pdn_type == GTPV1_PDP_TYPE_IPV4 && e->has_ue_ipv4) {
        memcpy(pdp_addr + 2, e->ue_ipv4, 4);
        pdp_addr_len = 6;
    } else if (pdn_type == GTPV1_PDP_TYPE_IPV6 && e->has_ue_ipv6) {
        memcpy(pdp_addr + 2, e->ue_ipv6, 16);
        pdp_addr_len = 18;
    } else if (pdn_type == GTPV1_PDP_TYPE_IPV4V6) {
        if (e->has_ue_ipv4) {
            memcpy(pdp_addr + 2, e->ue_ipv4, 4);
            pdp_addr_len = 6;
        }
        if (e->has_ue_ipv6) {
            memcpy(pdp_addr + pdp_addr_len, e->ue_ipv6, 16);
            pdp_addr_len += 16;
        }
    }

    if (gsup_put_sub(pdp, sizeof(pdp), &po, GSUP_IE_PDP_ADDRESS,
                     pdp_addr, pdp_addr_len) < 0)
        return -1;

    uint8_t apn_wire[68];
    int aw = gsup_enc_apn_wire(e->apn, apn_wire, sizeof(apn_wire));
    if (aw < 0)
        return -1;
    if (gsup_put_sub(pdp, sizeof(pdp), &po, GSUP_IE_APN,
                     apn_wire, (size_t)aw) < 0)
        return -1;

    static const uint8_t default_qos[] = {
        0x57, 0x59, 0x96, 0x6C, 0x62, 0x76, 0x86, 0x60,
        0x40, 0x80, 0x00, 0x00, 0x60, 0x40, 0x80, 0x00, 0x00,
    };
    if (gsup_put_sub(pdp, sizeof(pdp), &po, GSUP_IE_PDP_QOS,
                     default_qos, sizeof(default_qos)) < 0)
        return -1;

    return gsup_put_ie(out, cap, off, GSUP_IE_PDP_INFO, pdp, po);
}

static int gsup_enc_subscriber_data_ies(uint8_t *out, size_t cap, size_t *off,
                                        const char *msisdn,
                                        const char *hlr_number,
                                        uint8_t cn_domain,
                                        const map_ula_apn_entry_t *apns,
                                        size_t n_apns)
{
    if (gsup_enc_msisdn_ie(out, cap, off, msisdn) < 0) return -1;
    if (gsup_enc_isdn_addr_ie(out, cap, off, GSUP_IE_HLR_NUMBER,
                              hlr_number) < 0)
        return -1;

    uint8_t cn = (cn_domain == GSUP_CN_DOMAIN_CS)
                 ? GSUP_CN_DOMAIN_CS : GSUP_CN_DOMAIN_PS;
    if (gsup_put_ie(out, cap, off, GSUP_IE_CN_DOMAIN, &cn, 1) < 0)
        return -1;

    if (cn == GSUP_CN_DOMAIN_PS && apns && n_apns > 0) {
        if (gsup_put_ie(out, cap, off, GSUP_IE_PDP_INFO_COMPL, NULL, 0) < 0)
            return -1;
        for (size_t i = 0; i < n_apns; i++) {
            if (!apns[i].apn[0]) continue;
            if (gsup_enc_pdp_info(out, cap, off, &apns[i], i) < 0)
                return -1;
        }
    }
    return 0;
}

int gsup_build_ul_res(const char *imsi, const char *msisdn,
                      const map_ula_apn_entry_t *apns, size_t n_apns,
                      uint8_t cn_domain, const char *hlr_number,
                      uint8_t *out, size_t cap)
{
    if (!imsi || !out) return -1;
    size_t off = 0;
    out[off++] = GSUP_MSG_UL_RES;
    if (gsup_put_imsi_ie(out, cap, &off, imsi) < 0) return -1;
    if (msisdn || hlr_number || n_apns > 0 || cn_domain) {
        if (gsup_enc_subscriber_data_ies(out, cap, &off, msisdn, hlr_number,
                                         cn_domain, apns, n_apns) < 0)
            return -1;
    }
    return (int)off;
}

int gsup_build_isd_req(const char *imsi, const char *msisdn,
                       const map_ula_apn_entry_t *apns, size_t n_apns,
                       uint8_t cn_domain, const char *hlr_number,
                       uint8_t *out, size_t cap)
{
    if (!imsi || !out) return -1;
    size_t off = 0;
    out[off++] = GSUP_MSG_ISD_REQ;
    if (gsup_put_imsi_ie(out, cap, &off, imsi) < 0) return -1;
    if (gsup_enc_subscriber_data_ies(out, cap, &off, msisdn, hlr_number,
                                     cn_domain, apns, n_apns) < 0)
        return -1;
    return (int)off;
}

int gsup_ipa_wrap(const uint8_t *gsup, size_t gsup_len,
                  uint8_t *out, size_t cap)
{
    /* ipa_len = 1 (ext) + gsup_len; frame = 2 + 1 + ipa_len */
    if (!gsup || !out || gsup_len > 65530) return -1;
    size_t ipa_len = 1u + gsup_len;
    size_t frame   = 3u + ipa_len;
    if (frame > cap) return -1;
    out[0] = (uint8_t)((ipa_len >> 8) & 0xff);
    out[1] = (uint8_t)(ipa_len & 0xff);
    out[2] = GSUP_IPA_PROTO_OSMO;
    out[3] = GSUP_IPA_EXT_GSUP;
    memcpy(out + 4, gsup, gsup_len);
    return (int)frame;
}
