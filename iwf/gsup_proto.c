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
         *   RAND(16) + SRES(4) + Kc(8) + AUTN(16) + XRES(16, zero-padded)
         *
         * Notes:
         * - OsmoMSC vlr_auth_fsm expects XRES == 16 bytes for UMTS AKA.
         *   PyHSS returns 8-byte XRES; zero-pad to 16.
         * - IK/CK (0x29/0x2a) are NOT included: Osmocom VLR does not use
         *   them for 3G UMTS AKA and their presence triggers a
         *   "not expected in PDP info" parse warning in gsup.c:310.
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
        /* XRES zero-padded to 16 bytes */
        uint8_t xres16[16];
        memset(xres16, 0, sizeof(xres16));
        if (v->xres_len > 0)
            memcpy(xres16, v->xres, v->xres_len < 16 ? v->xres_len : 16);
        if (gsup_put_sub(tuple, sizeof(tuple), &to, GSUP_AUTH_IE_XRES, xres16, 16) < 0)
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

int gsup_build_ul_res(const char *imsi, const char *msisdn, uint8_t cn_domain,
                      uint8_t *out, size_t cap)
{
    if (!imsi || !out) return -1;
    size_t off = 0;
    out[off++] = GSUP_MSG_UL_RES;
    if (gsup_put_imsi_ie(out, cap, &off, imsi) < 0) return -1;
    if (gsup_enc_msisdn_ie(out, cap, &off, msisdn) < 0) return -1;
    if (cn_domain) {
        uint8_t cn = (cn_domain == GSUP_CN_DOMAIN_CS)
                     ? GSUP_CN_DOMAIN_CS : GSUP_CN_DOMAIN_PS;
        if (gsup_put_ie(out, cap, &off, GSUP_IE_CN_DOMAIN, &cn, 1) < 0)
            return -1;
    }
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

static int gsup_enc_msisdn_ie(uint8_t *out, size_t cap, size_t *off,
                              const char *msisdn)
{
    if (!msisdn || !msisdn[0]) return 0;
    /* OsmoMSC gsm48_decode_bcd_number2(..., h_len=0): [len][TBCD digits only]. */
    uint8_t lv[16];
    size_t in_len = 0;
    for (size_t k = 0; msisdn[k]; k++) {
        if (msisdn[k] >= '0' && msisdn[k] <= '9')
            in_len++;
    }
    if (in_len == 0) return 0;

    lv[0] = (uint8_t)(in_len / 2);
    if (in_len & 1)
        lv[0]++;

    uint8_t *bcd_cur = lv + 1;
    size_t di = 0;
    for (size_t k = 0; msisdn[k]; k++) {
        if (msisdn[k] < '0' || msisdn[k] > '9') continue;
        uint8_t d = (uint8_t)(msisdn[k] - '0');
        if ((di & 1) == 0)
            *bcd_cur = d;
        else
            *bcd_cur++ |= (uint8_t)(d << 4);
        di++;
    }
    if (di & 1)
        *bcd_cur++ |= 0xf0;

    size_t total = (size_t)(bcd_cur - lv);
    if (total > sizeof(lv)) return -1;
    return gsup_put_ie(out, cap, off, GSUP_IE_MSISDN, lv, total);
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

    uint8_t pdp_addr[2] = { 0xF1, 0x21 };
    if (e->pdn_type_nr == 0x57)
        pdp_addr[1] = 0x57;
    else if (e->pdn_type_nr == 0x8d)
        pdp_addr[1] = 0x8d;
    if (gsup_put_sub(pdp, sizeof(pdp), &po, GSUP_IE_PDP_ADDRESS,
                     pdp_addr, sizeof(pdp_addr)) < 0)
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

int gsup_build_isd_req(const char *imsi, const char *msisdn,
                       const map_ula_apn_entry_t *apns, size_t n_apns,
                       uint8_t cn_domain,
                       uint8_t *out, size_t cap)
{
    if (!imsi || !out) return -1;
    size_t off = 0;
    out[off++] = GSUP_MSG_ISD_REQ;
    if (gsup_put_imsi_ie(out, cap, &off, imsi) < 0) return -1;
    if (gsup_enc_msisdn_ie(out, cap, &off, msisdn) < 0) return -1;

    uint8_t cn = (cn_domain == GSUP_CN_DOMAIN_CS)
                 ? GSUP_CN_DOMAIN_CS : GSUP_CN_DOMAIN_PS;
    if (gsup_put_ie(out, cap, &off, GSUP_IE_CN_DOMAIN, &cn, 1) < 0)
        return -1;

    /* GPRS PDP context list is PS-only; MSC/VLR CS ISD carries MSISDN only. */
    if (cn == GSUP_CN_DOMAIN_PS && apns && n_apns > 0) {
        if (gsup_put_ie(out, cap, &off, GSUP_IE_PDP_INFO_COMPL, NULL, 0) < 0)
            return -1;
        for (size_t i = 0; i < n_apns; i++) {
            if (!apns[i].apn[0]) continue;
            if (gsup_enc_pdp_info(out, cap, &off, &apns[i], i) < 0)
                return -1;
        }
    }
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
