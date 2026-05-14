/*
 * map_codec.c - MAP (3GPP TS 29.002) BER encode/decode.
 *
 * Each operation argument is a tagged ASN.1 SEQUENCE.  We do not implement
 * a generic ASN.1 compiler output; instead we hand-code the few fields each
 * supported operation actually uses, taking advantage of the fact that
 * most MAP IEs are either OCTET STRING (BCD) or simple INTEGERs.
 *
 * The BCD encoding for IMSI / E.164 follows TS 24.008 §10.5.1.4:
 *     low-nibble = first digit, high-nibble = second digit.
 *     0xF in the high nibble of the last octet pads odd-length strings.
 *
 * AARQ / AARE
 * -----------
 * Each MAP dialogue carries either an AARQ (in TCAP Begin) or AARE (in TCAP
 * Continue/End) inside the dialogue portion.  We emit a compact AARQ/AARE
 * carrying just the application-context-name OID; that's all the MAP spec
 * requires for our supported operations.
 *
 * Note: MAP encoding has many vendor- and version-specific edge cases.  This
 * codec implements the common subset that interoperates with Osmocom HLRs,
 * Mobicents JSS7, and real-world SGSN/HLR equipment.  Unknown / extension
 * fields on decode are silently skipped (forward compatibility); on encode
 * we emit only mandatory IEs plus the small handful of optional ones our
 * Diameter peer needs.
 */

#include "map_codec.h"
#include "tcap.h"
#include "logging.h"

#include <stdint.h>
#include <string.h>
#include <ctype.h>

/* ====================================================================== */
/* BCD helpers                                                            */
/* ====================================================================== */

void map_bcd_to_str(const uint8_t *bcd, size_t bcd_len, char *out, size_t cap)
{
    if (!out || cap == 0) return;
    size_t o = 0;
    for (size_t i = 0; i < bcd_len; i++) {
        uint8_t lo = bcd[i] & 0x0f;
        uint8_t hi = (bcd[i] >> 4) & 0x0f;
        if (o + 1 >= cap) break;
        if (lo > 9) break;
        out[o++] = (char)('0' + lo);
        if (o + 1 >= cap) break;
        if (hi > 9) break;
        out[o++] = (char)('0' + hi);
    }
    out[o] = '\0';
}

int map_str_to_bcd(const char *digits, uint8_t *out, size_t out_cap)
{
    if (!digits || !out) return -1;
    size_t n = strlen(digits);
    size_t need = (n + 1) / 2;
    if (need > out_cap) return -1;
    memset(out, 0xff, need);
    for (size_t i = 0; i < n; i++) {
        if (!isdigit((unsigned char)digits[i])) return -1;
        uint8_t d = (uint8_t)(digits[i] - '0');
        uint8_t *p = &out[i / 2];
        if ((i & 1) == 0) {
            *p = (*p & 0xf0) | (d & 0x0f);
        } else {
            *p = (uint8_t)((*p & 0x0f) | ((d & 0x0f) << 4));
        }
    }
    return (int)need;
}

int map_plmn_pack(uint16_t mcc, uint16_t mnc, uint8_t out[3])
{
    /* TS 24.008 §10.5.1.3: MCC=ABC, MNC=DEF =>
     *   octet1 = B|A
     *   octet2 = F|C   (F = 0xF when MNC is 2 digits)
     *   octet3 = E|D                                                   */
    uint8_t mcc1 = (uint8_t)((mcc / 100) % 10);
    uint8_t mcc2 = (uint8_t)((mcc /  10) % 10);
    uint8_t mcc3 = (uint8_t)( mcc        % 10);
    uint8_t mnc1, mnc2, mnc3;
    if (mnc >= 100) {
        mnc1 = (uint8_t)((mnc / 100) % 10);
        mnc2 = (uint8_t)((mnc /  10) % 10);
        mnc3 = (uint8_t)( mnc        % 10);
    } else {
        mnc1 = (uint8_t)((mnc / 10) % 10);
        mnc2 = (uint8_t)( mnc       % 10);
        mnc3 = 0xf;
    }
    out[0] = (uint8_t)((mcc2 << 4) | mcc1);
    out[1] = (uint8_t)((mnc3 << 4) | mcc3);
    out[2] = (uint8_t)((mnc2 << 4) | mnc1);
    return 0;
}

int map_plmn_unpack(const uint8_t in[3], uint16_t *mcc, uint16_t *mnc)
{
    uint8_t mcc1 =  in[0]       & 0x0f;
    uint8_t mcc2 = (in[0] >> 4) & 0x0f;
    uint8_t mcc3 =  in[1]       & 0x0f;
    uint8_t mnc3 = (in[1] >> 4) & 0x0f;
    uint8_t mnc1 =  in[2]       & 0x0f;
    uint8_t mnc2 = (in[2] >> 4) & 0x0f;
    *mcc = (uint16_t)(mcc1 * 100 + mcc2 * 10 + mcc3);
    if (mnc3 == 0xf) *mnc = (uint16_t)(mnc1 * 10 + mnc2);
    else             *mnc = (uint16_t)(mnc1 * 100 + mnc2 * 10 + mnc3);
    return 0;
}

/* Helper: walk every TLV in a SEQUENCE body, returning the first match. */
static int find_tlv(const uint8_t *p, size_t n, uint8_t want_tag,
                    const uint8_t **out_val, size_t *out_len)
{
    size_t off = 0;
    while (off < n) {
        uint8_t tag;
        const uint8_t *v;
        size_t l;
        if (ber_dec_tlv(p, n, &off, &tag, &v, &l) < 0) return -1;
        if (tag == want_tag) { *out_val = v; *out_len = l; return 0; }
    }
    return -1;
}

/* Helper: strip an outer SEQUENCE / SET wrapper, leaving the body. */
static int unwrap_seq(const uint8_t *p, size_t n,
                      const uint8_t **out_body, size_t *out_len)
{
    if (n < 2) return -1;
    size_t off = 0;
    uint8_t tag;
    if (ber_dec_tlv(p, n, &off, &tag, out_body, out_len) < 0) return -1;
    /* Some senders use [APPLICATION x] tags here, others 0x30 SEQUENCE.
     * We accept anything constructed and inspect the body. */
    if ((tag & 0x20) == 0) return -1;
    return 0;
}

/* ====================================================================== */
/* Decoders                                                               */
/* ====================================================================== */

int map_decode_sai_arg(const uint8_t *p, size_t n, map_sai_req_t *out)
{
    /* SendAuthenticationInfoArg ::= SEQUENCE {
     *   imsi                  [0]  IMPLICIT IMSI,           -- OCTET STRING (BCD)
     *   numberOfRequestedVectors [2] IMPLICIT INTEGER (1..5),
     *   ...                                                                  */
    if (!p || !out) return -1;
    memset(out, 0, sizeof(*out));
    out->num_vectors = 1;

    const uint8_t *body = p;
    size_t blen = n;
    /* Accept either the bare SEQUENCE or the inner contents. */
    if (n >= 2 && (p[0] == 0x30 || (p[0] & 0x20))) {
        if (unwrap_seq(p, n, &body, &blen) < 0) return -1;
    }

    /* Walk fields by their context-specific tags. */
    size_t off = 0;
    while (off < blen) {
        uint8_t tag;
        const uint8_t *v;
        size_t l;
        if (ber_dec_tlv(body, blen, &off, &tag, &v, &l) < 0) return -1;

        if (tag == 0x80 || tag == 0x04) {           /* [0] IMPLICIT IMSI */
            if (l > sizeof(out->imsi_bcd)) l = sizeof(out->imsi_bcd);
            memcpy(out->imsi_bcd, v, l);
            out->imsi_bcd_len = (uint8_t)l;
            map_bcd_to_str(v, l, out->imsi_str, sizeof(out->imsi_str));
        } else if (tag == 0x82) {                    /* [2] numberOfRequestedVectors */
            uint32_t nv = 1;
            ber_dec_integer_u32(v, l, &nv);
            if (nv >= 1 && nv <= 5) out->num_vectors = (uint8_t)nv;
        } else if (tag == 0x83) {                    /* [3] segmentationProhibited (NULL) */
            /* present = TRUE; we don't need to do anything */
        } else if (tag == 0x84) {                    /* [4] immediateResponsePreferred (NULL) */
        } else if (tag == 0x85 || tag == 0x95) {     /* [5] requestingNodeType */
            uint32_t v32 = 0;
            ber_dec_integer_u32(v, l, &v32);
            out->requesting_node_type = (uint8_t)v32;
            out->have_requesting_node_type = true;
        } else if (tag == 0x86) {                    /* [6] requestingPLMN-Id */
            /* TBCD MCC+MNC, 3 octets; we store nothing here; map_iwf.c derives
             * visited PLMN from this exact tag via direct lookup below. */
        }
    }
    return out->imsi_bcd_len ? 0 : -1;
}

int map_decode_ugl_arg(const uint8_t *p, size_t n, map_ugl_req_t *out)
{
    /* UpdateGprsLocationArg ::= SEQUENCE {
     *   imsi                  IMSI,
     *   sgsn-Number           ISDN-AddressString,
     *   sgsn-Address          GSN-Address,
     *   ... }                                                              */
    if (!p || !out) return -1;
    memset(out, 0, sizeof(*out));
    const uint8_t *body = p;
    size_t blen = n;
    if (n >= 2 && (p[0] == 0x30 || (p[0] & 0x20))) {
        if (unwrap_seq(p, n, &body, &blen) < 0) return -1;
    }

    size_t off = 0;
    int seq_idx = 0;
    while (off < blen) {
        uint8_t tag;
        const uint8_t *v;
        size_t l;
        if (ber_dec_tlv(body, blen, &off, &tag, &v, &l) < 0) return -1;

        if (tag == 0x04 && seq_idx == 0) {           /* OCTET STRING - IMSI */
            if (l > sizeof(out->imsi_bcd)) l = sizeof(out->imsi_bcd);
            memcpy(out->imsi_bcd, v, l);
            out->imsi_bcd_len = (uint8_t)l;
            map_bcd_to_str(v, l, out->imsi_str, sizeof(out->imsi_str));
            seq_idx++;
        } else if (tag == 0x04 && seq_idx == 1) {    /* sgsn-Number */
            if (l > sizeof(out->sgsn_number_bcd)) l = sizeof(out->sgsn_number_bcd);
            memcpy(out->sgsn_number_bcd, v, l);
            out->sgsn_number_bcd_len = (uint8_t)l;
            seq_idx++;
        } else if (tag == 0x04 && seq_idx == 2) {    /* sgsn-Address */
            if (l > sizeof(out->sgsn_addr)) l = sizeof(out->sgsn_addr);
            memcpy(out->sgsn_addr, v, l);
            out->sgsn_addr_len = (uint8_t)l;
            seq_idx++;
        } else if (tag == 0x80) {                    /* [0] msNetworkCapability or similar */
            /* skip */
        }
        /* Other optional fields ignored. */
    }
    return out->imsi_bcd_len ? 0 : -1;
}

int map_decode_cl_arg(const uint8_t *p, size_t n, map_cl_req_t *out)
{
    if (!p || !out) return -1;
    memset(out, 0, sizeof(*out));
    const uint8_t *body = p;
    size_t blen = n;
    if (n >= 2 && (p[0] == 0x30 || (p[0] & 0x20))) {
        if (unwrap_seq(p, n, &body, &blen) < 0) return -1;
    }
    const uint8_t *v; size_t l;
    if (find_tlv(body, blen, 0x04, &v, &l) == 0 ||
        find_tlv(body, blen, 0x80, &v, &l) == 0) {
        if (l > sizeof(out->imsi_bcd)) l = sizeof(out->imsi_bcd);
        memcpy(out->imsi_bcd, v, l);
        out->imsi_bcd_len = (uint8_t)l;
        map_bcd_to_str(v, l, out->imsi_str, sizeof(out->imsi_str));
    }
    if (find_tlv(body, blen, 0x0a, &v, &l) == 0) {   /* ENUMERATED */
        uint32_t ct = 0;
        ber_dec_integer_u32(v, l, &ct);
        out->cancellation_type = (uint8_t)ct;
    }
    return out->imsi_bcd_len ? 0 : -1;
}

int map_decode_purge_arg(const uint8_t *p, size_t n, map_purge_req_t *out)
{
    if (!p || !out) return -1;
    memset(out, 0, sizeof(*out));
    const uint8_t *body = p;
    size_t blen = n;
    if (n >= 2 && (p[0] == 0x30 || (p[0] & 0x20))) {
        if (unwrap_seq(p, n, &body, &blen) < 0) return -1;
    }
    const uint8_t *v; size_t l;
    if (find_tlv(body, blen, 0x04, &v, &l) == 0 ||
        find_tlv(body, blen, 0x80, &v, &l) == 0) {
        if (l > sizeof(out->imsi_bcd)) l = sizeof(out->imsi_bcd);
        memcpy(out->imsi_bcd, v, l);
        out->imsi_bcd_len = (uint8_t)l;
        map_bcd_to_str(v, l, out->imsi_str, sizeof(out->imsi_str));
    }
    return out->imsi_bcd_len ? 0 : -1;
}

/* ====================================================================== */
/* Encoders                                                               */
/* ====================================================================== */

/* AuthenticationQuintuplet (TS 29.002 §8.5.1):
 *   SEQUENCE { rand OCTET STRING (4..16),
 *              xres OCTET STRING (4..16),
 *              ck   OCTET STRING (16),
 *              ik   OCTET STRING (16),
 *              autn OCTET STRING (16) }                                  */
static int enc_quintuplet(const map_auth_vector_t *v,
                          uint8_t *out, size_t cap, size_t *off)
{
    uint8_t inner[128];
    size_t io = 0;
    if (ber_enc_tlv(inner, sizeof(inner), &io, 0x04, v->rand, 16) < 0) return -1;
    if (ber_enc_tlv(inner, sizeof(inner), &io, 0x04, v->xres, v->xres_len) < 0) return -1;
    if (ber_enc_tlv(inner, sizeof(inner), &io, 0x04, v->ck,   16) < 0) return -1;
    if (ber_enc_tlv(inner, sizeof(inner), &io, 0x04, v->ik,   16) < 0) return -1;
    if (ber_enc_tlv(inner, sizeof(inner), &io, 0x04, v->autn, 16) < 0) return -1;
    return ber_enc_tlv(out, cap, off, 0x30 /* SEQUENCE */, inner, io);
}

static int enc_triplet(const map_auth_vector_t *v,
                       uint8_t *out, size_t cap, size_t *off)
{
    uint8_t inner[64];
    size_t io = 0;
    if (ber_enc_tlv(inner, sizeof(inner), &io, 0x04, v->rand, 16) < 0) return -1;
    if (ber_enc_tlv(inner, sizeof(inner), &io, 0x04, v->sres, 4)  < 0) return -1;
    if (ber_enc_tlv(inner, sizeof(inner), &io, 0x04, v->kc,   8)  < 0) return -1;
    return ber_enc_tlv(out, cap, off, 0x30 /* SEQUENCE */, inner, io);
}

int map_encode_sai_res(const map_auth_vector_t *vec, size_t n_vec,
                       uint8_t *out, size_t out_cap)
{
    /* SendAuthenticationInfoRes-v3 ::= SEQUENCE {
     *   authenticationSetList AuthenticationSetList OPTIONAL,
     *   ... }
     * AuthenticationSetList ::= CHOICE {
     *   tripletList   [0] IMPLICIT TripletList,
     *   quintupletList[1] IMPLICIT QuintupletList }                       */
    uint8_t outer[2048];
    size_t oo = 0;
    uint8_t list[2048];
    size_t lo = 0;

    /* Prefer quintuplets when at least one is present. */
    bool quint = false;
    for (size_t i = 0; i < n_vec; i++) if (vec[i].have_quintuplet) { quint = true; break; }

    if (quint) {
        for (size_t i = 0; i < n_vec; i++) {
            if (!vec[i].have_quintuplet) continue;
            if (enc_quintuplet(&vec[i], list, sizeof(list), &lo) < 0) return -1;
        }
        if (ber_enc_tlv(outer, sizeof(outer), &oo, 0xA1 /* [1] */, list, lo) < 0)
            return -1;
    } else {
        for (size_t i = 0; i < n_vec; i++) {
            if (!vec[i].have_triplet) continue;
            if (enc_triplet(&vec[i], list, sizeof(list), &lo) < 0) return -1;
        }
        if (ber_enc_tlv(outer, sizeof(outer), &oo, 0xA0 /* [0] */, list, lo) < 0)
            return -1;
    }

    size_t off = 0;
    if (ber_enc_tlv(out, out_cap, &off, 0x30 /* SEQUENCE */, outer, oo) < 0)
        return -1;
    return (int)off;
}

int map_encode_ugl_res(const uint8_t *hlr_number_bcd, size_t hlr_len,
                       uint8_t *out, size_t out_cap)
{
    /* UpdateGprsLocationRes ::= SEQUENCE { hlr-Number ISDN-AddressString } */
    uint8_t inner[64];
    size_t io = 0;
    if (hlr_number_bcd && hlr_len) {
        if (ber_enc_tlv(inner, sizeof(inner), &io,
                        0x04, hlr_number_bcd, hlr_len) < 0) return -1;
    } else {
        /* Synthesize a minimal non-empty hlr-Number = "00" so the SGSN
         * doesn't reject our response as malformed. */
        static const uint8_t fake[1] = { 0x00 };
        if (ber_enc_tlv(inner, sizeof(inner), &io, 0x04, fake, 1) < 0) return -1;
    }
    size_t off = 0;
    if (ber_enc_tlv(out, out_cap, &off, 0x30, inner, io) < 0) return -1;
    return (int)off;
}

int map_encode_isd_arg(const char *imsi_str,
                       const char *msisdn_str,
                       const char *apn,
                       uint64_t ambr_ul_bps,
                       uint64_t ambr_dl_bps,
                       uint8_t *out, size_t out_cap)
{
    /* InsertSubscriberDataArg ::= SEQUENCE {
     *   imsi                       IMSI                     OPTIONAL,
     *   msisdn                     ISDN-AddressString       OPTIONAL,
     *   ...
     *   apn-Configuration-Profile  [9] APN-Configuration-Profile OPTIONAL,
     *   ... }
     *
     * We construct just IMSI + MSISDN + a single APN entry with AMBR.  This
     * matches what the SGSN expects to populate the PDP context.            */
    uint8_t inner[1024];
    size_t io = 0;

    if (imsi_str && *imsi_str) {
        uint8_t bcd[8];
        int n = map_str_to_bcd(imsi_str, bcd, sizeof(bcd));
        if (n > 0)
            if (ber_enc_tlv(inner, sizeof(inner), &io, 0x04, bcd, (size_t)n) < 0)
                return -1;
    }
    if (msisdn_str && *msisdn_str) {
        /* ISDN-AddressString = octet[0]: NoA (0x91 = international, ISDN/E.164),
         * followed by BCD digits. */
        uint8_t buf[12];
        buf[0] = 0x91;
        int n = map_str_to_bcd(msisdn_str, buf + 1, sizeof(buf) - 1);
        if (n > 0)
            if (ber_enc_tlv(inner, sizeof(inner), &io, 0x04, buf, (size_t)(n + 1)) < 0)
                return -1;
    }
    /* APN configuration (we encode at most one). Tagged [9] IMPLICIT. */
    if (apn && *apn) {
        uint8_t apn_seq[256];
        size_t ao = 0;
        /* context-Id [0] INTEGER */
        if (ber_enc_integer_u32(apn_seq, sizeof(apn_seq), &ao, 0x80, 1) < 0) return -1;
        /* PDN-Type [1] INTEGER (0=IPv4) */
        if (ber_enc_integer_u32(apn_seq, sizeof(apn_seq), &ao, 0x81, 0) < 0) return -1;
        /* APN [2] OCTET STRING - DNS-labels form (length-prefixed segments). */
        uint8_t apn_dns[68];
        size_t adns = 0;
        const char *seg = apn;
        while (*seg) {
            const char *dot = strchr(seg, '.');
            size_t segl = dot ? (size_t)(dot - seg) : strlen(seg);
            if (adns + 1 + segl > sizeof(apn_dns)) break;
            apn_dns[adns++] = (uint8_t)segl;
            memcpy(apn_dns + adns, seg, segl);
            adns += segl;
            if (!dot) break;
            seg = dot + 1;
        }
        if (ber_enc_tlv(apn_seq, sizeof(apn_seq), &ao, 0x82, apn_dns, adns) < 0)
            return -1;
        /* AMBR [3] SEQUENCE { ul, dl } */
        if (ambr_ul_bps || ambr_dl_bps) {
            uint8_t ambr[32];
            size_t mo = 0;
            uint32_t ul_kbps = (uint32_t)(ambr_ul_bps / 1000);
            uint32_t dl_kbps = (uint32_t)(ambr_dl_bps / 1000);
            if (ber_enc_integer_u32(ambr, sizeof(ambr), &mo, 0x80, ul_kbps) < 0) return -1;
            if (ber_enc_integer_u32(ambr, sizeof(ambr), &mo, 0x81, dl_kbps) < 0) return -1;
            if (ber_enc_tlv(apn_seq, sizeof(apn_seq), &ao, 0xA3, ambr, mo) < 0)
                return -1;
        }
        if (ber_enc_tlv(inner, sizeof(inner), &io, 0xA9 /* [9] */, apn_seq, ao) < 0)
            return -1;
    }

    size_t off = 0;
    if (ber_enc_tlv(out, out_cap, &off, 0x30, inner, io) < 0) return -1;
    return (int)off;
}

int map_encode_cl_arg(const uint8_t *imsi_bcd, size_t imsi_bcd_len,
                      uint8_t cancellation_type,
                      uint8_t *out, size_t out_cap)
{
    /* CancelLocationArg ::= SEQUENCE {
     *   identity            CHOICE { imsi OCTET STRING, ... },
     *   cancellationType    CancellationType OPTIONAL }                  */
    uint8_t inner[64];
    size_t io = 0;
    if (ber_enc_tlv(inner, sizeof(inner), &io, 0x04, imsi_bcd, imsi_bcd_len) < 0)
        return -1;
    if (ber_enc_integer_u32(inner, sizeof(inner), &io, 0x0A /* ENUMERATED */,
                            cancellation_type) < 0) return -1;
    size_t off = 0;
    if (ber_enc_tlv(out, out_cap, &off, 0x30, inner, io) < 0) return -1;
    return (int)off;
}

int map_encode_purge_res(bool freeze_ptmsi,
                         uint8_t *out, size_t out_cap)
{
    /* PurgeMS-Res ::= SEQUENCE { freezeTMSI [0] NULL OPTIONAL,
     *                            freezePtmsi [1] NULL OPTIONAL, ... }    */
    uint8_t inner[8];
    size_t io = 0;
    if (freeze_ptmsi) {
        if (ber_enc_tlv(inner, sizeof(inner), &io, 0x81, NULL, 0) < 0) return -1;
    }
    size_t off = 0;
    if (ber_enc_tlv(out, out_cap, &off, 0x30, inner, io) < 0) return -1;
    return (int)off;
}

int map_encode_systemfailure_diag(uint8_t network_resource,
                                  uint8_t *out, size_t out_cap)
{
    /* SystemFailureParam ::= CHOICE {
     *   networkResource     NetworkResource,
     *   extensibleSystemFailureParam [0] IMPLICIT SEQUENCE { ... } }    */
    size_t off = 0;
    return ber_enc_integer_u32(out, out_cap, &off, 0x0A /* ENUMERATED */,
                               network_resource) < 0 ? -1 : (int)off;
}

/* ====================================================================== */
/* AARQ / AARE dialogue portion                                           */
/* ====================================================================== */

/*
 * Per-context OID byte arrays.  All MAP ACs are rooted at
 *   itu-t.identified-organization.etsi.mobileDomain.gsm-NetworkId.ac
 * = 0.4.0.0.1   (and within that ".(context).version")
 * In BER OID encoding, the first two arcs collapse: 0.4 -> byte 0x04, etc.
 *
 * The full prefix for our 3GPP MAP ACs (TS 29.002 §17.1):
 *   itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1)
 *   ac(0) <context> <version>
 *
 * Encoded: 04 00 00 01 00 <ctx> <ver>
 *
 * Concrete OIDs we emit (version 3):
 *   infoRetrievalContext-v3              0.4.0.0.1.0.14.3 -> 04 00 00 01 00 0e 03
 *   gprsLocationUpdateContext-v3         0.4.0.0.1.0.32.3 -> 04 00 00 01 00 20 03
 *   subscriberDataMngtContext-v3         0.4.0.0.1.0.16.3 -> 04 00 00 01 00 10 03
 *   gprsLocationCancellationCtx-v3       0.4.0.0.1.0. 7.3 -> 04 00 00 01 00 07 03
 *   msPurgingContext-v3                  0.4.0.0.1.0.27.3 -> 04 00 00 01 00 1b 03
 */
static const uint8_t AC_INFO_RETRIEVAL_V3[]      = { 0x04,0x00,0x00,0x01,0x00,0x0e,0x03 };
static const uint8_t AC_GPRS_LOC_UPDATE_V3[]     = { 0x04,0x00,0x00,0x01,0x00,0x20,0x03 };
static const uint8_t AC_SUBSCRIBER_DATA_MGMT_V3[]= { 0x04,0x00,0x00,0x01,0x00,0x10,0x03 };
static const uint8_t AC_GPRS_LOC_CANCEL_V3[]     = { 0x04,0x00,0x00,0x01,0x00,0x07,0x03 };
static const uint8_t AC_MS_PURGING_V3[]          = { 0x04,0x00,0x00,0x01,0x00,0x1b,0x03 };

static int oid_for_ac(map_app_ctx_t ac, const uint8_t **out, size_t *out_len)
{
    switch (ac) {
    case MAP_AC_INFO_RETRIEVAL_V3:
        *out = AC_INFO_RETRIEVAL_V3;       *out_len = sizeof(AC_INFO_RETRIEVAL_V3);       break;
    case MAP_AC_GPRS_LOCATION_UPDATE_V3:
        *out = AC_GPRS_LOC_UPDATE_V3;      *out_len = sizeof(AC_GPRS_LOC_UPDATE_V3);      break;
    case MAP_AC_SUBSCRIBER_DATA_MGMT_V3:
        *out = AC_SUBSCRIBER_DATA_MGMT_V3; *out_len = sizeof(AC_SUBSCRIBER_DATA_MGMT_V3); break;
    case MAP_AC_GPRS_LOCATION_CANCEL_V3:
        *out = AC_GPRS_LOC_CANCEL_V3;      *out_len = sizeof(AC_GPRS_LOC_CANCEL_V3);      break;
    case MAP_AC_MS_PURGING_V3:
        *out = AC_MS_PURGING_V3;           *out_len = sizeof(AC_MS_PURGING_V3);           break;
    default: return -1;
    }
    return 0;
}

/* The dialogue-as-id direct-reference (TC-DialogueAsId) is itself an OID:
 *   0.0.17.773.1.1.1  => BER: 00 11 86 05 01 01 01
 * Stored as the EXTERNAL.direct-reference. */
static const uint8_t DIALOGUE_AS_ID[] = { 0x00,0x11,0x86,0x05,0x01,0x01,0x01 };

static int enc_aaXX(uint8_t apdu_tag, map_app_ctx_t ac,
                    uint8_t *out, size_t out_cap)
{
    const uint8_t *ac_oid;
    size_t ac_len;
    if (oid_for_ac(ac, &ac_oid, &ac_len) < 0) return -1;

    /* AARQ/AARE body:
     *   [0] IMPLICIT protocol-version: { version1 (0) }   -> 80 02 07 80
     *   [1] EXPLICIT application-context-name OID         -> A1 <len> 06 <len> <oid bytes>
     */
    uint8_t apdu[64];
    size_t  apo = 0;
    /* protocol-version BIT STRING { version1(0) } */
    static const uint8_t pv[] = { 0x07, 0x80 };
    if (ber_enc_tlv(apdu, sizeof(apdu), &apo, 0x80, pv, sizeof(pv)) < 0) return -1;

    uint8_t ac_tlv[32];
    size_t  at = 0;
    if (ber_enc_tlv(ac_tlv, sizeof(ac_tlv), &at, 0x06 /* OID */,
                    ac_oid, ac_len) < 0) return -1;
    if (ber_enc_tlv(apdu, sizeof(apdu), &apo, 0xA1, ac_tlv, at) < 0) return -1;

    /* Wrap APDU in [APPLICATION 0] (AARQ) / [APPLICATION 1] (AARE). */
    uint8_t single_asn1[128];
    size_t  sa = 0;
    if (ber_enc_tlv(single_asn1, sizeof(single_asn1), &sa,
                    apdu_tag, apdu, apo) < 0) return -1;

    /* Wrap in [0] EXPLICIT single-ASN1-type. */
    uint8_t inside[128];
    size_t ii = 0;
    if (ber_enc_tlv(inside, sizeof(inside), &ii, 0xA0 /* [0] */,
                    single_asn1, sa) < 0) return -1;

    /* Prepend direct-reference OID inside EXTERNAL. */
    uint8_t ext[160];
    size_t  ei = 0;
    if (ber_enc_tlv(ext, sizeof(ext), &ei, 0x06 /* OID */,
                    DIALOGUE_AS_ID, sizeof(DIALOGUE_AS_ID)) < 0) return -1;
    if (ei + ii > sizeof(ext)) return -1;
    memcpy(ext + ei, inside, ii);
    ei += ii;

    /* Outer EXTERNAL [UNIVERSAL 8] IMPLICIT SEQUENCE -> tag 0x28. */
    size_t off = 0;
    if (ber_enc_tlv(out, out_cap, &off, 0x28, ext, ei) < 0) return -1;
    return (int)off;
}

int map_encode_aarq(map_app_ctx_t ac, uint8_t *out, size_t out_cap)
{
    return enc_aaXX(0x60 /* [APPLICATION 0] AARQ */, ac, out, out_cap);
}

int map_encode_aare(map_app_ctx_t ac, uint8_t *out, size_t out_cap)
{
    return enc_aaXX(0x61 /* [APPLICATION 1] AARE */, ac, out, out_cap);
}

int map_decode_aarq_ac(const uint8_t *p, size_t n, map_app_ctx_t *out)
{
    if (!p || !out) return -1;
    /* Find the AC OID inside the dialogue blob. */
    for (size_t i = 0; i + 8 < n; i++) {
        if (p[i] == 0xA1 && p[i + 2] == 0x06) {
            const uint8_t *oid = p + i + 4;
            size_t oid_len = p[i + 3];
            if (i + 4 + oid_len > n) continue;
            if (oid_len == sizeof(AC_INFO_RETRIEVAL_V3) &&
                !memcmp(oid, AC_INFO_RETRIEVAL_V3, oid_len)) {
                *out = MAP_AC_INFO_RETRIEVAL_V3; return 0;
            }
            if (oid_len == sizeof(AC_GPRS_LOC_UPDATE_V3) &&
                !memcmp(oid, AC_GPRS_LOC_UPDATE_V3, oid_len)) {
                *out = MAP_AC_GPRS_LOCATION_UPDATE_V3; return 0;
            }
            if (oid_len == sizeof(AC_SUBSCRIBER_DATA_MGMT_V3) &&
                !memcmp(oid, AC_SUBSCRIBER_DATA_MGMT_V3, oid_len)) {
                *out = MAP_AC_SUBSCRIBER_DATA_MGMT_V3; return 0;
            }
            if (oid_len == sizeof(AC_GPRS_LOC_CANCEL_V3) &&
                !memcmp(oid, AC_GPRS_LOC_CANCEL_V3, oid_len)) {
                *out = MAP_AC_GPRS_LOCATION_CANCEL_V3; return 0;
            }
            if (oid_len == sizeof(AC_MS_PURGING_V3) &&
                !memcmp(oid, AC_MS_PURGING_V3, oid_len)) {
                *out = MAP_AC_MS_PURGING_V3; return 0;
            }
        }
    }
    return -1;
}
