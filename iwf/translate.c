#include "translate.h"
#include "runtime.h"
#include "gtpv1.h"
#include "gtpv2.h"
#include "logging.h"
#include "session.h"

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

/* ------------------------------------------------------------------- */
/* helpers                                                             */
/* ------------------------------------------------------------------- */

static const char *v1_msg_str(uint8_t t)
{
    switch (t) {
    case GTPV1_CREATE_PDP_CONTEXT_REQUEST:  return "Create-PDP-Req";
    case GTPV1_CREATE_PDP_CONTEXT_RESPONSE: return "Create-PDP-Resp";
    case GTPV1_UPDATE_PDP_CONTEXT_REQUEST:  return "Update-PDP-Req";
    case GTPV1_UPDATE_PDP_CONTEXT_RESPONSE: return "Update-PDP-Resp";
    case GTPV1_DELETE_PDP_CONTEXT_REQUEST:  return "Delete-PDP-Req";
    case GTPV1_DELETE_PDP_CONTEXT_RESPONSE: return "Delete-PDP-Resp";
    case GTPV1_SGSN_CONTEXT_REQUEST:         return "SGSN-Ctx-Req";
    case GTPV1_SGSN_CONTEXT_RESPONSE:       return "SGSN-Ctx-Resp";
    case GTPV1_ECHO_REQUEST:                return "Echo-Req";
    case GTPV1_ECHO_RESPONSE:               return "Echo-Resp";
    default:                                return "?";
    }
}

/* Forward decl — used both for spontaneous activation MBReq after CSResp and
 * for the Update-PDP-Context-triggered MBReq path. */
static int send_modify_bearer_req(iwf_runtime_t *rt, sess_t *s, uint8_t ebi);

static const char *v2_msg_str(uint8_t t)
{
    switch (t) {
    case GTPV2_CREATE_SESSION_REQUEST:  return "Create-Session-Req";
    case GTPV2_CREATE_SESSION_RESPONSE: return "Create-Session-Resp";
    case GTPV2_MODIFY_BEARER_REQUEST:   return "Modify-Bearer-Req";
    case GTPV2_MODIFY_BEARER_RESPONSE:  return "Modify-Bearer-Resp";
    case GTPV2_DELETE_SESSION_REQUEST:  return "Delete-Session-Req";
    case GTPV2_DELETE_SESSION_RESPONSE: return "Delete-Session-Resp";
    case GTPV2_CONTEXT_REQUEST:         return "Context-Req";
    case GTPV2_CONTEXT_RESPONSE:        return "Context-Resp";
    case GTPV2_ECHO_REQUEST:            return "Echo-Req";
    case GTPV2_ECHO_RESPONSE:           return "Echo-Resp";
    default:                            return "?";
    }
}

/* Best-effort mapping of 3G QoS Profile (TS 24.008 §10.5.6.5) -> QCI/ARP/AMBR.
 *
 * The 3G QoS Profile is a complex octet structure carrying traffic class,
 * delivery order, peak/mean bitrate, etc. A robust IWF would decode each
 * field; here we set a conservative best-effort default and let the SGW-C /
 * PCF policy refine it. Operators can extend this with explicit mappings
 * (e.g. Conversational+Speech -> QCI 1).
 */
static void map_qos_to_qci_ambr(const uint8_t *qos, size_t len,
                                uint8_t *qci, uint8_t *pl, uint8_t *pci, uint8_t *pvi,
                                uint64_t *mbr_ul, uint64_t *mbr_dl,
                                uint64_t *gbr_ul, uint64_t *gbr_dl,
                                uint32_t *ambr_ul_kbps, uint32_t *ambr_dl_kbps)
{
    *qci = IWF_DEFAULT_QCI;
    *pl  = IWF_DEFAULT_ARP_PL;
    *pci = IWF_DEFAULT_ARP_PCI;
    *pvi = IWF_DEFAULT_ARP_PVI;
    *mbr_ul = *mbr_dl = 0;
    *gbr_ul = *gbr_dl = 0;
    *ambr_ul_kbps = 1000000;       /* 1 Gbps in kbps */
    *ambr_dl_kbps = 1000000;

    if (!qos || len < 3) return;

    /* Octet 1 = Allocation/Retention Priority (1..3, lower is higher prio). */
    uint8_t arp = qos[0] & 0x07;
    if (arp >= 1 && arp <= 3) {
        *pl  = (arp == 1) ? 5 : (arp == 2) ? 8 : 12;
        *pci = (arp == 1) ? 1 : 0;
    }

    /* Traffic class lives at octet 4 (index 3) bits 5..7. */
    if (len >= 4) {
        uint8_t tc = (qos[3] >> 5) & 0x07;
        switch (tc) {
        case 1: *qci = 1;  break;   /* Conversational  -> QCI 1 (GBR voice) */
        case 2: *qci = 2;  break;   /* Streaming       -> QCI 2 */
        case 3: *qci = 8;  break;   /* Interactive     -> QCI 8 */
        case 4: *qci = 9;  break;   /* Background      -> QCI 9 */
        default: *qci = IWF_DEFAULT_QCI; break;
        }
    }
}

static void log_msg(const char *dir, const iwf_msg_t *m,
                    const char *imsi, const char *apn)
{
    const char *name = (m->version == 1) ? v1_msg_str(m->msg_type)
                                         : v2_msg_str(m->msg_type);
    LOGI("translate",
         "%s v%u %s teid=0x%08x seq=%u imsi=%s apn=%s ies=%zu",
         dir, m->version, name, m->teid, m->seq,
         imsi[0] ? imsi : "-", apn[0] ? apn : "-", m->n_ies);
}

/* 0 ok, -1 missing IMSI IE, -2 BCD decode failure */
static int build_imsi_from_v1(const iwf_msg_t *v1, char *imsi_out)
{
    if (!v1 || !imsi_out)
        return -1;
    imsi_out[0] = '\0';
    const iwf_ie_t *ie = gtpv1_find_ie(v1, GTPV1_IE_IMSI);
    if (!ie)
        return -1;
    if (gtpv1_decode_imsi(ie, imsi_out, IWF_IMSI_MAX) != 0)
        return -2;
    return 0;
}

/* ------------------------------------------------------------------- */
/* GTPv2 Context Req/Resp <-> GTPv1 SGSN Context Req/Resp (Gn)         */
/* ------------------------------------------------------------------- */

typedef enum {
    CTX_FLOW_MME_TO_GN,   /* GTPv2 CR from MME; await GTPv1 SGSN Ctx Resp from [sgsn] */
    CTX_FLOW_GN_TO_MME,   /* GTPv1 SGSN Ctx Req from osmo; await GTPv2 Context Resp */
} ctx_pend_flow_t;

typedef struct ctx_pend_s {
    ctx_pend_flow_t flow;
    int             gn_seq_key;   /* HASH gn: SCR seq echoed in SGSN Ctx Resp (MME-init) */
    int             v2_seq_key;   /* HASH v2: our outbound CR seq (Gn-init) */

    UT_hash_handle  hh_gn;
    UT_hash_handle  hh_v2;
    int             in_gn_hash;
    int             in_v2_hash;

    /* MME-init: UDP source where v2 Context Request arrived. */
    iwf_endpoint_t  mme_sa;
    /* Gn-init (osmo SCR): UDP source — SGSN Context Response must return here. */
    iwf_endpoint_t  gn_peer_sa;

    uint32_t        mme_teid;
    uint32_t        mme_seq24;
    int             mme_t_present;

    /* Gn-init: wire fields from SCR to echo on SGSN Context Response header. */
    uint16_t        gn_req_seq16;
    uint32_t        gn_req_hdr_teid;

    uint32_t        sgsn_src_teid;
    uint32_t        sgsn_src_ipv4;

    char            req_imsi[IWF_IMSI_MAX];
} ctx_pend_t;

static ctx_pend_t *g_ctx_pend_gn = NULL;
static ctx_pend_t *g_ctx_pend_v2 = NULL;

static void ctx_pend_detach(ctx_pend_t *p)
{
    if (!p)
        return;
    if (p->in_gn_hash) {
        HASH_DELETE_HH(hh_gn, g_ctx_pend_gn, &(p)->hh_gn);
        p->in_gn_hash = 0;
    }
    if (p->in_v2_hash) {
        HASH_DELETE_HH(hh_v2, g_ctx_pend_v2, &(p)->hh_v2);
        p->in_v2_hash = 0;
    }
}

static void ctx_pend_free(ctx_pend_t *p)
{
    if (!p)
        return;
    ctx_pend_detach(p);
    free(p);
}

typedef struct parsed_pdp130_s {
    uint8_t  nsapi;
    uint32_t ul_teid_cp;
    uint32_t ul_teid_data;
    uint32_t ggsn_cp_ipv4;
    uint32_t ggsn_up_ipv4;
    uint32_t ue_ipv4;
    uint8_t  qos_neg[64];
    size_t   qos_neg_len;
    char     apn[IWF_APN_MAX];
    int      ok;
} parsed_pdp130_t;

static int v2_teid_present_in_hdr(const iwf_msg_t *m)
{
    if (!m->raw || m->raw_len < 1)
        return 1;
    return (((m->raw[0] >> 3) & 1u) != 0) ? 1 : 0;
}

static const iwf_ie_t *ctx_find_sender_fteid_v2(const iwf_msg_t *m)
{
    const iwf_ie_t *chosen = NULL;
    for (size_t i = 0; i < m->n_ies; i++) {
        if (m->ies[i].type != GTPV2_IE_FTEID)
            continue;
        uint8_t iface;
        uint32_t teid, ipv4;
        if (gtpv2_decode_fteid(&m->ies[i], &iface, &teid, &ipv4))
            continue;
        if (iface == FTEID_IFACE_S11_MME_GTPC ||
            iface == FTEID_IFACE_S11_S4_SGW_GTPC ||
            iface == FTEID_IFACE_S4_SGSN_GTPC)
            return &m->ies[i];
        if (!chosen)
            chosen = &m->ies[i];
    }
    return chosen;
}

static void ctx_synthetic_rai(const char *imsi, uint8_t rai6[6])
{
    uint16_t mcc = 0, mnc = 0;
    if (strlen(imsi) >= 5) {
        char mc[4] = { imsi[0], imsi[1], imsi[2], 0 };
        char mn[4] = { imsi[3], imsi[4], 0, 0 };
        mcc = (uint16_t)atoi(mc);
        mnc = (uint16_t)atoi(mn);
    }
    /* PLMN via same BCD packing as Serving Network encoder (gtpv2.c). */
    uint8_t plmn[3];
    uint8_t m1 = (uint8_t)((mcc / 100) % 10), m2 = (uint8_t)((mcc / 10) % 10),
            m3 = (uint8_t)(mcc % 10);
    uint8_t n1, n2, n3;
    if (mnc >= 100) {
        n1 = (uint8_t)((mnc / 100) % 10);
        n2 = (uint8_t)((mnc / 10) % 10);
        n3 = (uint8_t)(mnc % 10);
    } else {
        n1 = 0x0f;
        n2 = (uint8_t)((mnc / 10) % 10);
        n3 = (uint8_t)(mnc % 10);
    }
    plmn[0] = (uint8_t)((m2 << 4) | m1);
    plmn[1] = (uint8_t)((n1 << 4) | m3);
    plmn[2] = (uint8_t)((n3 << 4) | n2);
    memcpy(rai6, plmn, 3);
    rai6[3] = 0;
    rai6[4] = 0;
    rai6[5] = 0;
}

static int ctx_decode_uli_rai(const iwf_ie_t *ie, uint8_t rai6[6])
{
    if (!ie || ie->length < 8 || !rai6)
        return -1;
    if ((ie->value[0] & 0x04u) == 0) /* RAI flag */
        return -1;
    memcpy(rai6, ie->value + 1, 6);
    return 0;
}

/* Map supported GTPv1 MM Context (129) UMTS+quints variants to MM Context IE 104. */
static int mm_v129_to_v104(const uint8_t *s, uint16_t slen, uint8_t *d, size_t dc,
                           size_t *out_len)
{
    if (!s || slen < 36 || !d || dc < 64)
        return -1;
    uint8_t sec_mode = (uint8_t)((s[1] >> 4) & 0x0f); /* Fig 41/42A oct5 */
    if (sec_mode != 0 && sec_mode != 2) /* GSM-only / EPS not translated here */
        return -1;

    uint8_t nv = (uint8_t)((s[1] >> 1) & 0x07);
    uint16_t qlen = iwf_be16(s + 34);
    if ((uint32_t)36 + qlen > slen || (size_t)(3 + 32 + qlen + 2) > dc)
        return -1;

    size_t w = 0;
    d[w++] = (uint8_t)(((uint8_t)((s[1] >> 4) & 0x0fu) << 4) |
                       ((s[0] & 0x0fu) & 0x0fu));            /* §8.38-2 oct5-ish */
    d[w++] = (uint8_t)((nv << 5) |
                       ((((s[0] >> 7) & 1u) << 3) |
                        (((s[0] >> 6) & 1u) << 2)));          /* GUPII / UGIPAI */
    d[w++] = (uint8_t)((((s[0] >> 5) & 0x07u) << 3) |
                       ((s[1] & 0x07u) & 0x07u));           /* int alg bits + cipher */
    memcpy(d + w, s + 2, 32);                                 /* CK+IK */
    w += 32;
    memcpy(d + w, s + 36, qlen);
    w += qlen;
    if (slen >= 36 + qlen + 2) {
        memcpy(d + w, s + 36 + qlen, 2);                       /* DRX if present */
        w += 2;
    }
    *out_len = w;
    return 0;
}

/* Inverse mm_v129_to_v104 — no DRX round-trip yet (Gn→MME path). */
static int mm_v104_to_v129(const uint8_t *v104, size_t v104_len,
                           uint8_t *u129, size_t uc, size_t *out_len)
{
    if (!v104 || v104_len < 37 || !u129 || !out_len || uc < 64)
        return -1;

    uint8_t V0 = v104[0], V1 = v104[1], V2 = v104[2];
    uint8_t sec_mode = (uint8_t)((V0 >> 4) & 0x0fu);
    if (sec_mode != 0 && sec_mode != 2)
        return -1;

    uint8_t nv = (uint8_t)(((uint32_t)V1 >> 5) & 7u);
    uint8_t low3 = (uint8_t)(V2 & 7u);
    uint8_t n0 = (uint8_t)(nv & 1u), n1 = (uint8_t)((nv >> 1) & 1u),
            n2 = (uint8_t)((nv >> 2) & 1u);
    /* s1 positions 3..1 must match nv; positions 2..0 must equal low3. */
    if (((low3 >> 1) & 3u) != (nv & 3u))
        return -1;

    uint8_t s0 = (uint8_t)((V0 & 0x0fu) |
                           (((V1 >> 3) & 1u) << 7) |
                           (((V1 >> 2) & 1u) << 6) |
                           (((V2 >> 3) & 7u) << 5));
    uint8_t s1 = (uint8_t)((sec_mode << 4) | (uint8_t)(n2 << 3) |
                           (uint8_t)(n1 << 2) | (uint8_t)(n0 << 1) |
                           (uint8_t)(low3 & 1u));

    uint16_t qlen = (uint16_t)(v104_len - 35);
    size_t total_u = (size_t)36 + (size_t)qlen;
    if ((size_t)35 + (size_t)qlen != v104_len || total_u > uc)
        return -1;

    u129[0] = s0;
    u129[1] = s1;
    memcpy(u129 + 2, v104 + 3, 32);
    iwf_put_be16(u129 + 34, qlen);
    memcpy(u129 + 36, v104 + 35, qlen);
    *out_len = total_u;
    return 0;
}

static int decode_apn_from_labels(const uint8_t *buf, uint8_t apn_len,
                                  char *apn, size_t apn_cap)
{
    size_t pos = 0;
    size_t ai = 0;
    while (pos < apn_len) {
        uint8_t lab = buf[pos++];
        if (lab == 0)
            break;
        if ((size_t)pos + lab > apn_len)
            return -1;
        if (ai > 0 && ai + 1 < apn_cap)
            apn[ai++] = '.';
        for (uint8_t j = 0; j < lab && ai + 1 < apn_cap; j++)
            apn[ai++] = (char)buf[pos++];
        if (ai >= apn_cap)
            return -1;
        apn[ai] = '\0';
    }
    return ai > 0 ? 0 : -1;
}

static int parse_gtpu_pdp130(const iwf_ie_t *ie, parsed_pdp130_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!ie || ie->length < 40)
        return -1;
    const uint8_t *p = ie->value;
    size_t len = ie->length;
    size_t i = 0;
    out->nsapi = (uint8_t)(p[i++] & 0x0fu);
    i++; /* SAPI */
    uint8_t qs = p[i++];
    if (i + qs > len)
        return -1;
    i += qs;
    uint8_t qr = p[i++];
    if (i + qr > len)
        return -1;
    i += qr;
    uint8_t qn = p[i++];
    if (i + qn > len)
        return -1;
    size_t qos_copy = qn > sizeof(out->qos_neg) ? sizeof(out->qos_neg) : (size_t)qn;
    memcpy(out->qos_neg, p + i, qos_copy);
    out->qos_neg_len = qos_copy;
    i += qn;
    if (i + 10 > len)
        return -1;
    /* SND,SNU,N-PDU nums */
    i += 10;
    out->ul_teid_cp = iwf_be32(p + i);
    i += 4;
    out->ul_teid_data = iwf_be32(p + i);
    i += 4;
    i++; /* PDP ctxt id */
    i++; /* spare + PDP type org */
    uint8_t pdp_type_no = p[i++];
    uint8_t pd_len = p[i++];
    if (i + pd_len > len)
        return -1;
    if (pd_len >= 4 && (pdp_type_no == 0x21 || pdp_type_no == 0x57))
        out->ue_ipv4 = iwf_be32(p + i); /* simplified */
    i += pd_len;

    uint8_t gcp_len = p[i++];
    if (i + gcp_len > len)
        return -1;
    if (gcp_len >= 4)
        out->ggsn_cp_ipv4 = iwf_be32(p + i);
    i += gcp_len;

    uint8_t gup_len = p[i++];
    if (i + gup_len > len)
        return -1;
    if (gup_len >= 4)
        out->ggsn_up_ipv4 = iwf_be32(p + i);
    i += gup_len;

    uint8_t apnlen = p[i++];
    if (i + apnlen > len)
        return -1;
    decode_apn_from_labels(p + i, apnlen, out->apn, sizeof(out->apn));
    out->ok = 1;
    return 0;
}

static size_t encode_apn_dotted_wire(const char *dot_apn,
                                    uint8_t *wire, size_t wcap)
{
    size_t wi = 0;
    const char *p = dot_apn;
    if (!p || !*p || wcap < 3)
        return 0;

    while (*p) {
        const char *d = strchr(p, '.');
        size_t lab = d ? (size_t)(d - p) : strlen(p);
        if (lab == 0 || lab > 63 || wi + 1 + lab >= wcap)
            return 0;
        wire[wi++] = (uint8_t)lab;
        memcpy(wire + wi, p, lab);
        wi += lab;
        if (!d)
            break;
        p = d + 1;
    }
    if (wi >= wcap)
        return 0;
    wire[wi++] = 0;
    return wi;
}

static int encode_gtpu_pdp130_from_parse(const parsed_pdp130_t *p,
                                         uint8_t *buf, size_t cap,
                                         size_t *out_len)
{
    uint8_t apn_wire[192];
    const char *apn_src = (p->apn[0] ? p->apn : "internet");

    uint8_t qn = (p->qos_neg_len > (size_t)255) ? (uint8_t)255 : (uint8_t)p->qos_neg_len;

    size_t apnw = encode_apn_dotted_wire(apn_src, apn_wire, sizeof(apn_wire));
    if (apnw < 2 || apnw > sizeof(apn_wire))
        return -1;

    size_t est = (size_t)1 + (size_t)1 + /* nsapi+sapi placeholder */
                  (size_t)1 + (size_t)1 + /* qs/qr skips */
                  (size_t)1 + qn +
                  (size_t)10 +            /*SND…*/
                  (size_t)4 + (size_t)4 + /* ctrl + user teid */
                  (size_t)1 + (size_t)1 + /* pdp ctxt id spare */
                  (size_t)1 + (size_t)1 + /* type + pd len */
                  (size_t)4 +             /* ue ipv4 */
                  (size_t)1 + (size_t)4 + /* gsn cp len+ */
                  (size_t)1 + (size_t)4 +
                  apnw;
    if (est > cap)
        return -1;

    size_t i = 0;
    buf[i++] = (uint8_t)(p->nsapi & 0x0fu);
    buf[i++] = 0; /* spare SAPI / MS not reachable */
    buf[i++] = 0; /* requested QoS sub length */
    buf[i++] = 0; /* req QoS profile len */
    buf[i++] = qn;
    if (qn && i + qn <= cap)
        memcpy(buf + i, p->qos_neg, qn);
    i += qn;

    memset(buf + i, 0, 10); /*SND/SNU/N-PDU placeholders */
    i += 10;

    iwf_put_be32(buf + i, p->ul_teid_cp);
    i += 4;
    iwf_put_be32(buf + i, p->ul_teid_data);
    i += 4;

    buf[i++] = 1;    /* PDP context id */
    buf[i++] = 0xf1; /* PDP type org / spare like osmo payloads */
    buf[i++] = 0x21; /* PDP type IPv4 */
    buf[i++] = 4;
    iwf_put_be32(buf + i, p->ue_ipv4);
    i += 4;

    buf[i++] = 4;
    iwf_put_be32(buf + i, p->ggsn_cp_ipv4);
    i += 4;

    buf[i++] = 4;
    iwf_put_be32(buf + i, p->ggsn_up_ipv4);
    i += 4;

    if (i + apnw > cap)
        return -1;
    memcpy(buf + i, apn_wire, apnw);
    i += apnw;

    *out_len = i;
    return 0;
}

static int unpack_v2_pdn_for_reverse(const iwf_msg_t *v2rsp,
                                  parsed_pdp130_t *pdp_out)
{
    memset(pdp_out, 0, sizeof(*pdp_out));
    const iwf_ie_t *pdn = gtpv2_find_ie(v2rsp, GTPV2_IE_PDN_CONNECTION, 0);
    if (!pdn)
        return -1;
    iwf_ie_t inn[IWF_MAX_IES];
    size_t nin = 0;
    if (gtpv2_parse_grouped(pdn, inn, IWF_MAX_IES, &nin) != 0)
        return -1;

    uint8_t ebi = 5;

    for (size_t i = 0; i < nin; i++) {
        if (inn[i].type == GTPV2_IE_APN && inn[i].length)
            decode_apn_from_labels(inn[i].value, (uint8_t)inn[i].length,
                                   pdp_out->apn, sizeof(pdp_out->apn));
        else if (inn[i].type == GTPV2_IE_IP_ADDRESS &&
                 inn[i].length >= (uint16_t)sizeof(uint32_t))
            pdp_out->ue_ipv4 = iwf_be32(inn[i].value);
        else if (inn[i].type == GTPV2_IE_EBI && inn[i].length >= 1) {
            uint8_t ee = ebi;
            if (gtpv2_decode_ebi(&inn[i], &ee) == 0 && ee <= 15u)
                ebi = ee;
        } else if (inn[i].type == GTPV2_IE_BEARER_CONTEXT &&
                   inn[i].instance == 0) {
            iwf_ie_t bn[IWF_MAX_IES];
            size_t nbn = 0;
            if (gtpv2_parse_grouped(&inn[i], bn, IWF_MAX_IES, &nbn) != 0)
                continue;
            for (size_t k = 0; k < nbn; k++) {
                uint8_t ifc;
                uint32_t tid, ipa;
                if (bn[k].type == GTPV2_IE_FTEID &&
                    !gtpv2_decode_fteid(&bn[k], &ifc, &tid, &ipa) && ipa) {
                    if (ifc == FTEID_IFACE_S5S8_PGW_GTPC && tid && ipa) {
                        pdp_out->ul_teid_cp = tid;
                        pdp_out->ggsn_cp_ipv4 = ipa;
                    } else if ((ifc == FTEID_IFACE_S5S8_PGW_GTPU ||
                                ifc == FTEID_IFACE_S5S8_SGW_GTPU ||
                                ifc == FTEID_IFACE_S4_SGW_GTPU ||
                                ifc == FTEID_IFACE_S1U_SGW_GTPU) &&
                               tid && ipa && !pdp_out->ul_teid_data) {
                        pdp_out->ul_teid_data = tid;
                        pdp_out->ggsn_up_ipv4 = ipa;
                    }
                } else if (bn[k].type == GTPV2_IE_BEARER_QOS &&
                           bn[k].length &&
                           bn[k].length <= sizeof(pdp_out->qos_neg) &&
                           pdp_out->qos_neg_len == 0) {
                    memcpy(pdp_out->qos_neg, bn[k].value, bn[k].length);
                    pdp_out->qos_neg_len = bn[k].length;
                }
            }
        } else if (inn[i].type == GTPV2_IE_PAA &&
                   inn[i].length >= (uint16_t)5 &&
                   inn[i].value[0] == GTPV2_PDN_TYPE_IPV4 && !pdp_out->ue_ipv4) {
            pdp_out->ue_ipv4 = iwf_be32(inn[i].value + 1);
        }
    }

    pdp_out->nsapi = ebi;

    if (pdp_out->qos_neg_len == 0) {
        pdp_out->qos_neg[0] = 0;
        pdp_out->qos_neg_len = (size_t)1;
    }
    if (!pdp_out->ggsn_cp_ipv4 || !pdp_out->ul_teid_cp ||
        !pdp_out->ggsn_up_ipv4 || !pdp_out->ul_teid_data ||
        !pdp_out->ue_ipv4 || !pdp_out->apn[0])
        return -1;
    pdp_out->ok = 1;
    return 0;
}

static uint8_t map_gtpu_v2_cause_to_v1_basic(uint8_t c)
{
    if (c == GTPV2_CAUSE_REQUEST_ACCEPTED)
        return GTPV1_CAUSE_REQUEST_ACCEPTED;
    if (c == GTPV2_CAUSE_CONTEXT_NOT_FOUND)
        return GTPV1_CAUSE_NON_EXISTENT;
    return GTPV1_CAUSE_SYSTEM_FAILURE;
}

/* Map a GTPv2 cause (TS 29.274 §8.4) to a GTPv1 cause (TS 29.060 §7.7.1)
 * for Create / Modify / Update / Delete PDP Context Responses. We have only
 * a handful of GTPv1 causes available, so this is a many-to-few mapping; we
 * default to "No resources available" (199) which is what osmo-sgsn already
 * surfaces as a generic attach failure. */
static uint8_t map_gtpv2_cause_to_v1_pdp_resp(uint8_t c)
{
    switch (c) {
    case 16:  return GTPV1_CAUSE_REQUEST_ACCEPTED;   /* Request accepted    */
    case 64:  return GTPV1_CAUSE_NON_EXISTENT;       /* Context Not Found   */
    case 65:                                          /* Invalid Message Fmt */
    case 67:                                          /* Invalid length      */
    case 69:                                          /* Mandatory IE incorr.*/
    case 70:                                          /* Mandatory IE missing*/
    case 103: return GTPV1_CAUSE_INVALID_MESSAGE;    /* Conditional IE miss.*/
    case 72:  return GTPV1_CAUSE_SYSTEM_FAILURE;     /* System failure      */
    default:  return GTPV1_CAUSE_NO_RESOURCES;
    }
}

static int sin_addr_matches_cfg(const struct sockaddr_in *peer,
                                const struct sockaddr_in *expect)
{
    if (!peer || !expect || peer->sin_family != AF_INET ||
        expect->sin_family != AF_INET)
        return 0;
    if (expect->sin_addr.s_addr == htonl(INADDR_ANY))
        return 1;
    return peer->sin_addr.s_addr == expect->sin_addr.s_addr;
}

static int send_v1_sgsn_ctx_resp_quick(iwf_runtime_t *rt,
                                     const iwf_endpoint_t *to,
                                     uint32_t req_hdr_teid, uint16_t req_seq16,
                                     uint8_t v1cause, const char *imsi_digits)
{
    uint8_t out[IWF_MAX_PKT];
    gtpv1_enc_t e;
    gtpv1_enc_init(&e, out, sizeof(out));
    if (gtpv1_enc_begin(&e, GTPV1_SGSN_CONTEXT_RESPONSE,
                        req_hdr_teid, req_seq16) != 0)
        return -1;
    if (gtpv1_enc_tv_u8(&e, GTPV1_IE_CAUSE, v1cause) != 0)
        return -1;
    if (imsi_digits && imsi_digits[0])
        gtpv1_enc_imsi_tv(&e, imsi_digits);
    int tot = gtpv1_enc_finish(&e);
    if (tot <= 0)
        return -1;
    return iwf_send_v1(rt, to, out, (size_t)tot);
}

static int pick_mm104_mm_from_ctx_resp(const iwf_msg_t *v2,
                                       uint8_t **mm_wire, uint16_t *mm_len_out)
{
    const iwf_ie_t *mm =
        gtpv2_find_ie(v2, GTPV2_IE_MM_CONTEXT_UMTS_KEY_QUINT, 0);
    if (!mm || mm->length == 0)
        return -1;
    *mm_wire = (uint8_t *)mm->value;
    *mm_len_out = mm->length;
    return 0;
}

static void pick_mme_c_from_ctx_resp(const iwf_msg_t *v2,
                                    const iwf_endpoint_t *from_mme,
                                    uint32_t *out_teid, uint32_t *out_ipv4)
{
    *out_teid = 0;
    *out_ipv4 = 0;

    const iwf_ie_t *sf = ctx_find_sender_fteid_v2(v2);
    if (sf) {
        uint8_t iface;
        uint32_t tid, ipa;
        if (!gtpv2_decode_fteid(sf, &iface, &tid, &ipa) && tid &&
            ipa &&
            (iface == FTEID_IFACE_S11_MME_GTPC ||
             iface == FTEID_IFACE_S11_S4_SGW_GTPC)) {
            *out_teid = tid;
            *out_ipv4 = ipa;
            return;
        }
    }
    if (v2_teid_present_in_hdr(v2) && v2->teid && from_mme &&
        from_mme->addr.sin_family == AF_INET) {
        *out_teid = v2->teid;
        *out_ipv4 = ntohl(from_mme->addr.sin_addr.s_addr);
    }
}

static uint8_t map_gtpu_v1_cause_to_v2(uint8_t c)
{
    if (c == GTPV1_CAUSE_REQUEST_ACCEPTED)
        return GTPV2_CAUSE_REQUEST_ACCEPTED;
    /* Best-effort: non-existent subscriber / IMEI IMSI unknown */
    if (c == 192 || c == GTPV1_CAUSE_NON_EXISTENT)
        return GTPV2_CAUSE_CONTEXT_NOT_FOUND;
    return GTPV2_CAUSE_SYSTEM_FAILURE;
}

static int encode_ctx_resp_accepted(const ctx_pend_t *pend,
                                    const uint8_t *mm_buf, size_t mm_len,
                                    const parsed_pdp130_t *pdp,
                                    uint32_t sgsn_teid_cp,
                                    uint32_t sgsn_cp_ipv4,
                                    const char *rsp_imsi,
                                    uint8_t *outbuf, size_t outcap)
{
    gtpv2_enc_t e;
    gtpv2_enc_init(&e, outbuf, outcap);
    gtpv2_enc_begin_tf(&e, GTPV2_CONTEXT_RESPONSE, pend->mme_teid, pend->mme_seq24,
                       pend->mme_t_present);
    if (gtpv2_enc_cause(&e, GTPV2_CAUSE_REQUEST_ACCEPTED) != 0)
        return -1;
    if (rsp_imsi && rsp_imsi[0])
        gtpv2_enc_imsi_bcd(&e, rsp_imsi);
    gtpv2_enc_rat_type(&e, GTPV2_RAT_GERAN);
    if (gtpv2_enc_tlv(&e, GTPV2_IE_MM_CONTEXT_UMTS_KEY_QUINT, 0,
                      mm_buf, (uint16_t)mm_len) != 0)
        return -1;
    if (sgsn_teid_cp && sgsn_cp_ipv4)
        gtpv2_enc_fteid_ipv4(&e, 0, FTEID_IFACE_S4_SGSN_GTPC, sgsn_teid_cp,
                             sgsn_cp_ipv4);

    uint8_t qci, pl, pci, pvi;
    uint64_t mbr_ul, mbr_dl, gbr_ul, gbr_dl;
    uint32_t ambr_ul, ambr_dl;
    map_qos_to_qci_ambr(pdp->qos_neg, pdp->qos_neg_len,
                        &qci, &pl, &pci, &pvi,
                        &mbr_ul, &mbr_dl, &gbr_ul, &gbr_dl,
                        &ambr_ul, &ambr_dl);

    size_t patch_pdn;
    if (gtpv2_enc_group_begin(&e, GTPV2_IE_PDN_CONNECTION, 0, &patch_pdn) != 0)
        return -1;
    if (pdp->apn[0])
        gtpv2_enc_apn(&e, pdp->apn);
    else
        LOGW("translate", "Context-Resp: empty APN in decoded PDP IE");
    gtpv2_enc_apn_restriction(&e, 0);
    gtpv2_enc_selection_mode(&e, 0);
    if (pdp->ue_ipv4)
        gtpv2_enc_ipv4_ip_address(&e, 0, htonl(pdp->ue_ipv4));
    uint8_t ebi = pdp->nsapi <= 15 ? pdp->nsapi : 5;
    gtpv2_enc_ebi(&e, 0, ebi);
    if (pdp->ggsn_cp_ipv4)
        gtpv2_enc_fteid_ipv4(&e, 0, FTEID_IFACE_S5S8_PGW_GTPC, pdp->ul_teid_cp,
                             pdp->ggsn_cp_ipv4);

    size_t patch_bc;
    if (gtpv2_enc_group_begin(&e, GTPV2_IE_BEARER_CONTEXT, 0, &patch_bc) != 0)
        return -1;
    gtpv2_enc_ebi(&e, 0, ebi);
    if (pdp->ggsn_up_ipv4 && pdp->ul_teid_data)
        gtpv2_enc_fteid_ipv4(&e, 1, FTEID_IFACE_S5S8_PGW_GTPU,
                             pdp->ul_teid_data, pdp->ggsn_up_ipv4);
    gtpv2_enc_bearer_qos(&e, pci, pl, pvi, qci,
                         mbr_ul, mbr_dl, gbr_ul, gbr_dl);
    gtpv2_enc_group_finish(&e, patch_bc);

    gtpv2_enc_ambr(&e, ambr_ul, ambr_dl);
    gtpv2_enc_group_finish(&e, patch_pdn);

    return gtpv2_enc_finish(&e);
}
static int encode_context_response_reject_only(const ctx_pend_t *pend,
                                               uint8_t v2cause,
                                               uint8_t *outbuf, size_t outcap)
{
    gtpv2_enc_t e;
    gtpv2_enc_init(&e, outbuf, outcap);
    gtpv2_enc_begin_tf(&e, GTPV2_CONTEXT_RESPONSE, pend->mme_teid, pend->mme_seq24,
                       pend->mme_t_present);
    if (gtpv2_enc_cause(&e, v2cause) != 0)
        return -1;
    return gtpv2_enc_finish(&e);
}

static int handle_gtpu_context_request(iwf_runtime_t *rt,
                                       const iwf_endpoint_t *from,
                                       const iwf_msg_t *v2)
{
    char imsi[IWF_IMSI_MAX] = {0};
    const iwf_ie_t *imsi_ie = gtpv2_find_ie(v2, GTPV2_IE_IMSI, 0);
    if (!imsi_ie || gtpv2_decode_imsi(imsi_ie, imsi, sizeof(imsi)) != 0) {
        LOGW("translate", "Context Request: missing/decoding IMSI — drop");
        return -1;
    }

    uint8_t rai6[6];
    const iwf_ie_t *uli = gtpv2_find_ie(v2, GTPV2_IE_ULI, 0);
    if (!(uli && ctx_decode_uli_rai(uli, rai6) == 0)) {
        /* RAI is mandatory on SGSN Context Request; derive PLMN+LAC+RAC from ULI
         * or synthesize from IMSI digits (same idea as synthetic_uli_no_rai). */
        ctx_synthetic_rai(imsi, rai6);
    }

    uint32_t new_ctl_teid = sess_new_teid();
    const iwf_ie_t *sf = ctx_find_sender_fteid_v2(v2);
    if (sf) {
        uint8_t iface;
        uint32_t teid, ipv4;
        if (!gtpv2_decode_fteid(sf, &iface, &teid, &ipv4) && teid)
            new_ctl_teid = teid;
    }

    rt->gn_seq++;
    uint16_t gseq16 = (uint16_t)((rt->gn_seq & 0xffffu) == 0u ? 1u : rt->gn_seq & 0xffffu);

    ctx_pend_t *pend = (ctx_pend_t *)calloc(1, sizeof(ctx_pend_t));
    if (!pend)
        return -1;
    pend->flow = CTX_FLOW_MME_TO_GN;
    pend->gn_seq_key = (int)(uint16_t)gseq16;
    pend->v2_seq_key = -1;
    pend->mme_sa = *from;
    pend->mme_teid = v2->teid;
    pend->mme_seq24 = v2->seq;
    pend->mme_t_present = v2_teid_present_in_hdr(v2);
    memcpy(pend->req_imsi, imsi, sizeof(pend->req_imsi) - 1);
    pend->req_imsi[sizeof(pend->req_imsi) - 1] = '\0';
    HASH_ADD(hh_gn, g_ctx_pend_gn, gn_seq_key, sizeof(int), pend);
    pend->in_gn_hash = 1;

    if (!rt->cfg.sgsn_ip[0] || strcmp(rt->cfg.sgsn_ip, "0.0.0.0") == 0) {
        LOGE("translate", "Context Request: configure [sgsn] ip for osmo-sgsn Gn");
        ctx_pend_free(pend);
        return -1;
    }

    uint8_t out[IWF_MAX_PKT];
    gtpv1_enc_t eb;
    gtpv1_enc_init(&eb, out, sizeof(out));
    if (gtpv1_enc_begin(&eb, GTPV1_SGSN_CONTEXT_REQUEST, 0u, gseq16) != 0) {
        ctx_pend_free(pend);
        return -1;
    }
    if (gtpv1_enc_imsi_tv(&eb, imsi) != 0 ||
        gtpv1_enc_rai_tv(&eb, rai6) != 0 ||
        gtpv1_enc_tv_u32(&eb, GTPV1_IE_TEID_CTRL_PLANE, new_ctl_teid) != 0 ||
        gtpv1_enc_gsn_addr_ipv4(&eb, ntohl(rt->local_ipv4_be)) != 0) {
        ctx_pend_free(pend);
        return -1;
    }

    const iwf_ie_t *ratie = gtpv2_find_ie(v2, GTPV2_IE_RAT_TYPE, 0);
    if (ratie && ratie->length >= 1)
        gtpv1_enc_tv_u8(&eb, GTPV1_IE_RAT_TYPE, ratie->value[0]);

    int tot = gtpv1_enc_finish(&eb);
    if (tot <= 0) {
        ctx_pend_free(pend);
        return -1;
    }

    iwf_endpoint_t sgsn;
    memset(&sgsn, 0, sizeof(sgsn));
    sgsn.addr = rt->sgsn_gtp_addr;
    sgsn.addrlen = sizeof(sgsn.addr);

    LOGI("translate", "Context-Req→Gn SGSN-Ctx-Req imsi=%s gn_seq=%u peer=%s:%u teid_cp=0x%08x",
         imsi, (unsigned)gseq16,
         inet_ntoa(sgsn.addr.sin_addr), ntohs(sgsn.addr.sin_port),
         new_ctl_teid);
    iwf_log_hex("translate", "SGSN-Ctx-Req", out, (size_t)tot);

    return iwf_send_v1(rt, &sgsn, out, (size_t)tot);
}

static int handle_v1_sgsn_context_resp(iwf_runtime_t *rt,
                                     const iwf_endpoint_t *from,
                                     const iwf_msg_t *v1rsp)
{
    (void)from;

    uint16_t wire_seq = (uint16_t)v1rsp->seq;
    int seq_k = (int)wire_seq;
    ctx_pend_t *pend = NULL;
    HASH_FIND(hh_gn, g_ctx_pend_gn, &seq_k, sizeof(int), pend);
    if (!pend || pend->flow != CTX_FLOW_MME_TO_GN || !pend->in_gn_hash) {
        LOGW("translate", "SGSN-Ctx-Resp seq=%u: no pending MME→Gn Context Req",
             (unsigned)wire_seq);
        return -1;
    }

    iwf_endpoint_t mme_sa = pend->mme_sa;

    char rsp_imsi[IWF_IMSI_MAX];
    rsp_imsi[0] = '\0';
    const iwf_ie_t *vim = gtpv1_find_ie(v1rsp, GTPV1_IE_IMSI);
    if (!vim || gtpv1_decode_imsi(vim, rsp_imsi, sizeof(rsp_imsi)) != 0) {
        memcpy(rsp_imsi, pend->req_imsi, sizeof(rsp_imsi) - 1);
        rsp_imsi[sizeof(rsp_imsi) - 1] = '\0';
    }

    log_msg("RX-Gn", v1rsp, rsp_imsi[0] ? rsp_imsi : pend->req_imsi, "-");

    const iwf_ie_t *cause_tv = gtpv1_find_ie(v1rsp, GTPV1_IE_CAUSE);
    uint8_t v1cause = cause_tv ? cause_tv->value[0] : GTPV1_CAUSE_SYSTEM_FAILURE;

    uint8_t buf[IWF_MAX_PKT];
    int tot;

    if (v1cause != GTPV1_CAUSE_REQUEST_ACCEPTED) {
        tot = encode_context_response_reject_only(pend,
                map_gtpu_v1_cause_to_v2(v1cause),
                buf, sizeof(buf));
    } else {
        const iwf_ie_t *mm_ie = NULL;
        for (size_t k = 0; k < v1rsp->n_ies; k++) {
            if (v1rsp->ies[k].type == GTPV1_IE_MM_CONTEXT) {
                mm_ie = &v1rsp->ies[k];
                break;
            }
        }
        const iwf_ie_t *pd_ie = NULL;
        for (size_t k = 0; k < v1rsp->n_ies; k++) {
            if (v1rsp->ies[k].type == GTPV1_IE_PDP_CONTEXT) {
                pd_ie = &v1rsp->ies[k];
                break;
            }
        }
        uint8_t mm_buf[512];
        size_t mm_len = 0;
        parsed_pdp130_t pdp;

        if (!mm_ie ||
            mm_v129_to_v104(mm_ie->value, mm_ie->length, mm_buf, sizeof(mm_buf),
                            &mm_len) != 0) {
            LOGE("translate", "SGSN-Ctx-Resp: MM Context IE 129→104 failed");
            tot = encode_context_response_reject_only(pend,
                    GTPV2_CAUSE_SYSTEM_FAILURE, buf, sizeof(buf));
        } else if (!pd_ie ||
                   parse_gtpu_pdp130(pd_ie, &pdp) != 0 || !pdp.ok) {
            LOGE("translate", "SGSN-Ctx-Resp: PDP Context IE (130) parse failed");
            tot = encode_context_response_reject_only(pend,
                    GTPV2_CAUSE_SYSTEM_FAILURE, buf, sizeof(buf));
        } else {
            uint32_t sctl = 0, s_ipv4 = 0;
            const iwf_ie_t *scp = gtpv1_find_ie(v1rsp, GTPV1_IE_TEID_CTRL_PLANE);
            const iwf_ie_t *sgn = gtpv1_find_ie(v1rsp, GTPV1_IE_GSN_ADDRESS);
            if (scp)
                gtpv1_decode_teid(scp, &sctl);
            if (sgn)
                gtpv1_decode_gsn_addr(sgn, &s_ipv4);
            tot = encode_ctx_resp_accepted(pend, mm_buf, mm_len, &pdp, sctl, s_ipv4,
                                           rsp_imsi[0] ? rsp_imsi : pend->req_imsi,
                                           buf, sizeof(buf));
        }
    }

    ctx_pend_free(pend);

    if (tot <= 0)
        return -1;

    LOGI("translate", "TX-v2 Context-Resp (matched gn_seq=%u v1cause=%u) len=%d",
         (unsigned)wire_seq, (unsigned)v1cause, tot);
    iwf_log_hex("translate", "Context-Resp", buf, (size_t)tot);

    return iwf_send_v2_addr(rt, &mme_sa.addr, mme_sa.addrlen, buf, (size_t)tot);
}

/* GTPv1 SGSN Context Request from osmo (Gn) → GTPv2 Context Request → [mme]. */
static int handle_v1_sgsn_ctx_req_gn_to_mme(iwf_runtime_t *rt,
                                            const iwf_endpoint_t *from,
                                            const iwf_msg_t *v1req)
{
    if (!sin_addr_matches_cfg(&from->addr, &rt->sgsn_gtp_addr)) {
        LOGW("translate",
             "Gn SGSN-Ctx-Req from unexpected %s:%u (expected peer [sgsn] %s) — ignoring",
             inet_ntoa(from->addr.sin_addr), ntohs(from->addr.sin_port),
             inet_ntoa(rt->sgsn_gtp_addr.sin_addr));
        return -1;
    }

    char imsi[IWF_IMSI_MAX] = {0};
    if (build_imsi_from_v1(v1req, imsi) != 0) {
        LOGW("translate", "Gn SGSN-Ctx-Req: missing/decoding IMSI");
        send_v1_sgsn_ctx_resp_quick(rt, from, v1req->teid,
                                    (uint16_t)v1req->seq,
                                    GTPV1_CAUSE_SYSTEM_FAILURE, "");
        return -1;
    }

    uint8_t rai6[6];
    const iwf_ie_t *raitv = gtpv1_find_ie(v1req, GTPV1_IE_RAI);
    if (raitv && raitv->length == 6)
        memcpy(rai6, raitv->value, 6);
    else
        ctx_synthetic_rai(imsi, rai6);

    uint32_t s_teid_cp = 0;
    uint32_t s_cp_ipv4 = 0;
    const iwf_ie_t *stp = gtpv1_find_ie(v1req, GTPV1_IE_TEID_CTRL_PLANE);
    if (!stp || gtpv1_decode_teid(stp, &s_teid_cp) != 0 || !s_teid_cp) {
        LOGW("translate", "Gn SGSN-Ctx-Req imsi=%s: missing TEID Ctrl Plane IE",
             imsi);
        send_v1_sgsn_ctx_resp_quick(rt, from, v1req->teid,
                                    (uint16_t)v1req->seq,
                                    GTPV1_CAUSE_SYSTEM_FAILURE, imsi);
        return -1;
    }
    const iwf_ie_t *sgn_ie = gtpv1_find_ie(v1req, GTPV1_IE_GSN_ADDRESS);
    if (sgn_ie)
        gtpv1_decode_gsn_addr(sgn_ie, &s_cp_ipv4);
    if (!s_cp_ipv4)
        s_cp_ipv4 = ntohl(from->addr.sin_addr.s_addr);

    if (!rt->mme_gtp_addr.sin_port || rt->mme_gtp_addr.sin_addr.s_addr == 0) {
        LOGE("translate",
             "Gn SGSN-Ctx-Req imsi=%s: set [mme] ip (and port) to relay Context-Req",
             imsi);
        send_v1_sgsn_ctx_resp_quick(rt, from, v1req->teid,
                                    (uint16_t)v1req->seq,
                                    GTPV1_CAUSE_SYSTEM_FAILURE, imsi);
        return -1;
    }

    uint32_t vseq_full = ++rt->v2_seq & 0xffffffu;
    if (vseq_full == 0u)
        vseq_full = 1u;

    uint8_t buf[IWF_MAX_PKT];
    gtpv2_enc_t e;
    gtpv2_enc_init(&e, buf, sizeof(buf));
    if (gtpv2_enc_begin_tf(&e, GTPV2_CONTEXT_REQUEST, 0, vseq_full, 0) != 0)
        return -1;
    if (gtpv2_enc_imsi_bcd(&e, imsi) != 0)
        return -1;

    uint8_t v2_rat = rt->cfg.rat_type;
    const iwf_ie_t *rv1rat = gtpv1_find_ie(v1req, GTPV1_IE_RAT_TYPE);
    if (rv1rat && rv1rat->length >= 1)
        v2_rat = rv1rat->value[0];
    if (gtpv2_enc_rat_type(&e, v2_rat) != 0)
        return -1;
    if (gtpv2_enc_uli_from_v1_rai(&e, rai6) != 0)
        return -1;
    if (gtpv2_enc_fteid_ipv4(&e, /*instance*/ 0, FTEID_IFACE_S4_SGSN_GTPC,
                            s_teid_cp, s_cp_ipv4) != 0)
        return -1;

    ctx_pend_t *pend = (ctx_pend_t *)calloc(1, sizeof(ctx_pend_t));
    if (!pend)
        return -1;
    pend->flow = CTX_FLOW_GN_TO_MME;
    pend->gn_seq_key = -1;
    pend->v2_seq_key = (int)vseq_full;
    pend->gn_peer_sa = *from;
    pend->gn_req_hdr_teid = v1req->teid;
    pend->gn_req_seq16 = (uint16_t)v1req->seq;
    pend->sgsn_src_teid = s_teid_cp;
    pend->sgsn_src_ipv4 = s_cp_ipv4;
    memcpy(pend->req_imsi, imsi, sizeof(pend->req_imsi) - 1);
    pend->req_imsi[sizeof(pend->req_imsi) - 1] = '\0';
    HASH_ADD(hh_v2, g_ctx_pend_v2, v2_seq_key, sizeof(int), pend);
    pend->in_v2_hash = 1;

    int tot = gtpv2_enc_finish(&e);
    if (tot <= 0) {
        ctx_pend_free(pend);
        return -1;
    }

    iwf_endpoint_t mme_dst;
    memset(&mme_dst, 0, sizeof(mme_dst));
    mme_dst.addr = rt->mme_gtp_addr;
    mme_dst.addrlen = sizeof(mme_dst.addr);

    LOGI("translate",
         "Gn SGSN-Ctx-Req→MME Context-Req imsi=%s v2-seq=%06x peer=%s:%u gn_teid_cp=0x%08x",
         imsi, (unsigned)vseq_full,
         inet_ntoa(mme_dst.addr.sin_addr),
         ntohs(mme_dst.addr.sin_port),
         s_teid_cp);
    iwf_log_hex("translate", "v2 Context-Req (Gn-origin)", buf, (size_t)tot);

    if (iwf_send_v2_addr(rt, &mme_dst.addr, mme_dst.addrlen, buf,
                         (size_t)tot) < 0) {
        ctx_pend_free(pend);
        return -1;
    }

    return 0;
}

/* Returns 1 if this was a pending Gn→MME Context transaction. */
static int try_handle_gtpu_context_response_reverse(iwf_runtime_t *rt,
                                                    const iwf_endpoint_t *from,
                                                    const iwf_msg_t *v2rsp)
{
    int seq_k = (int)(v2rsp->seq & 0xffffffu);
    ctx_pend_t *pend = NULL;
    HASH_FIND(hh_v2, g_ctx_pend_v2, &seq_k, sizeof(int), pend);
    if (!pend || pend->flow != CTX_FLOW_GN_TO_MME || !pend->in_v2_hash)
        return 0;

    uint8_t gtpv2_cause = GTPV2_CAUSE_SYSTEM_FAILURE;
    if (gtpv2_find_cause_value(v2rsp, &gtpv2_cause) != 0)
        gtpv2_cause = GTPV2_CAUSE_SYSTEM_FAILURE;

    log_msg("RX-v2-CtxResp", v2rsp, pend->req_imsi, "-");

    if (gtpv2_cause != GTPV2_CAUSE_REQUEST_ACCEPTED) {
        uint8_t vc = map_gtpu_v2_cause_to_v1_basic(gtpv2_cause);
        send_v1_sgsn_ctx_resp_quick(rt, &pend->gn_peer_sa, pend->gn_req_hdr_teid,
                                    pend->gn_req_seq16, vc, pend->req_imsi);
        ctx_pend_free(pend);
        return 1;
    }

    uint8_t *mm104 = NULL;
    uint16_t mm104_len_w = 0;
    uint8_t u129_mm[512];
    size_t u129_len = 0;
    parsed_pdp130_t pfill;

    if (pick_mm104_mm_from_ctx_resp(v2rsp, &mm104, &mm104_len_w) != 0 ||
        mm_v104_to_v129(mm104, (size_t)mm104_len_w, u129_mm, sizeof(u129_mm),
                        &u129_len) != 0 ||
        unpack_v2_pdn_for_reverse(v2rsp, &pfill) != 0) {
        LOGE("translate", "Gn→MME Context-Resp reverse map failed imsi=%s",
             pend->req_imsi);
        send_v1_sgsn_ctx_resp_quick(rt, &pend->gn_peer_sa, pend->gn_req_hdr_teid,
                                    pend->gn_req_seq16, GTPV1_CAUSE_SYSTEM_FAILURE,
                                    pend->req_imsi);
        ctx_pend_free(pend);
        return 1;
    }

    uint8_t pdp130[896];
    size_t pdp130_len = 0;
    if (encode_gtpu_pdp130_from_parse(&pfill, pdp130, sizeof(pdp130),
                                      &pdp130_len) != 0) {
        send_v1_sgsn_ctx_resp_quick(rt, &pend->gn_peer_sa, pend->gn_req_hdr_teid,
                                    pend->gn_req_seq16, GTPV1_CAUSE_SYSTEM_FAILURE,
                                    pend->req_imsi);
        ctx_pend_free(pend);
        return 1;
    }

    uint32_t m_teid_cp = 0, m_cp_ip = 0;
    pick_mme_c_from_ctx_resp(v2rsp, from, &m_teid_cp, &m_cp_ip);

    uint8_t out[IWF_MAX_PKT];
    gtpv1_enc_t enc;
    gtpv1_enc_init(&enc, out, sizeof(out));
    if (gtpv1_enc_begin(&enc, GTPV1_SGSN_CONTEXT_RESPONSE,
                        pend->gn_req_hdr_teid, pend->gn_req_seq16) != 0) {
        send_v1_sgsn_ctx_resp_quick(rt, &pend->gn_peer_sa, pend->gn_req_hdr_teid,
                                    pend->gn_req_seq16, GTPV1_CAUSE_SYSTEM_FAILURE,
                                    pend->req_imsi);
        ctx_pend_free(pend);
        return 1;
    }
    if (gtpv1_enc_tv_u8(&enc, GTPV1_IE_CAUSE,
                        GTPV1_CAUSE_REQUEST_ACCEPTED) != 0 ||
        gtpv1_enc_imsi_tv(&enc, pend->req_imsi) != 0 ||
        gtpv1_enc_tlv(&enc, GTPV1_IE_MM_CONTEXT, u129_mm, (uint16_t)u129_len) !=
            0 ||
        gtpv1_enc_tlv(&enc, GTPV1_IE_PDP_CONTEXT, pdp130,
                      (uint16_t)pdp130_len) != 0) {
        send_v1_sgsn_ctx_resp_quick(rt, &pend->gn_peer_sa, pend->gn_req_hdr_teid,
                                    pend->gn_req_seq16, GTPV1_CAUSE_SYSTEM_FAILURE,
                                    pend->req_imsi);
        ctx_pend_free(pend);
        return 1;
    }
    if (m_teid_cp && m_cp_ip) {
        if (gtpv1_enc_tv_u32(&enc, GTPV1_IE_TEID_CTRL_PLANE, m_teid_cp) != 0 ||
            gtpv1_enc_gsn_addr_ipv4(&enc, m_cp_ip) != 0) {
            send_v1_sgsn_ctx_resp_quick(
                rt, &pend->gn_peer_sa, pend->gn_req_hdr_teid,
                pend->gn_req_seq16, GTPV1_CAUSE_SYSTEM_FAILURE, pend->req_imsi);
            ctx_pend_free(pend);
            return 1;
        }
    }

    int tout = gtpv1_enc_finish(&enc);
    if (tout <= 0) {
        send_v1_sgsn_ctx_resp_quick(rt, &pend->gn_peer_sa, pend->gn_req_hdr_teid,
                                    pend->gn_req_seq16, GTPV1_CAUSE_SYSTEM_FAILURE,
                                    pend->req_imsi);
        ctx_pend_free(pend);
        return 1;
    }

    LOGI("translate",
         "TX-Gn SGSN-Ctx-Resp imsi=%s (Gn←MME path) hdr-teid=0x%08x gn_seq=%u len=%d",
         pend->req_imsi, pend->gn_req_hdr_teid, (unsigned)pend->gn_req_seq16,
         tout);
    iwf_log_hex("translate", "SGSN-Ctx-Resp(reverse)", out, (size_t)tout);
    iwf_send_v1(rt, &pend->gn_peer_sa, out, (size_t)tout);
    ctx_pend_free(pend);
    return 1;
}


/* ------------------------------------------------------------------- */
/* Northbound: GTPv1-C from osmo-sgsn -> GTPv2-C to SGW-C               */
/* ------------------------------------------------------------------- */

/* Fire-and-forget Delete Session Request for a stale session that we are
 * about to drop locally. Used to implement the implicit detach behaviour
 * described in TS 23.060 §9.2.2 / TS 23.401 §5.10.2 when a new attach
 * arrives for an IMSI+NSAPI that already has an SGW-C session. We do not
 * keep the session around to correlate the DSResp; SMF/SGW-C will tear
 * down the old PFCP session and any DSResp it returns will be matched by
 * TEID -> not found -> WARN -> drop, which is fine. */
static int send_orphan_delete_session_req(iwf_runtime_t *rt,
                                          uint32_t sgwc_ctrl_teid,
                                          uint8_t  nsapi)
{
    if (!sgwc_ctrl_teid)
        return 0;

    uint8_t outbuf[IWF_MAX_PKT];
    gtpv2_enc_t e;
    gtpv2_enc_init(&e, outbuf, sizeof(outbuf));
    gtpv2_enc_begin(&e, GTPV2_DELETE_SESSION_REQUEST,
                    sgwc_ctrl_teid, ++rt->v2_seq);
    gtpv2_enc_ebi(&e, 0, nsapi);
    gtpv2_enc_indication(&e, 0x00, 0x40, 0x00, 0x00);

    int total = gtpv2_enc_finish(&e);
    if (total <= 0) return -1;
    iwf_log_hex("translate", "DSReq(orphan)", outbuf, (size_t)total);
    return iwf_send_v2(rt, outbuf, (size_t)total);
}

static int translate_create_pdp_context(iwf_runtime_t *rt,
                                        const iwf_endpoint_t *from,
                                        const iwf_msg_t *v1)
{
    char imsi[IWF_IMSI_MAX] = {0};
    int ir = build_imsi_from_v1(v1, imsi);
    if (ir == -1) {
        LOGE("translate", "Create PDP Context Req missing IMSI IE (type 2) — dropping");
        return -1;
    }
    if (ir == -2) {
        LOGE("translate", "Create PDP Context Req IMSI BCD decode failed — dropping");
        return -1;
    }

    uint8_t nsapi = 5;
    {
        const iwf_ie_t *ie = gtpv1_find_ie(v1, GTPV1_IE_NSAPI);
        if (ie) gtpv1_decode_nsapi(ie, &nsapi);
    }

    /* GTPv1 retransmissions reuse the same sequence number. A retransmit may
     * omit the NSAPI IE (we then default nsapi to 5), so do not key only on
     * sess_find(imsi, nsapi) — correlate by IMSI + GTPv1 seq. */
    {
        sess_t *pending =
            sess_find_pending_create_by_imsi_gnseq(imsi, (uint16_t)v1->seq);
        if (pending) {
            LOGI("translate",
                 "duplicate Create-PDP-Req (retransmit) imsi=%s gn_seq=%u nsapi=%u state=%s — ignoring",
                 imsi, (unsigned)(uint16_t)v1->seq, (unsigned)pending->key.nsapi,
                 sess_state_str(pending->state));
            return 0;
        }
    }

    /* Implicit detach: a Create-PDP for an IMSI+NSAPI that already has a
     * session (and isn't a retransmit, handled above) means the UE/SGSN
     * forgot the old context — TS 23.060 §9.2.2 / TS 23.401 §5.10.2 say
     * the network must release the old PDN connection before installing
     * the new one. Without this, SGW-C/SMF and UPF keep stale state and
     * the next Create-Session may collide on TEIDs. */
    {
        sess_t *stale = sess_find(imsi, nsapi);
        if (stale) {
            LOGW("translate",
                 "reattach for imsi=%s nsapi=%u (old state=%s sgwc_teid=0x%08x) — implicit detach",
                 imsi, (unsigned)nsapi, sess_state_str(stale->state),
                 stale->sgwc_ctrl_teid);
            if (stale->sgwc_ctrl_teid)
                (void)send_orphan_delete_session_req(rt,
                                                     stale->sgwc_ctrl_teid,
                                                     stale->key.nsapi);
            sess_remove(stale);
        }
    }

    sess_t *s = sess_create(imsi, nsapi);
    if (!s) {
        LOGE("translate", "out of memory creating session imsi=%s", imsi);
        return -1;
    }

    /* Stash transport info so we can reply later. */
    s->sgsn_ep   = *from;
    s->sgsn_seq  = (uint16_t)v1->seq;
    s->state     = SESS_CREATING;

    /* MSISDN, APN, GSN addresses, TEIDs, QoS. */
    const iwf_ie_t *ie;
    if ((ie = gtpv1_find_ie(v1, GTPV1_IE_MSISDN)))
        gtpv1_decode_msisdn(ie, s->msisdn, sizeof(s->msisdn));
    if ((ie = gtpv1_find_ie(v1, GTPV1_IE_ACCESS_POINT_NAME)))
        gtpv1_decode_apn(ie, s->apn, sizeof(s->apn));

    /* TEIDs SGSN advertises to us: control plane = where to send responses;
     * data = the SGSN/RNC user-plane TEID (initially the SGSN's own; replaced
     * by RNC TEID in Update PDP Context for Direct Tunnel). */
    if ((ie = gtpv1_find_ie(v1, GTPV1_IE_TEID_CTRL_PLANE)))
        gtpv1_decode_teid(ie, &s->sgsn_ctrl_teid);
    if ((ie = gtpv1_find_ie(v1, GTPV1_IE_TEID_DATA_I)))
        gtpv1_decode_teid(ie, &s->sgsn_data_teid);
    /* S4-SGSN-U F-TEID IPv4 must match the source of real GTP-U (sgsnemu host).
     * TS 29.060 orders two IE 133 as Control Plane then User Traffic; the first
     * IE alone is often only control — Open5GS would then expect GTP-U from the
     * IWF local_ip and drop packets from the SGSN. Use last GSN IE, else UDP src. */
    if (gtpv1_last_gsn_addr_ipv4(v1, &s->sgsn_addr_ipv4) != 0) {
        if (from->addr.sin_family == AF_INET)
            s->sgsn_addr_ipv4 = ntohl(from->addr.sin_addr.s_addr);
        else
            s->sgsn_addr_ipv4 = 0;
    }

    /* QoS Profile - keep verbatim to echo in the Create PDP Response. */
    if ((ie = gtpv1_find_ie(v1, GTPV1_IE_QOS_PROFILE))) {
        size_t cp = ie->length > sizeof(s->qos_blob) ?
                    sizeof(s->qos_blob) : ie->length;
        memcpy(s->qos_blob, ie->value, cp);
        s->qos_len = cp;
    }

    /* SGW-C transport. */
    s->sgwc_addr_ipv4 = ntohl(rt->sgwc_addr.sin_addr.s_addr);

    /* New GTPv2 transaction. */
    s->gtpv2_seq = ++rt->v2_seq;

    log_msg("RX-Gn", v1, imsi, s->apn);

    /* Build Create Session Request toward SGW-C. */
    uint8_t outbuf[IWF_MAX_PKT];
    gtpv2_enc_t e;
    gtpv2_enc_init(&e, outbuf, sizeof(outbuf));
    /* CSReq TEID is 0 because no SGW-C TEID is allocated yet for this session. */
    gtpv2_enc_begin(&e, GTPV2_CREATE_SESSION_REQUEST, 0, s->gtpv2_seq);

    gtpv2_enc_imsi_bcd(&e, imsi);
    if (s->msisdn[0]) gtpv2_enc_msisdn_bcd(&e, s->msisdn);

    uint16_t mcc_sn = 0, mnc_sn = 0;
    int      have_sn = 0;
    if (strlen(imsi) >= 5) {
        char mc[4] = { imsi[0], imsi[1], imsi[2], 0 };
        char mn[4] = { imsi[3], imsi[4], 0, 0 };
        mcc_sn = (uint16_t)atoi(mc);
        mnc_sn = (uint16_t)atoi(mn);
        have_sn = 1;
    }

    /* ULI (RAI) — Open5GS SGW-C often requires this for UTRAN (GTPv2 cause 103
     * "Conditional IE missing" if absent). Map from GTPv1 RAI TV IE. Cache the
     * 6-octet RAI on the session so the activation Modify Bearer Req can
     * replay the same ULI (Open5GS rejects MBReq without ULI as cause 70). */
    if ((ie = gtpv1_find_ie(v1, GTPV1_IE_RAI)) && ie->length >= 6) {
        memcpy(s->uli_rai6, ie->value, 6);
        s->uli_kind = 1;
        if (gtpv2_enc_uli_from_v1_rai(&e, ie->value) != 0)
            LOGW("translate", "encoding ULI from RAI failed");
    } else if (rt->cfg.synthetic_uli_no_rai && have_sn) {
        s->uli_kind = 2;
        s->uli_mcc  = mcc_sn;
        s->uli_mnc  = mnc_sn;
        if (gtpv2_enc_uli_synthetic_plmn(&e, mcc_sn, mnc_sn) != 0)
            LOGW("translate", "encoding synthetic ULI failed");
        else
            LOGI("translate",
                 "encoded synthetic ULI (Gn had no RAI; synthetic_uli_no_rai=1) mcc=%u mnc=%u",
                 (unsigned)mcc_sn, (unsigned)mnc_sn);
    } else {
        LOGW("translate",
             "Create PDP has no RAI IE — Create Session may be rejected (e.g. gtpv2 cause 103); "
             "enable [iwf] synthetic_uli_no_rai=1 for lab emulators that omit RAI");
    }

    /* IE: Serving Network - take MCC/MNC from the IMSI's first 5 digits
     * (heuristic: 3-digit MCC + 2-digit MNC). */
    if (have_sn)
        gtpv2_enc_serving_network(&e, mcc_sn, mnc_sn);

    /* RAT Type is configurable: real UTRAN (1) but Open5GS SMF only accepts
     * EUTRAN (6) / WLAN (3). Default of 6 is set in config defaults. */
    gtpv2_enc_rat_type(&e, rt->cfg.rat_type);

    /* Indication flags: hi=DAF | DTF | HI | ... (TS 29.274 §8.12). Set DTF
     * (bit 5 of octet 2) to advertise Direct Tunnel support. */
    gtpv2_enc_indication(&e, 0x00, 0x40, 0x00, 0x00);

    /* Sender F-TEID for Control Plane = S4-SGSN GTP-C, our own. */
    gtpv2_enc_fteid_ipv4(&e, /*instance*/ 0, FTEID_IFACE_S4_SGSN_GTPC,
                         s->iwf_s4_c_teid, ntohl(rt->local_ipv4_be));

    /* PGW/SMF S5/S8-C F-TEID (instance 1) — Open5GS SGWC requires this IE or
     * rejects with cause 103 ("No PGW IP" in sgwc logs). */
    if (rt->cfg.smf_ip[0]) {
        struct in_addr smf;
        if (inet_pton(AF_INET, rt->cfg.smf_ip, &smf) != 1) {
            LOGE("translate", "invalid [smf] ip=%s", rt->cfg.smf_ip);
            sess_remove(s);
            return -1;
        }
        gtpv2_enc_fteid_ipv4(&e, 1, FTEID_IFACE_S5S8_PGW_GTPC,
                             rt->cfg.smf_teid, ntohl(smf.s_addr));
    } else {
        static int warned_no_smf_fteid;
        if (!warned_no_smf_fteid) {
            warned_no_smf_fteid = 1;
            LOGW("translate",
                 "Create Session: [smf] ip not set (config file: %s) — Open5GS SGWC rejects CSReq (cause 103). Add: [smf] ip=<SMF GTP-C IPv4> teid=<S5/S8 F-TEID>",
                 rt->cfg.cfg_path[0] ? rt->cfg.cfg_path : "iwf.conf");
        }
    }

    /* APN. */
    if (s->apn[0]) gtpv2_enc_apn(&e, s->apn);

    /* Selection Mode = MS or network provided APN, subscribed verified (0). */
    gtpv2_enc_selection_mode(&e, 0);

    /* PDN Type = IPv4 (consistent with EUA decoding below). */
    gtpv2_enc_pdn_type(&e, GTPV2_PDN_TYPE_IPV4);

    /* PAA - request 0.0.0.0 (dynamic allocation). */
    gtpv2_enc_paa_ipv4(&e, 0);

    /* APN-AMBR (1 Gbps best-effort cap). */
    gtpv2_enc_ambr(&e, 1000000, 1000000);

    /* APN Restriction = 0 (no restriction). */
    gtpv2_enc_apn_restriction(&e, 0);

    /* QoS mapping (3G QoS Profile -> QCI/ARP/MBR/GBR). */
    uint8_t qci, pl, pci, pvi;
    uint64_t mbr_ul, mbr_dl, gbr_ul, gbr_dl;
    uint32_t ambr_ul, ambr_dl;
    map_qos_to_qci_ambr(s->qos_blob, s->qos_len,
                        &qci, &pl, &pci, &pvi,
                        &mbr_ul, &mbr_dl, &gbr_ul, &gbr_dl,
                        &ambr_ul, &ambr_dl);

    /* Bearer Context to be created (grouped IE 93, instance 0). */
    size_t patch_pos;
    gtpv2_enc_group_begin(&e, GTPV2_IE_BEARER_CONTEXT, 0, &patch_pos);
        gtpv2_enc_ebi(&e, /*instance*/ 0, nsapi);       /* NSAPI -> EBI */
        gtpv2_enc_bearer_qos(&e, pci, pl, pvi, qci,
                             mbr_ul, mbr_dl, gbr_ul, gbr_dl);
        /* S4-SGSN F-TEID for User Plane. For Direct Tunnel this will be
         * updated later via Modify Bearer Request once the RNC TEID is
         * known.  We send a placeholder (the SGSN's data TEID) here so the
         * SGW-U has somewhere to forward DL packets if Update is delayed. */
        if (!s->sgsn_addr_ipv4) {
            LOGE("translate",
                 "Create-Session: cannot derive S4-SGSN-U IPv4 (no GSN IE, invalid peer) imsi=%s",
                 imsi);
            sess_remove(s);
            return -1;
        }
        gtpv2_enc_fteid_ipv4(&e, /*instance*/ 1, FTEID_IFACE_S4_SGSN_GTPU,
                             s->sgsn_data_teid, s->sgsn_addr_ipv4);
    gtpv2_enc_group_finish(&e, patch_pos);

    int total = gtpv2_enc_finish(&e);
    if (total <= 0) {
        LOGE("translate", "failed to encode Create Session Request");
        sess_remove(s);
        return -1;
    }

    s->state = SESS_WAIT_CS_RESP;
    sess_touch(s);

    LOGI("translate", "TX-S4 Create-Session-Req imsi=%s seq=%u len=%d",
         imsi, s->gtpv2_seq, total);
    iwf_log_hex("translate", "CSReq", outbuf, (size_t)total);

    return iwf_send_v2(rt, outbuf, (size_t)total);
}

static int translate_update_pdp_context(iwf_runtime_t *rt,
                                        const iwf_endpoint_t *from,
                                        const iwf_msg_t *v1)
{
    char imsi[IWF_IMSI_MAX] = {0};
    build_imsi_from_v1(v1, imsi);

    uint8_t nsapi = 5;
    const iwf_ie_t *ie;
    if ((ie = gtpv1_find_ie(v1, GTPV1_IE_NSAPI)))
        gtpv1_decode_nsapi(ie, &nsapi);

    /* The session is keyed on (IMSI, NSAPI) but inbound traffic may
     * carry the local TEID we minted. Try both lookups. */
    sess_t *s = NULL;
    if (imsi[0]) s = sess_find(imsi, nsapi);
    if (!s && v1->teid) s = sess_find_by_iwf_ctrl_teid(v1->teid);

    if (!s) {
        LOGW("translate", "Update PDP Context for unknown session imsi=%s nsapi=%u teid=0x%08x",
             imsi, nsapi, v1->teid);
        return -1;
    }

    s->sgsn_ep  = *from;
    s->sgsn_seq = (uint16_t)v1->seq;

    /* Update PDP Context carries the new RNC TEID for Direct Tunnel as
     * "TEID Data I" together with the RNC's IP in a GSN Address (User
     * Plane) IE. We capture both and forward them via Modify Bearer. */
    uint32_t rnc_teid = s->sgsn_data_teid;
    uint32_t rnc_ipv4 = s->sgsn_addr_ipv4;
    if ((ie = gtpv1_find_ie(v1, GTPV1_IE_TEID_DATA_I)))
        gtpv1_decode_teid(ie, &rnc_teid);
    {
        uint32_t gsn_u = 0;
        if (gtpv1_last_gsn_addr_ipv4(v1, &gsn_u) == 0)
            rnc_ipv4 = gsn_u;
        else if (from->addr.sin_family == AF_INET)
            rnc_ipv4 = ntohl(from->addr.sin_addr.s_addr);
    }
    s->sgsn_data_teid   = rnc_teid;
    s->sgsn_addr_ipv4   = rnc_ipv4;
    s->state            = SESS_MODIFYING;

    log_msg("RX-Gn", v1, imsi, s->apn);

    int rc = send_modify_bearer_req(rt, s, nsapi);
    if (rc < 0) return rc;

    s->state = SESS_WAIT_MB_RESP;
    s->mb_pending_update_seq = s->gtpv2_seq;

    LOGI("translate", "TX-S4 Modify-Bearer-Req imsi=%s seq=%u rnc_teid=0x%08x rnc_ip=%u.%u.%u.%u",
         imsi, s->gtpv2_seq, rnc_teid,
         (rnc_ipv4 >> 24) & 0xff, (rnc_ipv4 >> 16) & 0xff,
         (rnc_ipv4 >> 8) & 0xff, rnc_ipv4 & 0xff);
    return rc;
}

static int translate_delete_pdp_context(iwf_runtime_t *rt,
                                        const iwf_endpoint_t *from,
                                        const iwf_msg_t *v1)
{
    char imsi[IWF_IMSI_MAX] = {0};
    build_imsi_from_v1(v1, imsi);

    uint8_t nsapi = 5;
    const iwf_ie_t *ie;
    if ((ie = gtpv1_find_ie(v1, GTPV1_IE_NSAPI)))
        gtpv1_decode_nsapi(ie, &nsapi);

    sess_t *s = NULL;
    if (imsi[0])      s = sess_find(imsi, nsapi);
    if (!s && v1->teid) s = sess_find_by_iwf_ctrl_teid(v1->teid);

    if (!s) {
        LOGW("translate", "Delete PDP Context for unknown session teid=0x%08x",
             v1->teid);
        return -1;
    }

    s->sgsn_ep   = *from;
    s->sgsn_seq  = (uint16_t)v1->seq;
    s->state     = SESS_DELETING;
    s->gtpv2_seq = ++rt->v2_seq;

    log_msg("RX-Gn", v1, s->key.imsi, s->apn);

    /* Build Delete Session Request. */
    uint8_t outbuf[IWF_MAX_PKT];
    gtpv2_enc_t e;
    gtpv2_enc_init(&e, outbuf, sizeof(outbuf));
    gtpv2_enc_begin(&e, GTPV2_DELETE_SESSION_REQUEST,
                    s->sgwc_ctrl_teid, s->gtpv2_seq);

    gtpv2_enc_ebi(&e, 0, nsapi);                  /* Linked EPS Bearer ID */
    gtpv2_enc_indication(&e, 0x00, 0x40, 0x00, 0x00); /* DTF */

    int total = gtpv2_enc_finish(&e);
    if (total <= 0) return -1;

    s->state = SESS_WAIT_DS_RESP;
    sess_touch(s);

    LOGI("translate", "TX-S4 Delete-Session-Req imsi=%s seq=%u sgwc_teid=0x%08x",
         s->key.imsi, s->gtpv2_seq, s->sgwc_ctrl_teid);
    iwf_log_hex("translate", "DSReq", outbuf, (size_t)total);

    return iwf_send_v2(rt, outbuf, (size_t)total);
}

int translate_v1_request(iwf_runtime_t *rt,
                         const iwf_endpoint_t *from,
                         const iwf_msg_t *v1)
{
    switch (v1->msg_type) {
    case GTPV1_CREATE_PDP_CONTEXT_REQUEST:
        return translate_create_pdp_context(rt, from, v1);
    case GTPV1_UPDATE_PDP_CONTEXT_REQUEST:
        return translate_update_pdp_context(rt, from, v1);
    case GTPV1_DELETE_PDP_CONTEXT_REQUEST:
        return translate_delete_pdp_context(rt, from, v1);
    case GTPV1_ECHO_REQUEST: {
        uint8_t outbuf[IWF_MAX_PKT];
        gtpv1_enc_t e;
        gtpv1_enc_init(&e, outbuf, sizeof(outbuf));
        gtpv1_enc_begin(&e, GTPV1_ECHO_RESPONSE, 0, (uint16_t)v1->seq);
        /* Recovery IE - restart counter 0 (we never reset). */
        gtpv1_enc_tv_u8(&e, GTPV1_IE_RECOVERY, 0);
        int total = gtpv1_enc_finish(&e);
        if (total > 0) iwf_send_v1(rt, from, outbuf, (size_t)total);
        return 0;
    }
    case GTPV1_SGSN_CONTEXT_REQUEST:
        return handle_v1_sgsn_ctx_req_gn_to_mme(rt, from, v1);
    case GTPV1_SGSN_CONTEXT_RESPONSE:
        return handle_v1_sgsn_context_resp(rt, from, v1);
    default:
        LOGW("translate", "unhandled GTPv1 msg_type=%u", v1->msg_type);
        return -1;
    }
}

/* Send Modify Bearer Request toward SGW-C carrying the S4-SGSN GTP-U F-TEID.
 * Used both for spontaneous bearer activation after Create Session Response
 * (Open5GS SGW-U otherwise leaves DL FAR in BUFFER) and for Update PDP Context
 * forwarding. The caller sets the session state after the call. */
static int send_modify_bearer_req(iwf_runtime_t *rt, sess_t *s, uint8_t ebi)
{
    s->gtpv2_seq = ++rt->v2_seq;

    uint8_t outbuf[IWF_MAX_PKT];
    gtpv2_enc_t e;
    gtpv2_enc_init(&e, outbuf, sizeof(outbuf));
    gtpv2_enc_begin(&e, GTPV2_MODIFY_BEARER_REQUEST,
                    s->sgwc_ctrl_teid, s->gtpv2_seq);

    /* User Location Information — Open5GS sgwcd validates ULI on Modify Bearer
     * for S4 and answers cause 70 (Mandatory IE missing) if absent. Replay
     * whatever we cached during Create PDP. */
    if (s->uli_kind == 1) {
        gtpv2_enc_uli_from_v1_rai(&e, s->uli_rai6);
    } else if (s->uli_kind == 2) {
        gtpv2_enc_uli_synthetic_plmn(&e, s->uli_mcc, s->uli_mnc);
    }

    /* Sender F-TEID for Control Plane (S4-SGSN GTP-C) — Open5GS sgwcd treats
     * this as conditional/mandatory on MBReq to identify the S4-SGSN peer. */
    gtpv2_enc_fteid_ipv4(&e, /*instance*/ 0, FTEID_IFACE_S4_SGSN_GTPC,
                         s->iwf_s4_c_teid, ntohl(rt->local_ipv4_be));

    gtpv2_enc_rat_type(&e, rt->cfg.rat_type);
    gtpv2_enc_indication(&e, 0x00, 0x40, 0x00, 0x00); /* DTF */

    /* Bearer Context (modified). Open5GS sgwc validates the access-side F-TEID
     * by *instance number* (sgwc/s11-handler.c looks at instance 0, which it
     * names s1_u_enodeb_f_teid), not by interface-type. For S4 interworking we
     * still set Interface Type = S4-SGSN GTP-U (15) — Open5GS only reads
     * TEID + IPv4 on this path — but the IE instance must be 0 or cause 70
     * (Mandatory IE Missing) comes back even though instance 1 is the spec
     * slot for S4-SGSN F-TEID in Modify Bearer Request. */
    size_t patch_pos;
    gtpv2_enc_group_begin(&e, GTPV2_IE_BEARER_CONTEXT, 0, &patch_pos);
        gtpv2_enc_ebi(&e, 0, ebi);
        gtpv2_enc_fteid_ipv4(&e, /*instance*/ 0, FTEID_IFACE_S4_SGSN_GTPU,
                             s->sgsn_data_teid, s->sgsn_addr_ipv4);
    gtpv2_enc_group_finish(&e, patch_pos);

    int total = gtpv2_enc_finish(&e);
    if (total <= 0) return -1;

    sess_touch(s);
    iwf_log_hex("translate", "MBReq", outbuf, (size_t)total);
    return iwf_send_v2(rt, outbuf, (size_t)total);
}

/* ------------------------------------------------------------------- */
/* Southbound: GTPv2-C from SGW-C -> GTPv1-C back to osmo-sgsn          */
/* ------------------------------------------------------------------- */

/* Create Session Response bearer may list several F-TEIDs (e.g. S5/S8 PGW
 * GTP-U before S4 SGW GTP-U). The SGSN must send GTP-U to the S4/S1 SGW-U
 * leg only — never the PGW S5-U address (iface 5). Rank by TS 29.274 type. */
static int bearer_fteid_rank_sgwu(uint8_t iface)
{
    switch (iface) {
    case FTEID_IFACE_S4_SGW_GTPU:   return 0;
    case FTEID_IFACE_S1U_SGW_GTPU:  return 1;
    case FTEID_IFACE_S5S8_SGW_GTPU: return 2;
    case FTEID_IFACE_S11_SGW_GTPU:   return 3;
    default:                         return 99;
    }
}

static void bearer_pick_sgwu_fteid(const iwf_ie_t *inner, size_t n_inner,
                                   uint32_t *out_teid, uint32_t *out_ipv4)
{
    int best = 100;
    *out_teid = 0;
    *out_ipv4 = 0;
    for (size_t i = 0; i < n_inner; i++) {
        if (inner[i].type != GTPV2_IE_FTEID)
            continue;
        uint8_t iface;
        uint32_t teid, ipv4;
        if (gtpv2_decode_fteid(&inner[i], &iface, &teid, &ipv4))
            continue;
        if (!ipv4)
            continue;
        if (iface == FTEID_IFACE_S5S8_PGW_GTPU)
            continue;
        int r = bearer_fteid_rank_sgwu(iface);
        if (r < best) {
            best = r;
            *out_teid  = teid;
            *out_ipv4  = ipv4;
        }
    }
}

static int handle_create_session_response(iwf_runtime_t *rt, const iwf_msg_t *v2)
{
    sess_t *s = sess_find_by_iwf_s4_c_teid(v2->teid);
    if (!s)
        s = sess_find_by_pending_v2_seq(v2->seq, SESS_WAIT_CS_RESP);
    if (!s) {
        LOGW("translate", "CSResp: no session for S4 TEID 0x%08x seq=%u (expected iwf_s4_c_teid or pending CS)",
             v2->teid, (unsigned)(v2->seq & 0xffffffu));
        return -1;
    }
    if (s->state != SESS_WAIT_CS_RESP) {
        LOGI("translate",
             "CSResp duplicate or late imsi=%s seq=%u state=%s — ignoring",
             s->key.imsi, (unsigned)(v2->seq & 0xffffffu), sess_state_str(s->state));
        return 0;
    }
    if (v2->teid != s->iwf_s4_c_teid)
        LOGI("translate", "CSResp imsi=%s matched via seq=%u (hdr teid=0x%08x, iwf_s4_c=0x%08x)",
             s->key.imsi, (unsigned)(v2->seq & 0xffffffu), v2->teid, s->iwf_s4_c_teid);

    uint8_t gtpv2_cause;
    if (gtpv2_find_cause_value(v2, &gtpv2_cause) < 0) {
        LOGW("translate", "CSResp imsi=%s no decodable Cause IE (ies=%zu) — treating as reject",
             s->key.imsi, v2->n_ies);
        gtpv2_cause = GTPV2_CAUSE_SYSTEM_FAILURE;
    } else if (gtpv2_cause != GTPV2_CAUSE_REQUEST_ACCEPTED) {
        if (gtpv2_cause == 103) {
            LOGW("translate",
                 "CSResp imsi=%s gtpv2_cause=103 (Conditional IE missing) — GTP CSReq: missing ULI or missing [smf] PGW F-TEID (sgwc: No IMSI / No PGW IP). If CSReq already has SMF F-TEID (len grew), Open5GS maps PFCP Sx failure (SGWC⇄SGW-U) to 103 — check sgwc/sgwu logs and udp/8805",
                 s->key.imsi);
        } else {
            LOGW("translate", "CSResp imsi=%s gtpv2_cause=%u (not Request Accepted)",
                 s->key.imsi, (unsigned)gtpv2_cause);
        }
    }

    const iwf_ie_t *ie;

    /* Pick up SGW-C control F-TEID (instance 0) and SGW-U user F-TEID
     * (carried inside the Bearer Context grouped IE). */
    if ((ie = gtpv2_find_ie(v2, GTPV2_IE_FTEID, 1))) {
        uint8_t iface; uint32_t teid, ipv4;
        if (!gtpv2_decode_fteid(ie, &iface, &teid, &ipv4)) {
            /* TS 29.274: instance 1 in CSResp = PGW F-TEID for S5/S8 C-plane;
             * for S4 the SGW S11/S4 C-plane is instance 0. We still capture it. */
            s->sgwc_ctrl_teid = teid;
            if (ipv4) s->sgwc_addr_ipv4 = ipv4;
        }
    }
    if ((ie = gtpv2_find_ie(v2, GTPV2_IE_FTEID, 0))) {
        uint8_t iface; uint32_t teid, ipv4;
        if (!gtpv2_decode_fteid(ie, &iface, &teid, &ipv4)) {
            s->sgwc_ctrl_teid = teid;
            if (ipv4) s->sgwc_addr_ipv4 = ipv4;
        }
    }

    /* PAA - the UE IP. */
    if ((ie = gtpv2_find_ie(v2, GTPV2_IE_PAA, 0))) {
        uint8_t pt; uint32_t ip;
        if (!gtpv2_decode_paa_ipv4(ie, &pt, &ip)) s->ue_ipv4 = ip;
    }

    /* Bearer Context — pick SGW user-plane F-TEID (S4=16, S1-U=1), not PGW S5-U (5),
     * and harvest the SMF-allocated Charging ID (IE 94) for CDR correlation. */
    iwf_ie_t bc_inner[IWF_MAX_IES];
    size_t   bc_n_inner = 0;
    s->charging_id = 0;
    if ((ie = gtpv2_find_ie(v2, GTPV2_IE_BEARER_CONTEXT, 0))) {
        if (gtpv2_parse_grouped(ie, bc_inner, IWF_MAX_IES, &bc_n_inner) == 0) {
            bearer_pick_sgwu_fteid(bc_inner, bc_n_inner, &s->sgwu_teid, &s->sgwu_addr_ipv4);
            for (size_t i = 0; i < bc_n_inner; i++) {
                if (bc_inner[i].type == GTPV2_IE_CHARGING_ID &&
                    bc_inner[i].length >= 4) {
                    s->charging_id = iwf_be32(bc_inner[i].value);
                    break;
                }
            }
        }
    }

    /* PAA fallback: some implementations nest PAA in PDN Connection (109)
     * for handover/relocation flows. Top-level wins; only consult the nested
     * copy when message-level PAA was absent. */
    if (!s->ue_ipv4 && (ie = gtpv2_find_ie(v2, GTPV2_IE_PDN_CONNECTION, 0))) {
        iwf_ie_t pdn_inner[IWF_MAX_IES];
        size_t   pdn_n = 0;
        if (gtpv2_parse_grouped(ie, pdn_inner, IWF_MAX_IES, &pdn_n) == 0) {
            for (size_t i = 0; i < pdn_n; i++) {
                if (pdn_inner[i].type == GTPV2_IE_PAA) {
                    uint8_t pt; uint32_t ip;
                    if (!gtpv2_decode_paa_ipv4(&pdn_inner[i], &pt, &ip))
                        s->ue_ipv4 = ip;
                    break;
                }
            }
        }
    }

    /* PCO (TS 29.274 §8.13) — copy verbatim from CSResp. EPS PCO uses the same
     * container-TLV layout as GTPv1 IE 132 (TS 29.060 §7.7.31), so the bytes
     * are interchangeable. SMF may place PCO at message level or inside the
     * Bearer Context; check both. Without this the SGSN delivers the UE
     * empty DNS / MTU / P-CSCF / IPCP and data plane is broken. */
    s->pco_len = 0;
    const iwf_ie_t *pco_ie = gtpv2_find_ie(v2, GTPV2_IE_PCO, 0);
    if (!pco_ie) {
        for (size_t i = 0; i < bc_n_inner; i++) {
            if (bc_inner[i].type == GTPV2_IE_PCO) {
                pco_ie = &bc_inner[i];
                break;
            }
        }
    }
    if (pco_ie && pco_ie->length > 0 && pco_ie->length <= sizeof(s->pco_blob)) {
        memcpy(s->pco_blob, pco_ie->value, pco_ie->length);
        s->pco_len = pco_ie->length;
    } else if (pco_ie && pco_ie->length > sizeof(s->pco_blob)) {
        LOGW("translate",
             "CSResp imsi=%s PCO too large (%u) — dropping; UE will see empty DNS/MTU",
             s->key.imsi, (unsigned)pco_ie->length);
    }

    if (gtpv2_cause == GTPV2_CAUSE_REQUEST_ACCEPTED && !s->sgwu_addr_ipv4) {
        LOGW("translate",
             "CSResp imsi=%s no SGW-U F-TEID in Bearer (expected iface 16 S4 SGW GTP-U or 1 S1-U SGW GTP-U)",
             s->key.imsi);
    }

    log_msg("RX-S4", v2, s->key.imsi, s->apn);

    /* Build Create PDP Context Response back to osmo-sgsn. */
    uint8_t outbuf[IWF_MAX_PKT];
    gtpv1_enc_t e;
    gtpv1_enc_init(&e, outbuf, sizeof(outbuf));
    gtpv1_enc_begin(&e, GTPV1_CREATE_PDP_CONTEXT_RESPONSE,
                    s->sgsn_ctrl_teid, s->sgsn_seq);

    uint8_t v1_cause = map_gtpv2_cause_to_v1_pdp_resp(gtpv2_cause);

    iwf_endpoint_t resp_ep    = s->sgsn_ep;
    uint16_t       resp_seq   = s->sgsn_seq;
    char           log_imsi[IWF_IMSI_MAX];
    strncpy(log_imsi, s->key.imsi, sizeof(log_imsi));
    log_imsi[sizeof(log_imsi) - 1] = '\0';
    uint32_t log_sgwu_ip   = s->sgwu_addr_ipv4;
    uint32_t log_sgwu_teid = s->sgwu_teid;
    uint32_t log_ue_ip     = s->ue_ipv4;

    gtpv1_enc_cause(&e, v1_cause);

    if (v1_cause == GTPV1_CAUSE_REQUEST_ACCEPTED) {
        /* Reordering Required IE (type 8, TV 1) - 0xfe = not required.
         * Mandatory in Create PDP Context Response per TS 29.060 §7.3.2. */
        gtpv1_enc_tv_u8(&e, 8, 0xfe);

        /* Charging ID — prefer the SMF-allocated value (GTPv2 IE 94) so SGSN
         * and PGW agree on the CDR correlator. Fall back to iwf_ctrl_teid
         * only when SMF didn't include one. */
        gtpv1_enc_tv_u32(&e, GTPV1_IE_CHARGING_ID,
                         s->charging_id ? s->charging_id : s->iwf_ctrl_teid);

        /* End User Address = UE IPv4. */
        if (s->ue_ipv4) gtpv1_enc_eua_ipv4(&e, s->ue_ipv4);

        /* PCO (TS 29.060 §7.3.1 ordering: after EUA, before TEIDs). EPS PCO
         * bytes from GTPv2 IE 78 are wire-compatible with GTPv1 IE 132 — copy
         * verbatim so DNS, IPv4 Link MTU, IM CN SS Flag, IPCP etc. survive
         * the translation. Without this the UE gets DNS=0.0.0.0 / MTU=0. */
        if (s->pco_len)
            gtpv1_enc_tlv(&e, GTPV1_IE_PCO, s->pco_blob, (uint16_t)s->pco_len);

        /* TEID Data I = SGW-U TEID (Direct Tunnel target). */
        if (s->sgwu_teid)
            gtpv1_enc_tv_u32(&e, GTPV1_IE_TEID_DATA_I, s->sgwu_teid);

        /* TEID Control Plane = IWF's GGSN-side ctrl TEID. */
        gtpv1_enc_tv_u32(&e, GTPV1_IE_TEID_CTRL_PLANE, s->iwf_ctrl_teid);

        /* Two GTPv1 IE type 133 (GSN Address) — TS 29.060 Table 6: Control Plane
         * then user traffic. osmo-sgsn/libgtp maps by order; if reversed, GTP-U
         * is sent to local_ip (IWF) instead of SGW-U. */
        gtpv1_enc_gsn_addr_ipv4(&e, ntohl(rt->local_ipv4_be));
        if (s->sgwu_addr_ipv4)
            gtpv1_enc_gsn_addr_ipv4(&e, s->sgwu_addr_ipv4);

        /* QoS Profile echoed back. */
        if (s->qos_len)
            gtpv1_enc_qos_profile(&e, s->qos_blob, s->qos_len);

        s->state = SESS_ACTIVE;
    } else {
        sess_remove(s);
    }

    int total = gtpv1_enc_finish(&e);
    if (total <= 0) return -1;

    LOGI("translate",
         "TX-Gn Create-PDP-Resp imsi=%s seq=%u cause=%u sgwu=%u.%u.%u.%u teid=0x%08x ue_ip=%u.%u.%u.%u",
         log_imsi, (unsigned)resp_seq, v1_cause,
         (log_sgwu_ip >> 24) & 0xff, (log_sgwu_ip >> 16) & 0xff,
         (log_sgwu_ip >> 8) & 0xff, log_sgwu_ip & 0xff,
         log_sgwu_teid,
         (log_ue_ip >> 24) & 0xff, (log_ue_ip >> 16) & 0xff,
         (log_ue_ip >> 8) & 0xff, log_ue_ip & 0xff);
    iwf_log_hex("translate", "Create-PDP-Resp", outbuf, (size_t)total);

    int sent_v1 = iwf_send_v1(rt, &resp_ep, outbuf, (size_t)total);

    /* Spontaneous Modify Bearer Request: Open5GS sgwcd installs the SGW-U DL
     * FAR in BUFFER until a Modify Bearer Request supplies the access-side
     * F-TEID. The SGSN F-TEID is already known from Create PDP Context Req,
     * so push it now; otherwise downlink stays buffered and ping never works.
     *
     * In Direct Tunnel deployments with a real RNC, osmo-sgsn will later send
     * Update PDP Context with the RNC's F-TEID; that path issues another MBReq
     * and SGW-U is reprogrammed accordingly. */
    if (v1_cause == GTPV1_CAUSE_REQUEST_ACCEPTED && s->sgsn_addr_ipv4) {
        /* Flip state BEFORE the send so an MBResp processed in the same
         * event-loop iteration matches WAIT_MB_RESP_INIT, not ACTIVE.
         * iwf_send_v2 returns byte count on success (>= 0 means dispatched). */
        s->state = SESS_WAIT_MB_RESP_INIT;
        int mb_rc = send_modify_bearer_req(rt, s, s->key.nsapi);
        if (mb_rc < 0) {
            LOGW("translate",
                 "activation MBReq send failed imsi=%s — DL FAR may stay BUFFER on SGW-U",
                 s->key.imsi);
            s->state = SESS_ACTIVE;
        } else {
            LOGI("translate",
                 "TX-S4 Modify-Bearer-Req (activate) imsi=%s seq=%u sgsn_teid=0x%08x sgsn_ip=%u.%u.%u.%u",
                 s->key.imsi, s->gtpv2_seq, s->sgsn_data_teid,
                 (s->sgsn_addr_ipv4 >> 24) & 0xff, (s->sgsn_addr_ipv4 >> 16) & 0xff,
                 (s->sgsn_addr_ipv4 >> 8)  & 0xff,  s->sgsn_addr_ipv4 & 0xff);
            s->mb_pending_init_seq = s->gtpv2_seq;
        }
    }

    return sent_v1;
}

static int handle_modify_bearer_response(iwf_runtime_t *rt, const iwf_msg_t *v2)
{
    sess_t *s = sess_find_by_iwf_s4_c_teid(v2->teid);
    if (!s)
        s = sess_find_by_pending_v2_seq(v2->seq, SESS_WAIT_MB_RESP);
    if (!s)
        s = sess_find_by_pending_v2_seq(v2->seq, SESS_WAIT_MB_RESP_INIT);
    if (!s) {
        LOGW("translate", "MBResp: no session for S4 TEID 0x%08x seq=%u",
             v2->teid, (unsigned)(v2->seq & 0xffffffu));
        return -1;
    }

    uint8_t cause = GTPV2_CAUSE_SYSTEM_FAILURE;
    const iwf_ie_t *ie = gtpv2_find_ie(v2, GTPV2_IE_CAUSE, 0);
    if (ie) gtpv2_decode_cause(ie, &cause);

    log_msg("RX-S4", v2, s->key.imsi, s->apn);

    uint32_t seq24 = v2->seq & 0xffffffu;
    int match_init = s->mb_pending_init_seq &&
        seq24 == (s->mb_pending_init_seq & 0xffffffu);
    int match_upd = s->mb_pending_update_seq &&
        seq24 == (s->mb_pending_update_seq & 0xffffffu);

    /* Activation MB after CSResp may complete after we've already sent Update PDP's MBReq
     * (WAIT_MB_RESP). Old logic treated any MBResp in WAIT_MB_RESP as Update PDP completion,
     * mis-delivered Update PDP Resp too early and left DL FAR confused until uplink arrived. */
    if (match_init) {
        s->mb_pending_init_seq = 0;
        if (cause == GTPV2_CAUSE_REQUEST_ACCEPTED) {
            LOGI("translate",
                 "MBResp (activate) imsi=%s seq=%u cause=16 — bearer ACTIVE, DL FAR should be FORWARD",
                 s->key.imsi, (unsigned)seq24);
        } else {
            LOGW("translate",
                 "MBResp (activate) imsi=%s seq=%u gtpv2_cause=%u — DL may stay BUFFER on SGW-U",
                 s->key.imsi, (unsigned)seq24, (unsigned)cause);
        }
        sess_touch(s);
        if (s->mb_pending_update_seq)
            s->state = SESS_WAIT_MB_RESP;
        else
            s->state = SESS_ACTIVE;
        return 0;
    }

    if (!match_upd) {
        /* Duplicate MBResp or TEID correlation without pending seq — tolerate activate-only path */
        if (s->state != SESS_WAIT_MB_RESP) {
            if (cause == GTPV2_CAUSE_REQUEST_ACCEPTED) {
                LOGI("translate",
                     "MBResp (activate/legacy) imsi=%s seq=%u cause=16 — bearer ACTIVE",
                     s->key.imsi, (unsigned)seq24);
            } else {
                LOGW("translate",
                     "MBResp (activate/legacy) imsi=%s seq=%u gtpv2_cause=%u",
                     s->key.imsi, (unsigned)seq24, (unsigned)cause);
            }
            s->state = SESS_ACTIVE;
            sess_touch(s);
            return 0;
        }
        LOGW("translate",
             "MBResp imsi=%s seq=%u unexpected (pending_init=%u pending_upd=%u state=%s)",
             s->key.imsi, (unsigned)seq24,
             (unsigned)(s->mb_pending_init_seq & 0xffffffu),
             (unsigned)(s->mb_pending_update_seq & 0xffffffu),
             sess_state_str(s->state));
        return 0;
    }

    s->mb_pending_update_seq = 0;

    uint8_t outbuf[IWF_MAX_PKT];
    gtpv1_enc_t e;
    gtpv1_enc_init(&e, outbuf, sizeof(outbuf));
    gtpv1_enc_begin(&e, GTPV1_UPDATE_PDP_CONTEXT_RESPONSE,
                    s->sgsn_ctrl_teid, s->sgsn_seq);

    uint8_t v1_cause = map_gtpv2_cause_to_v1_pdp_resp(cause);
    gtpv1_enc_cause(&e, v1_cause);

    if (v1_cause == GTPV1_CAUSE_REQUEST_ACCEPTED) {
        if (s->sgwu_teid)
            gtpv1_enc_tv_u32(&e, GTPV1_IE_TEID_DATA_I, s->sgwu_teid);
        gtpv1_enc_tv_u32(&e, GTPV1_IE_TEID_CTRL_PLANE, s->iwf_ctrl_teid);
        gtpv1_enc_gsn_addr_ipv4(&e, ntohl(rt->local_ipv4_be));
        if (s->sgwu_addr_ipv4)
            gtpv1_enc_gsn_addr_ipv4(&e, s->sgwu_addr_ipv4);
        if (s->qos_len)
            gtpv1_enc_qos_profile(&e, s->qos_blob, s->qos_len);
        s->state = SESS_ACTIVE;
    }

    int total = gtpv1_enc_finish(&e);
    if (total <= 0) return -1;

    LOGI("translate", "TX-Gn Update-PDP-Resp imsi=%s seq=%u cause=%u",
         s->key.imsi, s->sgsn_seq, v1_cause);
    iwf_log_hex("translate", "Update-PDP-Resp", outbuf, (size_t)total);

    return iwf_send_v1(rt, &s->sgsn_ep, outbuf, (size_t)total);
}

static int handle_delete_session_response(iwf_runtime_t *rt, const iwf_msg_t *v2)
{
    sess_t *s = sess_find_by_iwf_s4_c_teid(v2->teid);
    if (!s)
        s = sess_find_by_pending_v2_seq(v2->seq, SESS_WAIT_DS_RESP);
    if (!s) {
        LOGW("translate", "DSResp: no session for S4 TEID 0x%08x seq=%u",
             v2->teid, (unsigned)(v2->seq & 0xffffffu));
        return -1;
    }

    uint8_t cause = GTPV2_CAUSE_SYSTEM_FAILURE;
    const iwf_ie_t *ie = gtpv2_find_ie(v2, GTPV2_IE_CAUSE, 0);
    if (ie) gtpv2_decode_cause(ie, &cause);

    log_msg("RX-S4", v2, s->key.imsi, s->apn);

    uint8_t outbuf[IWF_MAX_PKT];
    gtpv1_enc_t e;
    gtpv1_enc_init(&e, outbuf, sizeof(outbuf));
    gtpv1_enc_begin(&e, GTPV1_DELETE_PDP_CONTEXT_RESPONSE,
                    s->sgsn_ctrl_teid, s->sgsn_seq);

    uint8_t v1_cause = (cause == GTPV2_CAUSE_REQUEST_ACCEPTED)
                       ? GTPV1_CAUSE_REQUEST_ACCEPTED
                       : GTPV1_CAUSE_NON_EXISTENT;
    gtpv1_enc_cause(&e, v1_cause);

    int total = gtpv1_enc_finish(&e);
    if (total > 0) {
        LOGI("translate", "TX-Gn Delete-PDP-Resp imsi=%s seq=%u cause=%u",
             s->key.imsi, s->sgsn_seq, v1_cause);
        iwf_log_hex("translate", "Delete-PDP-Resp", outbuf, (size_t)total);
        iwf_send_v1(rt, &s->sgsn_ep, outbuf, (size_t)total);
    }

    sess_remove(s);
    return 0;
}

int translate_v2_response(iwf_runtime_t *rt,
                          const iwf_endpoint_t *from,
                          const iwf_msg_t *v2)
{
    switch (v2->msg_type) {
    case GTPV2_CREATE_SESSION_RESPONSE: return handle_create_session_response(rt, v2);
    case GTPV2_MODIFY_BEARER_RESPONSE:  return handle_modify_bearer_response(rt, v2);
    case GTPV2_DELETE_SESSION_RESPONSE: return handle_delete_session_response(rt, v2);
    case GTPV2_CONTEXT_REQUEST:
        return handle_gtpu_context_request(rt, from, v2);
    case GTPV2_CONTEXT_RESPONSE: {
        if (try_handle_gtpu_context_response_reverse(rt, from, v2))
            return 0;
        LOGW("translate", "unmatched v2 Context-Resp seq=%06x — no Gn.pending",
             (unsigned)(v2->seq & 0xffffffu));
        return 0;
    }
    case GTPV2_ECHO_REQUEST: {
        uint8_t outbuf[IWF_MAX_PKT];
        gtpv2_enc_t e;
        gtpv2_enc_init(&e, outbuf, sizeof(outbuf));
        gtpv2_enc_begin(&e, GTPV2_ECHO_RESPONSE, 0, v2->seq);
        uint8_t rec = 0;
        gtpv2_enc_tlv(&e, GTPV2_IE_RECOVERY, 0, &rec, 1);
        int total = gtpv2_enc_finish(&e);
        if (total > 0)
            iwf_send_v2_addr(rt, &from->addr, from->addrlen,
                             outbuf, (size_t)total);
        return 0;
    }
    case GTPV2_ECHO_RESPONSE:
        return 0;
    default:
        LOGW("translate", "unhandled GTPv2 msg_type=%u", v2->msg_type);
        return -1;
    }
}
