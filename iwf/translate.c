#include "translate.h"
#include "runtime.h"
#include "gtpv1.h"
#include "gtpv2.h"
#include "logging.h"

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
    case GTPV1_ECHO_REQUEST:                return "Echo-Req";
    case GTPV1_ECHO_RESPONSE:               return "Echo-Resp";
    default:                                return "?";
    }
}

static const char *v2_msg_str(uint8_t t)
{
    switch (t) {
    case GTPV2_CREATE_SESSION_REQUEST:  return "Create-Session-Req";
    case GTPV2_CREATE_SESSION_RESPONSE: return "Create-Session-Resp";
    case GTPV2_MODIFY_BEARER_REQUEST:   return "Modify-Bearer-Req";
    case GTPV2_MODIFY_BEARER_RESPONSE:  return "Modify-Bearer-Resp";
    case GTPV2_DELETE_SESSION_REQUEST:  return "Delete-Session-Req";
    case GTPV2_DELETE_SESSION_RESPONSE: return "Delete-Session-Resp";
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

static int build_imsi_from_v1(const iwf_msg_t *v1, char *imsi)
{
    imsi[0] = '\0';
    const iwf_ie_t *ie = gtpv1_find_ie(v1, GTPV1_IE_IMSI);
    if (!ie) return -1;
    return gtpv1_decode_imsi(ie, imsi, IWF_IMSI_MAX);
}

/* ------------------------------------------------------------------- */
/* Northbound: GTPv1-C from osmo-sgsn -> GTPv2-C to SGW-C               */
/* ------------------------------------------------------------------- */

static int translate_create_pdp_context(iwf_runtime_t *rt,
                                        const iwf_endpoint_t *from,
                                        const iwf_msg_t *v1)
{
    char imsi[IWF_IMSI_MAX] = {0};
    if (build_imsi_from_v1(v1, imsi) < 0) {
        LOGE("translate", "Create PDP Context Req without IMSI - dropping");
        return -1;
    }

    uint8_t nsapi = 5;
    {
        const iwf_ie_t *ie = gtpv1_find_ie(v1, GTPV1_IE_NSAPI);
        if (ie) gtpv1_decode_nsapi(ie, &nsapi);
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
    if ((ie = gtpv1_find_ie(v1, GTPV1_IE_GSN_ADDRESS)))
        gtpv1_decode_gsn_addr(ie, &s->sgsn_addr_ipv4);

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

    /* IE: ULI - could be derived from RAI in v1; omitted minimally here.
     * Many SGW-C deployments accept CSReq without ULI. */

    /* IE: Serving Network - take MCC/MNC from the IMSI's first 5 digits
     * (heuristic: 3-digit MCC + 2-digit MNC). */
    if (strlen(imsi) >= 5) {
        char mc[4] = { imsi[0], imsi[1], imsi[2], 0 };
        char mn[4] = { imsi[3], imsi[4], 0, 0 };
        uint16_t mcc = (uint16_t)atoi(mc);
        uint16_t mnc = (uint16_t)atoi(mn);
        gtpv2_enc_serving_network(&e, mcc, mnc);
    }

    gtpv2_enc_rat_type(&e, GTPV2_RAT_UTRAN);

    /* Indication flags: hi=DAF | DTF | HI | ... (TS 29.274 §8.12). Set DTF
     * (bit 5 of octet 2) to advertise Direct Tunnel support. */
    gtpv2_enc_indication(&e, 0x00, 0x40, 0x00, 0x00);

    /* Sender F-TEID for Control Plane = S4-SGSN GTP-C, our own. */
    gtpv2_enc_fteid_ipv4(&e, /*instance*/ 0, FTEID_IFACE_S4_SGSN_GTPC,
                         s->iwf_s4_c_teid, ntohl(rt->local_ipv4_be));

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
        gtpv2_enc_fteid_ipv4(&e, /*instance*/ 1, FTEID_IFACE_S4_SGSN_GTPU,
                             s->sgsn_data_teid,
                             s->sgsn_addr_ipv4 ? s->sgsn_addr_ipv4
                                               : ntohl(rt->local_ipv4_be));
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
    if ((ie = gtpv1_find_ie(v1, GTPV1_IE_GSN_ADDRESS)))
        gtpv1_decode_gsn_addr(ie, &rnc_ipv4);
    s->sgsn_data_teid   = rnc_teid;
    s->sgsn_addr_ipv4   = rnc_ipv4;
    s->state            = SESS_MODIFYING;
    s->gtpv2_seq        = ++rt->v2_seq;

    log_msg("RX-Gn", v1, imsi, s->apn);

    /* Build Modify Bearer Request - addressed to SGW-C using its TEID. */
    uint8_t outbuf[IWF_MAX_PKT];
    gtpv2_enc_t e;
    gtpv2_enc_init(&e, outbuf, sizeof(outbuf));
    gtpv2_enc_begin(&e, GTPV2_MODIFY_BEARER_REQUEST,
                    s->sgwc_ctrl_teid, s->gtpv2_seq);

    gtpv2_enc_rat_type(&e, GTPV2_RAT_UTRAN);
    gtpv2_enc_indication(&e, 0x00, 0x40, 0x00, 0x00); /* DTF */

    /* Bearer Contexts To Be Modified (grouped IE 93, instance 0). */
    size_t patch_pos;
    gtpv2_enc_group_begin(&e, GTPV2_IE_BEARER_CONTEXT, 0, &patch_pos);
        gtpv2_enc_ebi(&e, 0, nsapi);
        /* Direct Tunnel: tell SGW-U to send DL straight to the RNC. */
        gtpv2_enc_fteid_ipv4(&e, /*instance*/ 1, FTEID_IFACE_S4_SGSN_GTPU,
                             s->sgsn_data_teid, s->sgsn_addr_ipv4);
    gtpv2_enc_group_finish(&e, patch_pos);

    int total = gtpv2_enc_finish(&e);
    if (total <= 0) return -1;

    s->state = SESS_WAIT_MB_RESP;
    sess_touch(s);

    LOGI("translate", "TX-S4 Modify-Bearer-Req imsi=%s seq=%u rnc_teid=0x%08x rnc_ip=%u.%u.%u.%u",
         imsi, s->gtpv2_seq, rnc_teid,
         (rnc_ipv4 >> 24) & 0xff, (rnc_ipv4 >> 16) & 0xff,
         (rnc_ipv4 >> 8) & 0xff, rnc_ipv4 & 0xff);
    iwf_log_hex("translate", "MBReq", outbuf, (size_t)total);

    return iwf_send_v2(rt, outbuf, (size_t)total);
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
    default:
        LOGW("translate", "unhandled GTPv1 msg_type=%u", v1->msg_type);
        return -1;
    }
}

/* ------------------------------------------------------------------- */
/* Southbound: GTPv2-C from SGW-C -> GTPv1-C back to osmo-sgsn          */
/* ------------------------------------------------------------------- */

static int handle_create_session_response(iwf_runtime_t *rt, const iwf_msg_t *v2)
{
    sess_t *s = sess_find_by_iwf_s4_c_teid(v2->teid);
    if (!s) {
        LOGW("translate", "CSResp for unknown S4 TEID 0x%08x", v2->teid);
        return -1;
    }

    uint8_t cause = 0;
    const iwf_ie_t *ie = gtpv2_find_ie(v2, GTPV2_IE_CAUSE, 0);
    if (ie) gtpv2_decode_cause(ie, &cause);

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

    /* Bearer Context - SGW-U F-TEID (Direct Tunnel target). */
    if ((ie = gtpv2_find_ie(v2, GTPV2_IE_BEARER_CONTEXT, 0))) {
        iwf_ie_t inner[8]; size_t n_inner = 0;
        if (gtpv2_parse_grouped(ie, inner, 8, &n_inner) == 0) {
            for (size_t i = 0; i < n_inner; i++) {
                if (inner[i].type == GTPV2_IE_FTEID) {
                    uint8_t iface; uint32_t teid, ipv4;
                    if (!gtpv2_decode_fteid(&inner[i], &iface, &teid, &ipv4)) {
                        /* S1-U SGW GTP-U (1) is the EUTRAN encoding; for S4
                         * the standard uses S4 SGW GTP-U as well. Accept any
                         * SGW user-plane F-TEID. */
                        s->sgwu_teid      = teid;
                        s->sgwu_addr_ipv4 = ipv4;
                    }
                }
            }
        }
    }

    log_msg("RX-S4", v2, s->key.imsi, s->apn);

    /* Build Create PDP Context Response back to osmo-sgsn. */
    uint8_t outbuf[IWF_MAX_PKT];
    gtpv1_enc_t e;
    gtpv1_enc_init(&e, outbuf, sizeof(outbuf));
    gtpv1_enc_begin(&e, GTPV1_CREATE_PDP_CONTEXT_RESPONSE,
                    s->sgsn_ctrl_teid, s->sgsn_seq);

    uint8_t v1_cause = (cause == GTPV2_CAUSE_REQUEST_ACCEPTED)
                       ? GTPV1_CAUSE_REQUEST_ACCEPTED
                       : GTPV1_CAUSE_NO_RESOURCES;
    gtpv1_enc_cause(&e, v1_cause);

    if (v1_cause == GTPV1_CAUSE_REQUEST_ACCEPTED) {
        /* Reordering Required IE (type 8, TV 1) - 0xfe = not required.
         * Mandatory in Create PDP Context Response per TS 29.060 §7.3.2. */
        gtpv1_enc_tv_u8(&e, 8, 0xfe);

        gtpv1_enc_tv_u32(&e, GTPV1_IE_CHARGING_ID, (uint32_t)s->iwf_ctrl_teid);

        /* End User Address = UE IPv4. */
        if (s->ue_ipv4) gtpv1_enc_eua_ipv4(&e, s->ue_ipv4);

        /* TEID Data I = SGW-U TEID (Direct Tunnel target). */
        if (s->sgwu_teid)
            gtpv1_enc_tv_u32(&e, GTPV1_IE_TEID_DATA_I, s->sgwu_teid);

        /* TEID Control Plane = IWF's GGSN-side ctrl TEID. */
        gtpv1_enc_tv_u32(&e, GTPV1_IE_TEID_CTRL_PLANE, s->iwf_ctrl_teid);

        /* GSN Address (User Plane) = SGW-U IP. */
        if (s->sgwu_addr_ipv4)
            gtpv1_enc_gsn_addr_ipv4(&e, s->sgwu_addr_ipv4);
        /* GSN Address (Control Plane) = IWF local IP. */
        gtpv1_enc_gsn_addr_ipv4(&e, ntohl(rt->local_ipv4_be));

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
         s->key.imsi, s->sgsn_seq, v1_cause,
         (s->sgwu_addr_ipv4 >> 24) & 0xff, (s->sgwu_addr_ipv4 >> 16) & 0xff,
         (s->sgwu_addr_ipv4 >> 8) & 0xff, s->sgwu_addr_ipv4 & 0xff,
         s->sgwu_teid,
         (s->ue_ipv4 >> 24) & 0xff, (s->ue_ipv4 >> 16) & 0xff,
         (s->ue_ipv4 >> 8) & 0xff, s->ue_ipv4 & 0xff);
    iwf_log_hex("translate", "Create-PDP-Resp", outbuf, (size_t)total);

    return iwf_send_v1(rt, &s->sgsn_ep, outbuf, (size_t)total);
}

static int handle_modify_bearer_response(iwf_runtime_t *rt, const iwf_msg_t *v2)
{
    sess_t *s = sess_find_by_iwf_s4_c_teid(v2->teid);
    if (!s) {
        LOGW("translate", "MBResp for unknown S4 TEID 0x%08x", v2->teid);
        return -1;
    }

    uint8_t cause = GTPV2_CAUSE_SYSTEM_FAILURE;
    const iwf_ie_t *ie = gtpv2_find_ie(v2, GTPV2_IE_CAUSE, 0);
    if (ie) gtpv2_decode_cause(ie, &cause);

    log_msg("RX-S4", v2, s->key.imsi, s->apn);

    uint8_t outbuf[IWF_MAX_PKT];
    gtpv1_enc_t e;
    gtpv1_enc_init(&e, outbuf, sizeof(outbuf));
    gtpv1_enc_begin(&e, GTPV1_UPDATE_PDP_CONTEXT_RESPONSE,
                    s->sgsn_ctrl_teid, s->sgsn_seq);

    uint8_t v1_cause = (cause == GTPV2_CAUSE_REQUEST_ACCEPTED)
                       ? GTPV1_CAUSE_REQUEST_ACCEPTED
                       : GTPV1_CAUSE_NO_RESOURCES;
    gtpv1_enc_cause(&e, v1_cause);

    if (v1_cause == GTPV1_CAUSE_REQUEST_ACCEPTED) {
        if (s->sgwu_teid)
            gtpv1_enc_tv_u32(&e, GTPV1_IE_TEID_DATA_I, s->sgwu_teid);
        gtpv1_enc_tv_u32(&e, GTPV1_IE_TEID_CTRL_PLANE, s->iwf_ctrl_teid);
        if (s->sgwu_addr_ipv4)
            gtpv1_enc_gsn_addr_ipv4(&e, s->sgwu_addr_ipv4);
        gtpv1_enc_gsn_addr_ipv4(&e, ntohl(rt->local_ipv4_be));
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
    if (!s) {
        LOGW("translate", "DSResp for unknown S4 TEID 0x%08x", v2->teid);
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
    (void)from;
    switch (v2->msg_type) {
    case GTPV2_CREATE_SESSION_RESPONSE: return handle_create_session_response(rt, v2);
    case GTPV2_MODIFY_BEARER_RESPONSE:  return handle_modify_bearer_response(rt, v2);
    case GTPV2_DELETE_SESSION_RESPONSE: return handle_delete_session_response(rt, v2);
    case GTPV2_ECHO_REQUEST: {
        uint8_t outbuf[IWF_MAX_PKT];
        gtpv2_enc_t e;
        gtpv2_enc_init(&e, outbuf, sizeof(outbuf));
        gtpv2_enc_begin(&e, GTPV2_ECHO_RESPONSE, 0, v2->seq);
        uint8_t rec = 0;
        gtpv2_enc_tlv(&e, GTPV2_IE_RECOVERY, 0, &rec, 1);
        int total = gtpv2_enc_finish(&e);
        if (total > 0) iwf_send_v2(rt, outbuf, (size_t)total);
        return 0;
    }
    case GTPV2_ECHO_RESPONSE:
        return 0;
    default:
        LOGW("translate", "unhandled GTPv2 msg_type=%u", v2->msg_type);
        return -1;
    }
}
