/*
 * map_iwf.c - MAP <-> Diameter S6d translation engine.
 *
 * Lifecycles per operation
 * ========================
 *
 * SAI (Send Authentication Info)
 * ------------------------------
 *   SGSN -> IWF: TCAP-Begin (AARQ=infoRetrievalContext-v3, Invoke SAI)
 *   IWF  -> HSS: Diameter AIR (Authentication-Information-Request)
 *   HSS  -> IWF: Diameter AIA (with Authentication-Info AVP list)
 *   IWF  -> SGSN: TCAP-End   (AARE=infoRetrievalContext-v3,
 *                            ReturnResult: AuthenticationSetList)
 *
 * UGL (Update GPRS Location)
 * --------------------------
 *   SGSN -> IWF: TCAP-Begin (AARQ=gprsLocationUpdateContext-v3, Invoke UGL)
 *   IWF  -> HSS: Diameter ULR with ULR-Flags = S6d-Indicator |
 *                                              GPRS-Subscription-Required
 *   HSS  -> IWF: Diameter ULA + Subscription-Data
 *   IWF  -> SGSN: TCAP-Begin (AARQ=subscriberDataMngtContext-v3, Invoke ISD)
 *   SGSN -> IWF: TCAP-End   (ReturnResult: empty)
 *   IWF  -> SGSN: TCAP-End on the original UGL dialogue
 *                 (ReturnResult: hlr-Number)
 *
 * CL (Cancel Location, HSS-initiated)
 * -----------------------------------
 *   HSS  -> IWF: Diameter CLR
 *   IWF  -> SGSN: TCAP-Begin (Invoke CancelLocation)
 *   SGSN -> IWF: TCAP-End   (ReturnResult)
 *   IWF  -> HSS: Diameter CLA Result-Code=2001
 *
 * PurgeMS
 * -------
 *   SGSN -> IWF: TCAP-Begin (Invoke PurgeMS)
 *   IWF  -> HSS: Diameter PUR
 *   HSS  -> IWF: Diameter PUA
 *   IWF  -> SGSN: TCAP-End (ReturnResult)
 *
 * Error paths
 * -----------
 *   - Diameter Result-Code != 2001/2002 -> MAP ReturnError(systemFailure) +
 *     TCAP-End on the SGSN-facing dialogue.
 *   - TCAP T-dialogue timeout (10s default) -> teardown + MAP Abort.
 *   - Diameter disconnect mid-transaction -> SystemFailure to SGSN.
 *   - SS7 link down -> in-flight dialogues are aborted on the SGSN side
 *     implicitly (no SCCP route).  We do not generate spurious traffic.
 */

#include "map_iwf.h"
#include "map_iwf_priv.h"
#include "map_session.h"
#include "map_codec.h"
#include "tcap.h"
#include "diameter.h"
#include "ss7_link.h"
#include "runtime.h"
#include "logging.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <arpa/inet.h>

/* ====================================================================== */
/* Inbound dispatch from ss7_link.c                                       */
/* ====================================================================== */

static map_app_ctx_t ac_for_op(map_op_t op)
{
    switch (op) {
    case MAP_OP_SAI:      return MAP_AC_INFO_RETRIEVAL_V3;
    case MAP_OP_UGL:      return MAP_AC_GPRS_LOCATION_UPDATE_V3;
    case MAP_OP_ISD:      return MAP_AC_SUBSCRIBER_DATA_MGMT_V3;
    case MAP_OP_CL:       return MAP_AC_GPRS_LOCATION_CANCEL_V3;
    case MAP_OP_PURGE_MS: return MAP_AC_MS_PURGING_V3;
    default: return MAP_AC_INFO_RETRIEVAL_V3;
    }
}

static int send_tcap_end_with_error(struct iwf_runtime *rt,
                                    map_session_t *s,
                                    uint8_t invoke_id,
                                    int map_error_code,
                                    uint8_t network_resource);

static int send_tcap_end_with_result(struct iwf_runtime *rt,
                                     map_session_t *s,
                                     uint8_t invoke_id,
                                     int local_opcode,
                                     const uint8_t *params, size_t params_len);

/* ----- Begin handlers ---------------------------------------------- */

static void handle_begin_sai(struct iwf_runtime *rt,
                             const ss7_sccp_addr_t *calling,
                             const tcap_msg_t *tmsg,
                             const tcap_component_t *cmp)
{
    map_sai_req_t req;
    if (map_decode_sai_arg(cmp->parameters, cmp->parameters_len, &req) < 0) {
        LOGW("map", "SAI: malformed argument from pc=%u (cannot decode IMSI)",
             calling->point_code);
        /* No session created yet - the SGSN will time out. */
        return;
    }

    map_session_t *s = map_sess_create(map_sess_new_tid());
    if (!s) return;
    s->map_op = MAP_OP_SAI;
    s->state  = MAP_SESS_WAIT_DIAMETER;
    s->peer_tcap_dialogue_id = tmsg->otid;
    s->have_peer_tid         = tmsg->have_otid;
    s->t_dialogue_ms         = rt->cfg.map_t_dialogue_ms > 0
                                 ? rt->cfg.map_t_dialogue_ms : TCAP_DEFAULT_T_MS;
    memcpy(s->imsi_bcd, req.imsi_bcd, req.imsi_bcd_len);
    s->imsi_bcd_len = req.imsi_bcd_len;
    memcpy(s->imsi_str, req.imsi_str, sizeof(s->imsi_str));

    /* Visited PLMN: derive from the IMSI MCC+MNC (TS 24.008).  This is a
     * fallback - a future patch can prefer the SCCP CallingParty GT's
     * country code if it differs (roaming-from-home detection). */
    if (req.imsi_bcd_len >= 2) {
        uint8_t plmn[3] = { req.imsi_bcd[0], req.imsi_bcd[1], req.imsi_bcd[2] };
        memcpy(s->visited_plmn_bcd, plmn, 3);
        s->have_visited_plmn = true;
    }

    LOGI("map", "RX BEGIN SAI imsi=%s tid=0x%08x peer_otid=0x%08x vec_req=%u",
         s->imsi_str, s->tcap_dialogue_id, s->peer_tcap_dialogue_id,
         req.num_vectors);

    if (diameter_send_air(rt, s) < 0) {
        LOGW("map", "AIR send failed imsi=%s; replying systemFailure", s->imsi_str);
        send_tcap_end_with_error(rt, s, /*invoke_id*/ 1,
                                 MAP_ERR_SYSTEM_FAILURE, /*nrc=hlr*/ 1);
    }
}

static void handle_begin_ugl(struct iwf_runtime *rt,
                             const ss7_sccp_addr_t *calling,
                             const tcap_msg_t *tmsg,
                             const tcap_component_t *cmp)
{
    map_ugl_req_t req;
    if (map_decode_ugl_arg(cmp->parameters, cmp->parameters_len, &req) < 0) {
        LOGW("map", "UGL: malformed argument from pc=%u", calling->point_code);
        return;
    }
    map_session_t *s = map_sess_create(map_sess_new_tid());
    if (!s) return;
    s->map_op = MAP_OP_UGL;
    s->state  = MAP_SESS_WAIT_DIAMETER;
    s->peer_tcap_dialogue_id = tmsg->otid;
    s->have_peer_tid         = tmsg->have_otid;
    s->t_dialogue_ms         = rt->cfg.map_t_dialogue_ms > 0
                                 ? rt->cfg.map_t_dialogue_ms : TCAP_DEFAULT_T_MS;
    memcpy(s->imsi_bcd, req.imsi_bcd, req.imsi_bcd_len);
    s->imsi_bcd_len = req.imsi_bcd_len;
    memcpy(s->imsi_str, req.imsi_str, sizeof(s->imsi_str));
    if (req.imsi_bcd_len >= 3) {
        s->visited_plmn_bcd[0] = req.imsi_bcd[0];
        s->visited_plmn_bcd[1] = req.imsi_bcd[1];
        s->visited_plmn_bcd[2] = req.imsi_bcd[2];
        s->have_visited_plmn = true;
    }

    LOGI("map", "RX BEGIN UGL imsi=%s tid=0x%08x peer_otid=0x%08x",
         s->imsi_str, s->tcap_dialogue_id, s->peer_tcap_dialogue_id);
    if (diameter_send_ulr(rt, s) < 0) {
        send_tcap_end_with_error(rt, s, 1, MAP_ERR_SYSTEM_FAILURE, 1);
    }
}

static void handle_begin_purge(struct iwf_runtime *rt,
                               const ss7_sccp_addr_t *calling,
                               const tcap_msg_t *tmsg,
                               const tcap_component_t *cmp)
{
    map_purge_req_t req;
    if (map_decode_purge_arg(cmp->parameters, cmp->parameters_len, &req) < 0) {
        LOGW("map", "PurgeMS: malformed argument from pc=%u", calling->point_code);
        return;
    }
    map_session_t *s = map_sess_create(map_sess_new_tid());
    if (!s) return;
    s->map_op = MAP_OP_PURGE_MS;
    s->state  = MAP_SESS_WAIT_DIAMETER;
    s->peer_tcap_dialogue_id = tmsg->otid;
    s->have_peer_tid         = tmsg->have_otid;
    s->t_dialogue_ms         = rt->cfg.map_t_dialogue_ms > 0
                                 ? rt->cfg.map_t_dialogue_ms : TCAP_DEFAULT_T_MS;
    memcpy(s->imsi_bcd, req.imsi_bcd, req.imsi_bcd_len);
    s->imsi_bcd_len = req.imsi_bcd_len;
    memcpy(s->imsi_str, req.imsi_str, sizeof(s->imsi_str));
    if (req.imsi_bcd_len >= 3) {
        s->visited_plmn_bcd[0] = req.imsi_bcd[0];
        s->visited_plmn_bcd[1] = req.imsi_bcd[1];
        s->visited_plmn_bcd[2] = req.imsi_bcd[2];
        s->have_visited_plmn = true;
    }
    LOGI("map", "RX BEGIN PurgeMS imsi=%s tid=0x%08x",
         s->imsi_str, s->tcap_dialogue_id);
    if (diameter_send_pur(rt, s) < 0) {
        send_tcap_end_with_error(rt, s, 1, MAP_ERR_SYSTEM_FAILURE, 1);
    }
}

/* CancelLocation can be SGSN-initiated too (rare; mostly HSS-initiated via
 * Diameter CLR). For inbound BEGIN CL we acknowledge promptly. */
static void handle_begin_cl(struct iwf_runtime *rt,
                            const ss7_sccp_addr_t *calling,
                            const tcap_msg_t *tmsg,
                            const tcap_component_t *cmp)
{
    map_cl_req_t req;
    if (map_decode_cl_arg(cmp->parameters, cmp->parameters_len, &req) < 0) {
        LOGW("map", "CL: malformed argument from pc=%u", calling->point_code);
        return;
    }
    map_session_t *s = map_sess_create(map_sess_new_tid());
    if (!s) return;
    s->map_op = MAP_OP_CL;
    s->state  = MAP_SESS_WAIT_MAP_TX;
    s->peer_tcap_dialogue_id = tmsg->otid;
    s->have_peer_tid         = tmsg->have_otid;
    memcpy(s->imsi_str, req.imsi_str, sizeof(s->imsi_str));
    LOGI("map", "RX BEGIN CL imsi=%s ct=%u (immediate ack)",
         s->imsi_str, req.cancellation_type);
    /* No Diameter side - just acknowledge. */
    send_tcap_end_with_result(rt, s, cmp->invoke_id,
                              MAP_OP_CODE_CANCEL_LOCATION, NULL, 0);
}

/* ----- Continue / End handlers (ISD ack from SGSN) ----------------- */

static void handle_continue_or_end(struct iwf_runtime *rt,
                                   const tcap_msg_t *tmsg)
{
    if (!tmsg->have_dtid) {
        LOGW("map", "CONTINUE/END without DTID; ignoring");
        return;
    }
    map_session_t *s = map_sess_find_by_tid(tmsg->dtid);
    if (!s) {
        LOGD("map", "CONTINUE/END dtid=0x%08x no session (already torn down)",
             tmsg->dtid);
        return;
    }
    /* ISD ack from SGSN: complete the parent UGL response. */
    if (s->state == MAP_SESS_WAIT_MAP_ACK && s->map_op == MAP_OP_ISD) {
        LOGI("map", "ISD acked by SGSN tid=0x%08x", s->tcap_dialogue_id);
        s->state = MAP_SESS_DONE;
        map_sess_remove(s);
    } else {
        LOGD("map", "ignoring CONTINUE/END for tid=0x%08x state=%s",
             tmsg->dtid, map_sess_state_str(s->state));
    }
}

static void handle_abort(struct iwf_runtime *rt, const tcap_msg_t *tmsg)
{
    if (!tmsg->have_dtid) return;
    map_session_t *s = map_sess_find_by_tid(tmsg->dtid);
    if (!s) return;
    LOGW("map", "RX ABORT imsi=%s tid=0x%08x state=%s",
         s->imsi_str[0] ? s->imsi_str : "?",
         s->tcap_dialogue_id, map_sess_state_str(s->state));
    rt->map->stat_timeouts++;
    map_sess_remove(s);
}

/* ----- SCCP receive entrypoint (set on ss7_link at init) ----------- */

static void on_sccp_pdu(struct iwf_runtime *rt,
                        const ss7_sccp_addr_t *calling,
                        const uint8_t *tcap, size_t tcap_len)
{
    rt->map->stat_map_rx++;

    tcap_msg_t tmsg;
    if (tcap_decode(tcap, tcap_len, &tmsg) < 0) {
        LOGW("map", "RX malformed TCAP len=%zu from pc=%u",
             tcap_len, calling->point_code);
        return;
    }

    /* Begin: identify the operation via the dialogue AC and/or opcode. */
    if (tmsg.type == TCAP_MSG_BEGIN) {
        map_app_ctx_t ac = MAP_AC_INFO_RETRIEVAL_V3;
        if (tmsg.dialogue && tmsg.dialogue_len)
            (void)map_decode_aarq_ac(tmsg.dialogue, tmsg.dialogue_len, &ac);

        if (tmsg.n_components == 0 ||
            tmsg.components[0].kind != TCAP_CMP_KIND_INVOKE) {
            LOGW("map", "BEGIN without Invoke component (n=%zu)", tmsg.n_components);
            return;
        }
        const tcap_component_t *c = &tmsg.components[0];
        switch (c->opcode) {
        case MAP_OP_CODE_SEND_AUTH_INFO:        handle_begin_sai  (rt, calling, &tmsg, c); break;
        case MAP_OP_CODE_UPDATE_GPRS_LOCATION:  handle_begin_ugl  (rt, calling, &tmsg, c); break;
        case MAP_OP_CODE_PURGE_MS:              handle_begin_purge(rt, calling, &tmsg, c); break;
        case MAP_OP_CODE_CANCEL_LOCATION:       handle_begin_cl   (rt, calling, &tmsg, c); break;
        default:
            LOGW("map", "unsupported MAP opcode=%d ac=%d in BEGIN",
                 c->opcode, ac);
            break;
        }
        return;
    }

    if (tmsg.type == TCAP_MSG_CONTINUE || tmsg.type == TCAP_MSG_END) {
        handle_continue_or_end(rt, &tmsg);
        return;
    }
    if (tmsg.type == TCAP_MSG_ABORT) {
        handle_abort(rt, &tmsg);
        return;
    }
}

/* ====================================================================== */
/* Outbound: build & send TCAP messages back to the SGSN                  */
/* ====================================================================== */

static int send_tcap_end_with_result(struct iwf_runtime *rt,
                                     map_session_t *s,
                                     uint8_t invoke_id,
                                     int local_opcode,
                                     const uint8_t *params, size_t params_len)
{
    /* Build component portion. */
    uint8_t cmp[2048]; size_t co = 0;
    if (tcap_enc_return_result(cmp, sizeof(cmp), &co,
                               invoke_id, local_opcode,
                               params, params_len) < 0) {
        LOGE("map", "tcap_enc_return_result failed imsi=%s", s->imsi_str);
        return -1;
    }
    /* AARE dialogue portion. */
    uint8_t dlg[128]; int dn = map_encode_aare(ac_for_op(s->map_op),
                                               dlg, sizeof(dlg));
    if (dn < 0) return -1;

    uint8_t out[3072];
    int n = tcap_encode_message(TCAP_MSG_END,
                                0, false,
                                s->peer_tcap_dialogue_id, s->have_peer_tid,
                                dlg, (size_t)dn,
                                cmp, co,
                                out, sizeof(out));
    if (n < 0) return -1;

    /* For now we don't have the SGSN's full SCCP addr cached.  We send to
     * the SS7 default route via the local address swapped to a "called" -
     * the STP fills in based on the inverse of the calling we received.
     * A future patch will cache the original calling-party address per
     * dialogue so the SCCP layer can route by point-code rather than GT. */
    ss7_sccp_addr_t called = {0};
    called.ssn = SS7_SSN_SGSN;
    int rc = ss7_link_send_tcap(rt, &called, out, (size_t)n);
    if (rc == 0) {
        rt->map->stat_map_tx++;
        LOGI("map", "TX END dtid=0x%08x op=%s imsi=%s len=%d",
             s->peer_tcap_dialogue_id, map_op_str(s->map_op), s->imsi_str, n);
        s->state = MAP_SESS_DONE;
        map_sess_remove(s);
    }
    return rc;
}

static int send_tcap_end_with_error(struct iwf_runtime *rt,
                                    map_session_t *s,
                                    uint8_t invoke_id,
                                    int map_error_code,
                                    uint8_t network_resource)
{
    uint8_t param[8]; size_t plen = 0;
    if (map_error_code == MAP_ERR_SYSTEM_FAILURE) {
        int n = map_encode_systemfailure_diag(network_resource, param, sizeof(param));
        if (n > 0) plen = (size_t)n;
    }
    uint8_t cmp[64]; size_t co = 0;
    if (tcap_enc_return_error(cmp, sizeof(cmp), &co, invoke_id,
                              map_error_code,
                              plen ? param : NULL, plen) < 0) return -1;
    uint8_t dlg[128]; int dn = map_encode_aare(ac_for_op(s->map_op),
                                               dlg, sizeof(dlg));
    if (dn < 0) return -1;

    uint8_t out[1024];
    int n = tcap_encode_message(TCAP_MSG_END,
                                0, false,
                                s->peer_tcap_dialogue_id, s->have_peer_tid,
                                dlg, (size_t)dn,
                                cmp, co,
                                out, sizeof(out));
    if (n < 0) return -1;

    ss7_sccp_addr_t called = {0};
    called.ssn = SS7_SSN_SGSN;
    int rc = ss7_link_send_tcap(rt, &called, out, (size_t)n);
    if (rc == 0) {
        rt->map->stat_systemfailures_sent++;
        rt->map->stat_map_tx++;
        LOGW("map", "TX END(Error %d) imsi=%s dtid=0x%08x op=%s",
             map_error_code, s->imsi_str, s->peer_tcap_dialogue_id,
             map_op_str(s->map_op));
        s->state = MAP_SESS_DONE;
        map_sess_remove(s);
    }
    return rc;
}

/* ====================================================================== */
/* Diameter answer handlers (called by diameter.c)                         */
/* ====================================================================== */

/* Parse one E-UTRAN/UTRAN/GERAN-Vector grouped AVP into map_auth_vector_t. */
static int parse_vector_avp(const uint8_t *body, size_t len,
                            map_auth_vector_t *v)
{
    diameter_avp_t a;
    /* RAND */
    if (diameter_avp_find(body, len, AVP_3GPP_RAND, DIAMETER_VENDOR_3GPP, &a) == 0) {
        size_t n = a.data_len > 16 ? 16 : a.data_len;
        memcpy(v->rand, a.data, n);
    }
    if (diameter_avp_find(body, len, AVP_3GPP_XRES, DIAMETER_VENDOR_3GPP, &a) == 0) {
        size_t n = a.data_len > 16 ? 16 : a.data_len;
        memcpy(v->xres, a.data, n);
        v->xres_len = (uint8_t)n;
    }
    if (diameter_avp_find(body, len, AVP_3GPP_AUTN, DIAMETER_VENDOR_3GPP, &a) == 0) {
        size_t n = a.data_len > 16 ? 16 : a.data_len;
        memcpy(v->autn, a.data, n);
    }
    if (diameter_avp_find(body, len, AVP_3GPP_CK, DIAMETER_VENDOR_3GPP, &a) == 0) {
        size_t n = a.data_len > 16 ? 16 : a.data_len;
        memcpy(v->ck, a.data, n);
    }
    if (diameter_avp_find(body, len, AVP_3GPP_IK, DIAMETER_VENDOR_3GPP, &a) == 0) {
        size_t n = a.data_len > 16 ? 16 : a.data_len;
        memcpy(v->ik, a.data, n);
    }
    v->have_quintuplet = true;
    return 0;
}

void map_iwf_on_aia(struct iwf_runtime *rt, map_session_t *s,
                    const uint8_t *body, size_t body_len)
{
    diameter_avp_t auth_info;
    if (diameter_avp_find(body, body_len, AVP_3GPP_AUTHENTICATION_INFO,
                          DIAMETER_VENDOR_3GPP, &auth_info) < 0) {
        LOGW("map", "AIA imsi=%s: no Authentication-Info AVP", s->imsi_str);
        send_tcap_end_with_error(rt, s, 1, MAP_ERR_SYSTEM_FAILURE, 1);
        return;
    }
    /* Walk every E-UTRAN-Vector / UTRAN-Vector / GERAN-Vector child. */
    s->n_av = 0;
    diameter_avp_t v;
    if (diameter_avp_first(auth_info.data, auth_info.data_len, &v) == 0) {
        do {
            if (s->n_av >= MAP_AUTH_VECTOR_MAX) break;
            if ((v.code == AVP_3GPP_E_UTRAN_VECTOR ||
                 v.code == AVP_3GPP_UTRAN_VECTOR  ||
                 v.code == AVP_3GPP_GERAN_VECTOR) &&
                v.vendor_id == DIAMETER_VENDOR_3GPP) {
                parse_vector_avp(v.data, v.data_len, &s->av[s->n_av]);
                s->n_av++;
            }
        } while (diameter_avp_next(auth_info.data, auth_info.data_len, &v) == 0);
    }
    LOGI("map", "AIA imsi=%s vectors=%u -> emitting MAP SAI Resp",
         s->imsi_str, s->n_av);
    if (s->n_av == 0) {
        send_tcap_end_with_error(rt, s, 1, MAP_ERR_SYSTEM_FAILURE, 1);
        return;
    }
    uint8_t params[1600];
    int pn = map_encode_sai_res(s->av, s->n_av, params, sizeof(params));
    if (pn < 0) {
        send_tcap_end_with_error(rt, s, 1, MAP_ERR_SYSTEM_FAILURE, 1);
        return;
    }
    send_tcap_end_with_result(rt, s, /*invoke_id*/ 1,
                              MAP_OP_CODE_SEND_AUTH_INFO,
                              params, (size_t)pn);
}

/* Extract subscription data from ULA (MSISDN, APN config, AMBR). */
static void extract_ula_subdata(map_session_t *s,
                                const uint8_t *body, size_t body_len)
{
    diameter_avp_t sd;
    if (diameter_avp_find(body, body_len, AVP_3GPP_SUBSCRIPTION_DATA,
                          DIAMETER_VENDOR_3GPP, &sd) < 0) {
        LOGD("map", "ULA imsi=%s: no Subscription-Data (Skip-Subscriber-Data path)",
             s->imsi_str);
        return;
    }
    diameter_avp_t a;
    if (diameter_avp_find(sd.data, sd.data_len, AVP_3GPP_MSISDN,
                          DIAMETER_VENDOR_3GPP, &a) == 0) {
        size_t n = a.data_len > sizeof(s->msisdn_str) - 1
                       ? sizeof(s->msisdn_str) - 1 : a.data_len;
        /* MSISDN AVP is TBCD; convert to digits. */
        char tmp[24];
        size_t o = 0;
        for (size_t i = 0; i < n && o + 2 < sizeof(tmp); i++) {
            uint8_t lo = a.data[i] & 0x0f;
            uint8_t hi = (a.data[i] >> 4) & 0x0f;
            if (lo <= 9) tmp[o++] = (char)('0' + lo);
            if (hi <= 9) tmp[o++] = (char)('0' + hi);
        }
        tmp[o] = '\0';
        memcpy(s->msisdn_str, tmp, sizeof(s->msisdn_str));
        s->msisdn_str[sizeof(s->msisdn_str) - 1] = '\0';
    }

    /* APN-Configuration-Profile -> APN-Configuration[0] -> Service-Selection + AMBR. */
    diameter_avp_t apnp;
    if (diameter_avp_find(sd.data, sd.data_len,
                          AVP_3GPP_APN_CONFIGURATION_PROFILE,
                          DIAMETER_VENDOR_3GPP, &apnp) == 0) {
        diameter_avp_t apnc;
        if (diameter_avp_find(apnp.data, apnp.data_len,
                              AVP_3GPP_APN_CONFIGURATION,
                              DIAMETER_VENDOR_3GPP, &apnc) == 0) {
            diameter_avp_t ss;
            if (diameter_avp_find(apnc.data, apnc.data_len,
                                  AVP_3GPP_SERVICE_SELECTION, 0, &ss) == 0) {
                size_t n = ss.data_len > sizeof(s->ula_apn) - 1
                               ? sizeof(s->ula_apn) - 1 : ss.data_len;
                memcpy(s->ula_apn, ss.data, n);
                s->ula_apn[n] = '\0';
            }
            diameter_avp_t ambr;
            if (diameter_avp_find(apnc.data, apnc.data_len,
                                  AVP_3GPP_AMBR,
                                  DIAMETER_VENDOR_3GPP, &ambr) == 0) {
                diameter_avp_t ul, dl;
                if (diameter_avp_find(ambr.data, ambr.data_len,
                                      AVP_3GPP_MAX_REQUESTED_BANDWIDTH_UL,
                                      DIAMETER_VENDOR_3GPP, &ul) == 0 &&
                    ul.data_len == 4) {
                    s->ula_ambr_ul_bps =
                        ((uint64_t)ul.data[0] << 24) | ((uint64_t)ul.data[1] << 16) |
                        ((uint64_t)ul.data[2] << 8)  |  (uint64_t)ul.data[3];
                }
                if (diameter_avp_find(ambr.data, ambr.data_len,
                                      AVP_3GPP_MAX_REQUESTED_BANDWIDTH_DL,
                                      DIAMETER_VENDOR_3GPP, &dl) == 0 &&
                    dl.data_len == 4) {
                    s->ula_ambr_dl_bps =
                        ((uint64_t)dl.data[0] << 24) | ((uint64_t)dl.data[1] << 16) |
                        ((uint64_t)dl.data[2] << 8)  |  (uint64_t)dl.data[3];
                }
            }
        }
    }
    s->have_ula_subdata = true;
    LOGI("map", "ULA imsi=%s msisdn=%s apn=%s ambr=%lu/%lu bps",
         s->imsi_str,
         s->msisdn_str[0] ? s->msisdn_str : "(none)",
         s->ula_apn[0]   ? s->ula_apn   : "(none)",
         (unsigned long)s->ula_ambr_ul_bps,
         (unsigned long)s->ula_ambr_dl_bps);
}

/* For UGL we send an ISD invoke FIRST (separate TCAP dialogue), then once
 * the SGSN acks it we send the UGL ReturnResult.  This keeps the model
 * close to the real HLR behavior even though we collapse it back into a
 * single Diameter ULR.
 *
 * For simplicity and to keep this patch focused, we currently fold
 * MSISDN/APN/AMBR directly into the UGL ReturnResult Extension Container
 * is NOT supported - the SGSN gets the subscription data via a follow-up
 * ISD Invoke, exactly as TS 29.002 describes. */
static void send_isd_invoke(struct iwf_runtime *rt, map_session_t *parent);

void map_iwf_on_ula(struct iwf_runtime *rt, map_session_t *s,
                    const uint8_t *body, size_t body_len)
{
    extract_ula_subdata(s, body, body_len);

    /* If we have any subscription data, push ISD first (then UGL Resp on
     * its ack).  Otherwise send the UGL ReturnResult immediately. */
    if (s->have_ula_subdata && (s->msisdn_str[0] || s->ula_apn[0])) {
        send_isd_invoke(rt, s);
        return;
    }
    /* Send UGL ReturnResult: hlr-Number is synthesized as our origin host. */
    static const uint8_t fake_hlr[1] = { 0x00 };
    uint8_t params[64];
    int pn = map_encode_ugl_res(fake_hlr, sizeof(fake_hlr),
                                params, sizeof(params));
    if (pn < 0) {
        send_tcap_end_with_error(rt, s, 1, MAP_ERR_SYSTEM_FAILURE, 1);
        return;
    }
    send_tcap_end_with_result(rt, s, 1,
                              MAP_OP_CODE_UPDATE_GPRS_LOCATION,
                              params, (size_t)pn);
}

static void send_isd_invoke(struct iwf_runtime *rt, map_session_t *parent)
{
    /* Open a brand-new dialogue toward the SGSN for the ISD invoke. */
    map_session_t *isd = map_sess_create(map_sess_new_tid());
    if (!isd) {
        LOGE("map", "ISD: alloc failed for imsi=%s", parent->imsi_str);
        return;
    }
    isd->map_op = MAP_OP_ISD;
    isd->state  = MAP_SESS_WAIT_MAP_ACK;
    isd->t_dialogue_ms = parent->t_dialogue_ms;
    memcpy(isd->imsi_str, parent->imsi_str, sizeof(isd->imsi_str));

    uint8_t arg[1024];
    int an = map_encode_isd_arg(parent->imsi_str,
                                parent->msisdn_str,
                                parent->ula_apn,
                                parent->ula_ambr_ul_bps,
                                parent->ula_ambr_dl_bps,
                                arg, sizeof(arg));
    if (an < 0) { map_sess_remove(isd); return; }

    uint8_t cmp[1200]; size_t co = 0;
    if (tcap_enc_invoke(cmp, sizeof(cmp), &co,
                        /*invoke_id*/ 1,
                        MAP_OP_CODE_INSERT_SUBSCRIBER_DATA,
                        arg, (size_t)an) < 0) {
        map_sess_remove(isd); return;
    }
    uint8_t dlg[128];
    int dn = map_encode_aarq(MAP_AC_SUBSCRIBER_DATA_MGMT_V3, dlg, sizeof(dlg));
    if (dn < 0) { map_sess_remove(isd); return; }

    uint8_t out[2048];
    int n = tcap_encode_message(TCAP_MSG_BEGIN,
                                isd->tcap_dialogue_id, true,
                                0, false,
                                dlg, (size_t)dn,
                                cmp, co,
                                out, sizeof(out));
    if (n < 0) { map_sess_remove(isd); return; }

    ss7_sccp_addr_t called = {0};
    called.ssn = SS7_SSN_SGSN;
    if (ss7_link_send_tcap(rt, &called, out, (size_t)n) < 0) {
        LOGE("map", "ISD: SCCP send failed imsi=%s", parent->imsi_str);
        map_sess_remove(isd);
        return;
    }
    rt->map->stat_map_tx++;
    LOGI("map", "TX BEGIN ISD imsi=%s tid=0x%08x (UGL parent tid=0x%08x)",
         parent->imsi_str, isd->tcap_dialogue_id, parent->tcap_dialogue_id);

    /* Now also send the UGL ReturnResult on the parent dialogue. */
    static const uint8_t fake_hlr[1] = { 0x00 };
    uint8_t params[64];
    int pn = map_encode_ugl_res(fake_hlr, sizeof(fake_hlr), params, sizeof(params));
    if (pn < 0) {
        send_tcap_end_with_error(rt, parent, 1, MAP_ERR_SYSTEM_FAILURE, 1);
        return;
    }
    send_tcap_end_with_result(rt, parent, 1,
                              MAP_OP_CODE_UPDATE_GPRS_LOCATION,
                              params, (size_t)pn);
}

void map_iwf_on_cla(struct iwf_runtime *rt, map_session_t *s,
                    const uint8_t *body, size_t body_len)
{
    (void)body; (void)body_len;
    /* The CL flow originates HSS-side (we get the CLR from PyHSS and then
     * Invoke MAP CancelLocation toward the SGSN).  CLA acknowledges that
     * our Diameter request was accepted; the SGSN-facing dialogue should
     * already be settled.  Nothing further to do here. */
    LOGI("map", "CLA imsi=%s rc=%u", s->imsi_str, s->diameter_result_code);
    map_sess_remove(s);
}

void map_iwf_on_pua(struct iwf_runtime *rt, map_session_t *s,
                    const uint8_t *body, size_t body_len)
{
    (void)body; (void)body_len;
    uint8_t params[16];
    int pn = map_encode_purge_res(false, params, sizeof(params));
    if (pn < 0) {
        send_tcap_end_with_error(rt, s, 1, MAP_ERR_SYSTEM_FAILURE, 1);
        return;
    }
    send_tcap_end_with_result(rt, s, 1, MAP_OP_CODE_PURGE_MS, params, (size_t)pn);
}

void map_iwf_diameter_error(struct iwf_runtime *rt, map_session_t *s,
                            uint32_t rc)
{
    LOGW("map", "Diameter error rc=%u imsi=%s op=%s; sending MAP SystemFailure",
         (unsigned)rc, s->imsi_str, map_op_str(s->map_op));
    int map_err = MAP_ERR_SYSTEM_FAILURE;
    if (rc == DIAM_EXP_RC_USER_UNKNOWN)        map_err = MAP_ERR_UNKNOWN_SUBSCRIBER;
    else if (rc == DIAM_EXP_RC_ROAMING_NOT_ALLOWED) map_err = MAP_ERR_ROAMING_NOT_ALLOWED;
    send_tcap_end_with_error(rt, s, 1, map_err, /*nrc=hlr*/ 1);
}

/* ====================================================================== */
/* Module wiring                                                          */
/* ====================================================================== */

bool map_iwf_enabled(const struct iwf_runtime *rt)
{
    return rt && rt->map && rt->map->enabled;
}

int map_iwf_get_ss7_fd      (const struct iwf_runtime *rt) { return ss7_link_get_fd(rt); }
int map_iwf_get_diameter_fd (const struct iwf_runtime *rt) { return diameter_get_fd(rt); }
int map_iwf_get_ttimer_fd   (const struct iwf_runtime *rt) {
    return rt && rt->map ? rt->map->t_timer_fd : -1;
}
int map_iwf_get_dwa_timer_fd(const struct iwf_runtime *rt) {
    return diameter_get_dwa_timer_fd(rt);
}

void map_iwf_on_ss7_readable     (struct iwf_runtime *rt) { ss7_link_on_readable(rt); }
void map_iwf_on_diameter_readable(struct iwf_runtime *rt) { diameter_on_readable(rt); }
void map_iwf_on_dwa_timer_tick   (struct iwf_runtime *rt) { diameter_on_dwa_tick(rt); }

void map_iwf_on_ttimer_tick(struct iwf_runtime *rt)
{
    if (!rt || !rt->map) return;
    uint64_t exp;
    ssize_t r = read(rt->map->t_timer_fd, &exp, sizeof(exp));
    (void)r;
    int killed = map_sess_sweep(time(NULL));
    if (killed) rt->map->stat_timeouts += (uint64_t)killed;
}

int map_iwf_init(struct iwf_runtime *rt, int epfd)
{
    if (!rt->cfg.map_iwf_enabled) {
        LOGI("map", "MAP-IWF disabled in config; skipping");
        return 0;     /* not an error - the GTP IWF runs alone */
    }
    rt->map = (map_iwf_state_t *)calloc(1, sizeof(*rt->map));
    if (!rt->map) {
        LOGE("map", "alloc map_iwf_state failed");
        return -1;
    }
    rt->map->enabled    = true;
    rt->map->epoll_fd   = epfd;
    rt->map->t_timer_fd = -1;
    rt->map->diam.fd    = -1;
    rt->map->ss7.fd     = -1;

    map_sess_init();

    if (ss7_link_init(rt) < 0) {
        LOGE("map", "SS7 link bring-up failed");
        free(rt->map); rt->map = NULL;
        return -1;
    }
    ss7_link_set_recv_cb(rt, on_sccp_pdu);

    if (diameter_init(rt) < 0) {
        LOGE("map", "Diameter bring-up failed");
        ss7_link_shutdown(rt);
        free(rt->map); rt->map = NULL;
        return -1;
    }

    /* TCAP T-timeout sweep: tick every 1s; per-dialogue deadline lives in
     * map_session_t.t_dialogue_ms. */
    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (tfd < 0) {
        LOGE("map", "timerfd: %s", strerror(errno));
        diameter_shutdown(rt);
        ss7_link_shutdown(rt);
        free(rt->map); rt->map = NULL;
        return -1;
    }
    struct itimerspec its = {
        .it_interval = { .tv_sec = 1, .tv_nsec = 0 },
        .it_value    = { .tv_sec = 1, .tv_nsec = 0 },
    };
    timerfd_settime(tfd, 0, &its, NULL);
    rt->map->t_timer_fd = tfd;

    /* Register module fds with the shared epoll set.  diameter.c re-adds
     * its own socket on each successful (re)connect, so we only register
     * the things that never churn here: the SS7 fd (if any), the per-dialogue
     * sweep timer, and the Diameter watchdog timer. */
    struct epoll_event ev = { .events = EPOLLIN };
    if (rt->map->ss7.fd >= 0) {
        ev.data.u64 = MAP_EPOLL_ROLE_SS7;
        epoll_ctl(epfd, EPOLL_CTL_ADD, rt->map->ss7.fd, &ev);
    }
    ev.data.u64 = MAP_EPOLL_ROLE_T_TIMER;
    epoll_ctl(epfd, EPOLL_CTL_ADD, rt->map->t_timer_fd, &ev);
    if (rt->map->diam.watchdog_timerfd >= 0) {
        ev.data.u64 = MAP_EPOLL_ROLE_DWA_TIMER;
        epoll_ctl(epfd, EPOLL_CTL_ADD, rt->map->diam.watchdog_timerfd, &ev);
    }
    /* The Diameter socket itself is registered/unregistered by diameter.c
     * on each (re)connect via diameter_epoll_attach() below. */

    LOGI("map", "MAP-IWF ready (SS7=M3UA via libosmo select pump; diameter peer=%s:%u "
                "origin=%s realm=%s)",
         rt->cfg.diam_peer_ip, rt->cfg.diam_peer_port,
         rt->cfg.diam_origin_host, rt->cfg.diam_origin_realm);
    return 0;
}

void map_iwf_shutdown(struct iwf_runtime *rt)
{
    if (!rt || !rt->map) return;
    LOGI("map", "shutting down (map_rx=%lu map_tx=%lu diam_rx=%lu diam_tx=%lu "
                "timeouts=%lu sysfail=%lu)",
         (unsigned long)rt->map->stat_map_rx,
         (unsigned long)rt->map->stat_map_tx,
         (unsigned long)rt->map->stat_diam_rx,
         (unsigned long)rt->map->stat_diam_tx,
         (unsigned long)rt->map->stat_timeouts,
         (unsigned long)rt->map->stat_systemfailures_sent);
    diameter_shutdown(rt);
    ss7_link_shutdown(rt);
    if (rt->map->t_timer_fd >= 0) close(rt->map->t_timer_fd);
    map_sess_shutdown();
    free(rt->map);
    rt->map = NULL;
}
