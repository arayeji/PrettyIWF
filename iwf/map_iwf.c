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
#include "test_cmd.h"
#ifdef GSUP_PROXY_ENABLED
#include "gsup_map_proxy.h"
#include "gsup_proto.h"
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
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

/* UNIX / SIGUSR1 test session: never send TCAP toward SS7; use cmd_test_abort. */
static void cmd_test_abort(map_session_t *s, const char *reason)
{
    if (!s || !s->cmd_test) return;
    const char *r = reason ? reason : "abort";
    if (s->cmd_test_reply_fd >= 0) {
        test_cmd_reply_err(s->cmd_test_reply_fd, r);
        close(s->cmd_test_reply_fd);
        s->cmd_test_reply_fd = -1;
    } else {
        LOGW("map", "cmd-test SAI failed imsi=%s: %s",
             s->imsi_str[0] ? s->imsi_str : "?", r);
    }
    s->cmd_test = false;
    map_sess_remove(s);
}

static void map_sess_timeout_hook_cmd(map_session_t *s, void *hook_ctx)
{
    (void)hook_ctx;
    if (!s || !s->cmd_test) {
#ifdef GSUP_PROXY_ENABLED
        if (s && s->gsup_originated && hook_ctx) {
            gsup_map_proxy_on_timeout((struct iwf_runtime *)hook_ctx, s);
        }
#endif
        return;
    }
    if (s->cmd_test_reply_fd >= 0) {
        test_cmd_reply_err(s->cmd_test_reply_fd, "timeout");
        close(s->cmd_test_reply_fd);
        s->cmd_test_reply_fd = -1;
    }
    s->cmd_test = false;
}

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
    if (map_plmn_pack_home(rt->cfg.gsup_local_mnc, s->visited_plmn_bcd) == 0)
        s->have_visited_plmn = true;

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
    if (map_plmn_pack_home(rt->cfg.gsup_local_mnc, s->visited_plmn_bcd) == 0)
        s->have_visited_plmn = true;

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
    if (map_plmn_pack_home(rt->cfg.gsup_local_mnc, s->visited_plmn_bcd) == 0)
        s->have_visited_plmn = true;
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
#ifdef GSUP_PROXY_ENABLED
        if (gsup_map_proxy_on_tcap(rt, calling, &tmsg))
            return;
#endif
        handle_continue_or_end(rt, &tmsg);
        return;
    }
    if (tmsg.type == TCAP_MSG_ABORT) {
#ifdef GSUP_PROXY_ENABLED
        if (gsup_map_proxy_on_tcap(rt, calling, &tmsg))
            return;
#endif
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
    if (s->cmd_test) {
        cmd_test_abort(s, "unexpected_tcap_result");
        return -1;
    }
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
    if (s->cmd_test) {
        cmd_test_abort(s, "map_failure");
        return 0;
    }
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
    const bool is_cmd_test = s->cmd_test;

    diameter_avp_t auth_info;
    if (diameter_avp_find(body, body_len, AVP_3GPP_AUTHENTICATION_INFO,
                          DIAMETER_VENDOR_3GPP, &auth_info) < 0) {
        LOGW("map", "AIA imsi=%s: no Authentication-Info AVP", s->imsi_str);
        if (is_cmd_test) {
            cmd_test_abort(s, "no_authentication_info_avp");
            return;
        }
        if (s->gsup_originated) {
#ifdef GSUP_PROXY_ENABLED
            gsup_map_proxy_diameter_error(rt, s, 0);
#endif
            return;
        }
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

    if (is_cmd_test) {
        if (s->n_av == 0) {
            cmd_test_abort(s, "no_vectors");
            return;
        }
        int fd = s->cmd_test_reply_fd;
        s->cmd_test_reply_fd = -1;
        s->cmd_test = false;
        if (fd >= 0) {
            test_cmd_reply_ok(fd, (unsigned)s->n_av,
                              s->av[0].rand, s->av[0].autn);
            close(fd);
        } else {
            LOGI("map", "cmd-test SAI OK imsi=%s vectors=%u",
                 s->imsi_str, (unsigned)s->n_av);
        }
        map_sess_remove(s);
        return;
    }

    if (s->n_av == 0) {
        if (s->gsup_originated) {
#ifdef GSUP_PROXY_ENABLED
            gsup_map_proxy_diameter_error(rt, s, 0);
#endif
            return;
        }
        send_tcap_end_with_error(rt, s, 1, MAP_ERR_SYSTEM_FAILURE, 1);
        return;
    }
    if (s->gsup_originated) {
#ifdef GSUP_PROXY_ENABLED
        gsup_map_proxy_finish_sai(rt, s);
#endif
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
static int ula_add_apn_entry(map_session_t *s, const diameter_avp_t *apnc)
{
    if (!s || !apnc || s->n_ula_apns >= MAP_MAX_ULA_APN)
        return -1;

    diameter_avp_t ss;
    if (diameter_avp_find(apnc->data, apnc->data_len,
                          AVP_3GPP_SERVICE_SELECTION, 0, &ss) != 0)
        return -1;

    map_ula_apn_entry_t *e = &s->ula_apns[s->n_ula_apns];
    memset(e, 0, sizeof(*e));

    size_t n = ss.data_len > sizeof(e->apn) - 1
                   ? sizeof(e->apn) - 1 : ss.data_len;
    memcpy(e->apn, ss.data, n);
    e->apn[n] = '\0';
    iwf_apn_normalize(e->apn);
    if (!e->apn[0])
        return -1;

    diameter_avp_t ctx;
    if (diameter_avp_find(apnc->data, apnc->data_len,
                          AVP_3GPP_CONTEXT_IDENTIFIER,
                          DIAMETER_VENDOR_3GPP, &ctx) == 0 &&
        ctx.data_len >= 4) {
        e->context_id = (uint8_t)iwf_be32(ctx.data);
    } else {
        e->context_id = (uint8_t)(s->n_ula_apns + 1);
    }

    /* PyHSS ip_version: 0=IPv4, 1=IPv6, 2=IPv4v6 → TS 29.060 PDP type numbers. */
    diameter_avp_t pdn;
    if (diameter_avp_find(apnc->data, apnc->data_len,
                          AVP_3GPP_PDN_TYPE, DIAMETER_VENDOR_3GPP, &pdn) == 0 &&
        pdn.data_len >= 4) {
        uint32_t iv = iwf_be32(pdn.data);
        if (iv == 1)
            e->pdn_type_nr = GTPV1_PDP_TYPE_IPV6;
        else if (iv == 2)
            e->pdn_type_nr = GTPV1_PDP_TYPE_IPV4V6;
        else
            e->pdn_type_nr = GTPV1_PDP_TYPE_IPV4;
    } else {
        e->pdn_type_nr = GTPV1_PDP_TYPE_IPV4;
    }

    diameter_avp_t ambr;
    if (diameter_avp_find(apnc->data, apnc->data_len,
                          AVP_3GPP_AMBR, DIAMETER_VENDOR_3GPP, &ambr) == 0) {
        diameter_avp_t ul, dl;
        if (diameter_avp_find(ambr.data, ambr.data_len,
                              AVP_3GPP_MAX_REQUESTED_BANDWIDTH_UL,
                              DIAMETER_VENDOR_3GPP, &ul) == 0 &&
            ul.data_len == 4)
            e->ambr_ul_kbps = iwf_be32(ul.data);
        if (diameter_avp_find(ambr.data, ambr.data_len,
                              AVP_3GPP_MAX_REQUESTED_BANDWIDTH_DL,
                              DIAMETER_VENDOR_3GPP, &dl) == 0 &&
            dl.data_len == 4)
            e->ambr_dl_kbps = iwf_be32(dl.data);
    }

    s->n_ula_apns++;
    return 0;
}

static void decode_ula_msisdn(const uint8_t *data, size_t n, char *out, size_t cap)
{
    if (!out || cap == 0) return;
    out[0] = '\0';
    if (!data || n == 0) return;

    size_t o = 0;
    for (size_t i = 0; i < n && o + 1 < cap; i++) {
        uint8_t lo = data[i] & 0x0f;
        uint8_t hi = (data[i] >> 4) & 0x0f;
        if (lo <= 9) out[o++] = (char)('0' + lo);
        if (hi <= 9 && o + 1 < cap) out[o++] = (char)('0' + hi);
    }
    out[o] = '\0';
}

static void extract_ula_subdata(map_session_t *s,
                                const uint8_t *body, size_t body_len)
{
    s->n_ula_apns = 0;
    s->ula_default_context_id = 0;
    s->ula_apn[0] = '\0';
    s->ula_ambr_ul_bps = 0;
    s->ula_ambr_dl_bps = 0;
    s->msisdn_str[0] = '\0';

    diameter_avp_t msisdn_avp;
    if (diameter_avp_find_recursive(body, body_len, AVP_3GPP_MSISDN,
                                    DIAMETER_VENDOR_3GPP, &msisdn_avp) == 0)
        decode_ula_msisdn(msisdn_avp.data, msisdn_avp.data_len,
                          s->msisdn_str, sizeof(s->msisdn_str));

    diameter_avp_t sd;
    if (diameter_avp_find(body, body_len, AVP_3GPP_SUBSCRIPTION_DATA,
                          DIAMETER_VENDOR_3GPP, &sd) < 0) {
        if (s->msisdn_str[0]) {
            s->have_ula_subdata = true;
            LOGI("map", "ULA imsi=%s msisdn=%s (no Subscription-Data AVP)",
                 s->imsi_str, s->msisdn_str);
        } else {
            LOGW("map", "ULA imsi=%s: no Subscription-Data and no MSISDN "
                 "(check Open5GS subscriber msisdn[] in MongoDB)",
                 s->imsi_str);
        }
        return;
    }

    s->have_ula_subdata = true;

    /* CS GSUP: MSISDN only toward MSC; skip GPRS APN walk. */
    const bool want_apn =
        !(s->gsup_originated && s->gsup_cn_domain == GSUP_CN_DOMAIN_CS);

    /* APN-Configuration-Profile → all APN-Configuration (1430) children. */
    diameter_avp_t apnp;
    if (want_apn &&
        diameter_avp_find(sd.data, sd.data_len,
                          AVP_3GPP_APN_CONFIGURATION_PROFILE,
                          DIAMETER_VENDOR_3GPP, &apnp) == 0) {
        diameter_avp_t it;
        if (diameter_avp_first(apnp.data, apnp.data_len, &it) == 0) {
            for (;;) {
                if (it.code == AVP_3GPP_CONTEXT_IDENTIFIER &&
                    it.vendor_id == DIAMETER_VENDOR_3GPP &&
                    it.data_len >= 4 && !s->ula_default_context_id) {
                    s->ula_default_context_id = (uint8_t)iwf_be32(it.data);
                } else if (it.code == AVP_3GPP_APN_CONFIGURATION &&
                           it.vendor_id == DIAMETER_VENDOR_3GPP) {
                    (void)ula_add_apn_entry(s, &it);
                }
                if (diameter_avp_next(apnp.data, apnp.data_len, &it) < 0)
                    break;
            }
        }
    }

    if (s->n_ula_apns > 0) {
        map_ula_apn_entry_t *def = &s->ula_apns[0];
        if (s->ula_default_context_id) {
            for (uint8_t i = 0; i < s->n_ula_apns; i++) {
                if (s->ula_apns[i].context_id == s->ula_default_context_id) {
                    def = &s->ula_apns[i];
                    break;
                }
            }
        }
        snprintf(s->ula_apn, sizeof(s->ula_apn), "%s", def->apn);
        s->ula_ambr_ul_bps = (uint64_t)def->ambr_ul_kbps * 1000ull;
        s->ula_ambr_dl_bps = (uint64_t)def->ambr_dl_kbps * 1000ull;
    }

    if (s->n_ula_apns <= 1) {
        LOGI("map", "ULA imsi=%s msisdn=%s apn=%s ambr=%lu/%lu bps",
             s->imsi_str,
             s->msisdn_str[0] ? s->msisdn_str : "(none)",
             s->ula_apn[0]   ? s->ula_apn   : "(none)",
             (unsigned long)s->ula_ambr_ul_bps,
             (unsigned long)s->ula_ambr_dl_bps);
    } else {
        LOGI("map", "ULA imsi=%s msisdn=%s apns=%u default_ctx=%u ambr=%lu/%lu bps",
             s->imsi_str,
             s->msisdn_str[0] ? s->msisdn_str : "(none)",
             (unsigned)s->n_ula_apns,
             (unsigned)s->ula_default_context_id,
             (unsigned long)s->ula_ambr_ul_bps,
             (unsigned long)s->ula_ambr_dl_bps);
        for (uint8_t i = 0; i < s->n_ula_apns; i++) {
            LOGI("map", "  ULA APN[%u] ctx=%u apn=%s pdp=0x%02x",
                 (unsigned)i,
                 (unsigned)s->ula_apns[i].context_id,
                 s->ula_apns[i].apn,
                 (unsigned)s->ula_apns[i].pdn_type_nr);
        }
    }
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
    if (s->gsup_originated) {
#ifdef GSUP_PROXY_ENABLED
        extract_ula_subdata(s, body, body_len);
        bool need_isd = false;
        if (s->gsup_cn_domain == GSUP_CN_DOMAIN_CS)
            need_isd = s->msisdn_str[0] != '\0';
        else
            need_isd = s->msisdn_str[0] != '\0' || s->n_ula_apns > 0;
        if (s->have_ula_subdata && need_isd) {
            if (gsup_map_proxy_send_isd(rt, s) < 0)
                gsup_map_proxy_finish_ugl(rt, s);
        } else {
            gsup_map_proxy_finish_ugl(rt, s);
        }
#endif
        return;
    }
    extract_ula_subdata(s, body, body_len);

    /* If we have any subscription data, push ISD first (then UGL Resp on
     * its ack).  Otherwise send the UGL ReturnResult immediately. */
    if (s->have_ula_subdata && (s->msisdn_str[0] || s->n_ula_apns > 0)) {
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
                                parent->ula_apns,
                                parent->n_ula_apns,
                                parent->ula_default_context_id,
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
    LOGI("map", "TX BEGIN ISD imsi=%s tid=0x%08x apns=%u (UGL parent tid=0x%08x)",
         parent->imsi_str, isd->tcap_dialogue_id,
         (unsigned)parent->n_ula_apns, parent->tcap_dialogue_id);

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

static int send_map_cl_begin(struct iwf_runtime *rt, const char *imsi,
                             uint8_t cancellation_type)
{
    if (!ss7_link_is_active(rt)) return -1;

    uint8_t imsi_bcd[MAP_IMSI_BCD_MAX];
    int bl = map_str_to_bcd(imsi, imsi_bcd, sizeof(imsi_bcd));
    if (bl < 0) return -1;

    uint8_t arg[64];
    int an = map_encode_cl_arg(imsi_bcd, (size_t)bl, cancellation_type,
                               arg, sizeof(arg));
    if (an < 0) return -1;

    uint32_t tid = map_sess_new_tid();
    uint8_t cmp[512];
    size_t co = 0;
    if (tcap_enc_invoke(cmp, sizeof(cmp), &co, 1,
                        MAP_OP_CODE_CANCEL_LOCATION, arg, (size_t)an) < 0)
        return -1;

    uint8_t dlg[128];
    int dn = map_encode_aarq(MAP_AC_GPRS_LOCATION_CANCEL_V3, dlg, sizeof(dlg));
    if (dn < 0) return -1;

    uint8_t out[1024];
    int n = tcap_encode_message(TCAP_MSG_BEGIN, tid, true,
                                0, false,
                                dlg, (size_t)dn,
                                cmp, co,
                                out, sizeof(out));
    if (n < 0) return -1;

    ss7_sccp_addr_t called = {0};
    called.ssn = SS7_SSN_SGSN;
    if (ss7_link_send_tcap(rt, &called, out, (size_t)n) < 0)
        return -1;

    rt->map->stat_map_tx++;
    LOGI("map", "TX BEGIN CL imsi=%s tid=0x%08x type=%u (HSS CLR)",
         imsi, tid, (unsigned)cancellation_type);
    return 0;
}

void map_iwf_on_clr(struct iwf_runtime *rt,
                    const uint8_t *body, size_t body_len,
                    uint32_t hop_by_hop, uint32_t end_to_end)
{
    char sid[DIAMETER_SESSION_ID_MAX];
    char imsi[MAP_IMSI_STR_MAX];
    uint32_t cancel_type = 0;
    bool forwarded = false;

    sid[0] = '\0';
    (void)diameter_get_session_id(body, body_len, sid, sizeof(sid));

    if (diameter_get_user_name(body, body_len, imsi, sizeof(imsi)) < 0) {
        LOGW("map", "CLR: missing User-Name");
        (void)diameter_send_cla_answer(rt, hop_by_hop, end_to_end, sid,
                                       DIAM_RC_UNABLE_TO_DELIVER);
        return;
    }

    (void)diameter_get_uint32_avp(body, body_len, AVP_3GPP_CANCELLATION_TYPE,
                                  DIAMETER_VENDOR_3GPP, &cancel_type);

    LOGI("map", "RX CLR imsi=%s cancel_type=%u sid=%s",
         imsi, (unsigned)cancel_type, sid[0] ? sid : "-");

#ifdef GSUP_PROXY_ENABLED
    if (gsup_map_proxy_hss_clr(rt, imsi, (uint8_t)cancel_type))
        forwarded = true;
#endif
    if (!forwarded && send_map_cl_begin(rt, imsi, (uint8_t)cancel_type) == 0)
        forwarded = true;

    if (!forwarded)
        LOGW("map", "CLR: no GSUP/MAP downstream for imsi=%s", imsi);

    (void)diameter_send_cla_answer(rt, hop_by_hop, end_to_end, sid,
                                   DIAM_RC_SUCCESS);
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
    if (s->gsup_originated) {
#ifdef GSUP_PROXY_ENABLED
        gsup_map_proxy_diameter_error(rt, s, rc);
#endif
        return;
    }
    LOGW("map", "Diameter error rc=%u imsi=%s op=%s; sending MAP SystemFailure",
         (unsigned)rc, s->imsi_str, map_op_str(s->map_op));
    if (s->cmd_test) {
        char buf[48];
        snprintf(buf, sizeof(buf), "diameter_%u", (unsigned)rc);
        cmd_test_abort(s, buf);
        return;
    }
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
    int killed = map_sess_sweep(time(NULL), map_sess_timeout_hook_cmd, rt);
    if (killed) rt->map->stat_timeouts += (uint64_t)killed;
#ifdef GSUP_PROXY_ENABLED
    gsup_map_proxy_sweep(rt, time(NULL));
#endif
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

    if (test_cmd_init(rt, epfd) < 0) {
        const char *p = rt->cfg.map_cmd_sock_path[0]
                            ? rt->cfg.map_cmd_sock_path
                            : IWF_TEST_CMD_SOCK_PATH;
        LOGW("map", "test command socket not available (%s)", p);
    }
    return 0;
}

void map_iwf_shutdown(struct iwf_runtime *rt)
{
    if (!rt || !rt->map) return;
    test_cmd_shutdown();
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

/* ====================================================================== */
/* UNIX / SIGUSR1 test SAI (Diameter AIR only; no SS7 TCAP reply)         */
/* ====================================================================== */

int map_iwf_cmd_test_sai(struct iwf_runtime *rt,
                         const char *imsi_digits,
                         int reply_unix_fd)
{
    if (!map_iwf_enabled(rt)) {
        if (reply_unix_fd >= 0)
            test_cmd_reply_err(reply_unix_fd, "map_iwf_disabled");
        return reply_unix_fd >= 0 ? -1 : 0;
    }
    if (!imsi_digits || !imsi_digits[0]) {
        if (reply_unix_fd >= 0)
            test_cmd_reply_err(reply_unix_fd, "invalid_imsi");
        return -1;
    }

    for (const char *p = imsi_digits; *p; p++) {
        if (!isdigit((unsigned char)*p)) {
            if (reply_unix_fd >= 0)
                test_cmd_reply_err(reply_unix_fd, "invalid_imsi");
            return -1;
        }
    }

    size_t L = strlen(imsi_digits);
    if (L < 10 || L > 15) {
        if (reply_unix_fd >= 0)
            test_cmd_reply_err(reply_unix_fd, "invalid_imsi_length");
        return -1;
    }

    map_session_t *s = map_sess_create(map_sess_new_tid());
    if (!s) {
        if (reply_unix_fd >= 0)
            test_cmd_reply_err(reply_unix_fd, "no_session");
        return -1;
    }

    s->map_op = MAP_OP_SAI;
    s->state  = MAP_SESS_WAIT_DIAMETER;
    s->have_peer_tid = false;
    s->peer_tcap_dialogue_id = 0;

    int bn = map_str_to_bcd(imsi_digits, s->imsi_bcd, sizeof(s->imsi_bcd));
    if (bn < 0) {
        if (reply_unix_fd >= 0)
            test_cmd_reply_err(reply_unix_fd, "bcd_encode_failed");
        map_sess_remove(s);
        return -1;
    }
    s->imsi_bcd_len = (uint8_t)bn;
    strncpy(s->imsi_str, imsi_digits, sizeof(s->imsi_str) - 1);
    s->imsi_str[sizeof(s->imsi_str) - 1] = '\0';

    if (map_plmn_pack_home(rt->cfg.gsup_local_mnc, s->visited_plmn_bcd) == 0)
        s->have_visited_plmn = true;

    s->cmd_test = true;
    s->cmd_test_reply_fd = reply_unix_fd;
    s->t_dialogue_ms = 10000;
    map_sess_touch(s);

    LOGI("map", "cmd-test TX AIR imsi=%s tid=0x%08x",
         s->imsi_str, s->tcap_dialogue_id);

    if (diameter_send_air(rt, s) < 0) {
        cmd_test_abort(s, "air_send_failed");
        return 0;
    }
    return 0;
}

void map_iwf_sigusr1_test_sai(struct iwf_runtime *rt)
{
    if (!map_iwf_enabled(rt)) {
        LOGW("map", "SIGUSR1 cmd-test SAI ignored (MAP-IWF not active)");
        return;
    }
    LOGI("map", "SIGUSR1: cmd-test SAI imsi=432120000000001");
    (void)map_iwf_cmd_test_sai(rt, "432120000000001", -1);
}
