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
 * UL (Update Location, MAP-C)
 * ---------------------------
 *   VLR -> IWF: TCAP-Begin (AARQ=networkLocUpContext-v3, Invoke updateLocation)
 *   IWF -> HSS: Diameter ULR (CS flags, SGSN-Number = MAP vlr-Number)
 *   HSS -> IWF: Diameter ULA + MSISDN
 *   IWF -> MSC: GSUP ISD_REQ (home MSC learns IMSI+MSISDN for MT-SMS/SGs)
 *   IWF -> VLR: TCAP-Continue (AARE + Invoke ISD) on the same dialogue
 *   VLR -> IWF: TCAP-Continue/End (ISD ReturnResult)
 *   IWF -> VLR: TCAP-End (updateLocation ReturnResult)
 *
 * CL (Cancel Location, HSS-initiated)
 * -----------------------------------
 *   HSS  -> IWF: Diameter CLR (Dest-Host = iwf or iwf-vlr)
 *   IWF  -> MSC/SGSN: GSUP Location-Cancel (CN from Dest-Host)
 *   IWF  -> HSS: Diameter CLA (Origin-Host matches Dest-Host)
 *
 * IDR (Insert Subscriber Data, HSS-initiated)
 * ------------------------------------------
 *   HSS  -> IWF: Diameter IDR + Subscription-Data
 *   IWF  -> MSC/SGSN: GSUP ISD_REQ (CN from Dest-Host)
 *   IWF  -> HSS: Diameter IDA
 *
 * PurgeMS
 * -------
 *   SGSN -> IWF: TCAP-Begin (Invoke PurgeMS)
 *   IWF  -> HSS: Diameter PUR
 *   HSS  -> IWF: Diameter PUA
 *   IWF  -> SGSN: TCAP-End (ReturnResult)
 *
 * PRN (Provide Roaming Number)
 * ----------------------------
 *   HLR/GMSC -> IWF: TCAP-Begin (AARQ=roamingNumberEnquiryContext-v3,
 *                               Invoke provideRoamingNumber)
 *   IWF allocates MSRN from configured pool, binds to IMSI (TTL),
 *   replies TCAP-End ReturnResult(roamingNumber). On pool miss/exhaustion
 *   replies ReturnError(noRoamingNumberAvailable) — never silent drop.
 *   SIP (outside repo) resolves inbound calls via cmd_sock msrn_lookup.
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
#include "msrn_pool.h"
#include "tcap.h"
#include "diameter.h"
#include "ss7_link.h"
#include "runtime.h"
#include "logging.h"
#include "test_cmd.h"
#include "imsi_trace.h"
#include "subscr_cache.h"
#include "gsup_proto.h"
#include "msisdn_db.h"
#ifdef GSUP_PROXY_ENABLED
#include "gsup_map_proxy.h"
#include "ussd_iwf.h"
#endif
#ifdef SMS_IWF_ENABLED
#include "sms_iwf.h"
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
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
    case MAP_OP_UL:       return MAP_AC_NETWORK_LOC_UP_V3;
    case MAP_OP_UGL:      return MAP_AC_GPRS_LOCATION_UPDATE_V3;
    case MAP_OP_ISD:      return MAP_AC_SUBSCRIBER_DATA_MGMT_V3;
    case MAP_OP_CL:       return MAP_AC_GPRS_LOCATION_CANCEL_V3;
    case MAP_OP_PURGE_MS: return MAP_AC_MS_PURGING_V3;
    case MAP_OP_PRN:      return MAP_AC_ROAMING_NUMBER_ENQUIRY_V3;
    case MAP_OP_SRI:      return MAP_AC_ROAMING_NUMBER_ENQUIRY_V3;
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

static int encode_loc_up_res(struct iwf_runtime *rt,
                             uint8_t *params, size_t params_cap);

static void sri_send_end(struct iwf_runtime *rt,
                         const ss7_sccp_addr_t *calling,
                         const tcap_msg_t *tmsg,
                         const uint8_t *cmp, size_t co);
static void sri_send_error(struct iwf_runtime *rt,
                           const ss7_sccp_addr_t *calling,
                           const tcap_msg_t *tmsg,
                           uint8_t invoke_id, int err);

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
        LOGW("map",
         "[%s] cmd-test SAI failed: %s",
         s->imsi_str[0] ? s->imsi_str : "?",
         r);
    }
    s->cmd_test = false;
    map_sess_remove(s);
}

static void map_sess_timeout_hook_cmd(map_session_t *s, void *hook_ctx)
{
    struct iwf_runtime *rt = (struct iwf_runtime *)hook_ctx;

    if (!s) return;

    if (!s->cmd_test) {
#ifdef GSUP_PROXY_ENABLED
        if (s->gsup_originated && rt) {
            gsup_map_proxy_on_timeout(rt, s);
            return;
        }
#endif
        if (rt && !s->gsup_originated) {
            if (s->map_op == MAP_OP_ISD && s->have_parent_tid) {
                map_session_t *parent =
                    map_sess_find_by_tid(s->parent_tcap_dialogue_id);
                if (parent &&
                    parent->state == MAP_SESS_WAIT_MAP_ACK &&
                    parent->map_op == MAP_OP_UGL) {
                    send_tcap_end_with_error(rt, parent, parent->peer_invoke_id,
                                             MAP_ERR_SYSTEM_FAILURE, 1);
                }
            } else if (s->state == MAP_SESS_WAIT_MAP_ACK &&
                       (s->map_op == MAP_OP_UL || s->map_op == MAP_OP_UGL)) {
                send_tcap_end_with_error(rt, s, s->peer_invoke_id,
                                         MAP_ERR_SYSTEM_FAILURE, 1);
            } else if (s->state == MAP_SESS_WAIT_MAP_ACK &&
                       s->map_op == MAP_OP_SRI) {
                ss7_sccp_addr_t peer = s->peer_sccp;
                uint32_t otid = s->peer_tcap_dialogue_id;
                bool have_otid = s->have_peer_tid;
                uint8_t inv = s->peer_invoke_id;
                map_sess_remove(s);
                if (peer.have_gt || peer.point_code) {
                    tcap_msg_t fake = {0};
                    fake.otid = otid;
                    fake.have_otid = have_otid;
                    sri_send_error(rt, &peer, &fake, inv,
                                   MAP_ERR_SYSTEM_FAILURE);
                }
            }
        }
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

static void map_sess_store_peer(map_session_t *s, const ss7_sccp_addr_t *calling)
{
    if (!s || !calling) return;
    s->peer_sccp = *calling;
    s->have_peer_sccp = true;
}

/* Reply CdPA = inbound CgPA; CgPA = local GT, HLR SSN when peer is VLR/MSC/SGSN. */
static int map_send_tcap_to_peer(struct iwf_runtime *rt, map_session_t *s,
                                 const uint8_t *out, size_t n)
{
    ss7_sccp_addr_t called = {0};
    ss7_sccp_addr_t calling;

    if (s->have_peer_sccp)
        called = s->peer_sccp;
    else
        called.ssn = SS7_SSN_SGSN;

    ss7_link_make_local_addr(rt, &calling);
    /* Acting as HLR: force CgPA SSN=6 for VLR/MSC/SGSN peers (not HLR↔HLR). */
    if (s->have_peer_sccp &&
        (s->peer_sccp.ssn == SS7_SSN_VLR ||
         s->peer_sccp.ssn == SS7_SSN_MSC ||
         s->peer_sccp.ssn == SS7_SSN_SGSN))
        calling.ssn = SS7_SSN_HLR;

    int rc = ss7_link_send_tcap_ex(rt, &called, &calling, out, n);
    if (rc >= 0 && s->imsi_str[0])
        iwf_imsi_trace_packet(s->imsi_str, "map", "tx", out, n);
    return rc;
}

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
    s->peer_invoke_id        = cmp->invoke_id;
    s->t_dialogue_ms         = rt->cfg.map_t_dialogue_ms > 0
                                 ? rt->cfg.map_t_dialogue_ms : TCAP_DEFAULT_T_MS;
    map_sess_store_peer(s, calling);
    memcpy(s->imsi_bcd, req.imsi_bcd, req.imsi_bcd_len);
    s->imsi_bcd_len = req.imsi_bcd_len;
    memcpy(s->imsi_str, req.imsi_str, sizeof(s->imsi_str));

    /* Visited PLMN: derive from the IMSI MCC+MNC (TS 24.008).  This is a
     * fallback - a future patch can prefer the SCCP CallingParty GT's
     * country code if it differs (roaming-from-home detection). */
    if (map_plmn_pack_home(rt->cfg.gsup_local_mnc, s->visited_plmn_bcd) == 0)
        s->have_visited_plmn = true;

    LOGI("map",
         "[%s] RX BEGIN SAI tid=0x%08x peer_otid=0x%08x invoke=%u vec_req=%u",
         s->imsi_str,
         s->tcap_dialogue_id,
         s->peer_tcap_dialogue_id,
         (unsigned)s->peer_invoke_id,
         req.num_vectors);

    if (diameter_send_air(rt, s) < 0) {
        LOGW("map", "[%s] AIR send failed; replying systemFailure", s->imsi_str);
        send_tcap_end_with_error(rt, s, s->peer_invoke_id,
                                 MAP_ERR_SYSTEM_FAILURE, /*nrc=hlr*/ 1);
    }
    iwf_imsi_trace_flush_rx(s->imsi_str);
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
    s->gsup_cn_domain = GSUP_CN_DOMAIN_PS;
    s->state  = MAP_SESS_WAIT_DIAMETER;
    s->peer_tcap_dialogue_id = tmsg->otid;
    s->have_peer_tid         = tmsg->have_otid;
    s->peer_invoke_id        = cmp->invoke_id;
    s->t_dialogue_ms         = rt->cfg.map_t_dialogue_ms > 0
                                 ? rt->cfg.map_t_dialogue_ms : TCAP_DEFAULT_T_MS;
    map_sess_store_peer(s, calling);
    memcpy(s->imsi_bcd, req.imsi_bcd, req.imsi_bcd_len);
    s->imsi_bcd_len = req.imsi_bcd_len;
    memcpy(s->imsi_str, req.imsi_str, sizeof(s->imsi_str));
    if (map_plmn_pack_home(rt->cfg.gsup_local_mnc, s->visited_plmn_bcd) == 0)
        s->have_visited_plmn = true;

    LOGI("map",
         "[%s] RX BEGIN UGL tid=0x%08x peer_otid=0x%08x",
         s->imsi_str,
         s->tcap_dialogue_id,
         s->peer_tcap_dialogue_id);
    if (diameter_send_ulr(rt, s) < 0) {
        send_tcap_end_with_error(rt, s, s->peer_invoke_id, MAP_ERR_SYSTEM_FAILURE, 1);
    }
    iwf_imsi_trace_flush_rx(s->imsi_str);
}

static void handle_begin_ul(struct iwf_runtime *rt,
                            const ss7_sccp_addr_t *calling,
                            const tcap_msg_t *tmsg,
                            const tcap_component_t *cmp)
{
    map_ul_req_t req;
    if (map_decode_ul_arg(cmp->parameters, cmp->parameters_len, &req) < 0) {
        LOGW("map", "UL: malformed argument from pc=%u", calling->point_code);
        return;
    }
    map_session_t *s = map_sess_create(map_sess_new_tid());
    if (!s) return;
    s->map_op = MAP_OP_UL;
    s->gsup_cn_domain = GSUP_CN_DOMAIN_CS;
    s->state  = MAP_SESS_WAIT_DIAMETER;
    s->peer_tcap_dialogue_id = tmsg->otid;
    s->have_peer_tid         = tmsg->have_otid;
    s->peer_invoke_id        = cmp->invoke_id;
    s->t_dialogue_ms         = rt->cfg.map_t_dialogue_ms > 0
                                 ? rt->cfg.map_t_dialogue_ms : TCAP_DEFAULT_T_MS;
    map_sess_store_peer(s, calling);
    memcpy(s->imsi_bcd, req.imsi_bcd, req.imsi_bcd_len);
    s->imsi_bcd_len = req.imsi_bcd_len;
    memcpy(s->imsi_str, req.imsi_str, sizeof(s->imsi_str));
    if (map_plmn_pack_home(rt->cfg.gsup_local_mnc, s->visited_plmn_bcd) == 0)
        s->have_visited_plmn = true;
    if (req.msc_number[0])
        snprintf(s->msc_number, sizeof(s->msc_number), "%s", req.msc_number);
    if (req.vlr_number[0])
        snprintf(s->vlr_number, sizeof(s->vlr_number), "%s", req.vlr_number);

    LOGI("map",
         "[%s] RX BEGIN UL tid=0x%08x peer_otid=0x%08x invoke=%u msc=%s vlr=%s",
         s->imsi_str,
         s->tcap_dialogue_id,
         s->peer_tcap_dialogue_id,
         (unsigned)s->peer_invoke_id,
         req.msc_number[0] ? req.msc_number : "-",
         req.vlr_number[0] ? req.vlr_number
                           : (calling && calling->have_gt ? calling->gt_digits : "-"));
    if (diameter_send_ulr(rt, s) < 0) {
        send_tcap_end_with_error(rt, s, s->peer_invoke_id, MAP_ERR_SYSTEM_FAILURE, 1);
    }
    iwf_imsi_trace_flush_rx(s->imsi_str);
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
    s->peer_invoke_id        = cmp->invoke_id;
    s->t_dialogue_ms         = rt->cfg.map_t_dialogue_ms > 0
                                 ? rt->cfg.map_t_dialogue_ms : TCAP_DEFAULT_T_MS;
    map_sess_store_peer(s, calling);
    memcpy(s->imsi_bcd, req.imsi_bcd, req.imsi_bcd_len);
    s->imsi_bcd_len = req.imsi_bcd_len;
    memcpy(s->imsi_str, req.imsi_str, sizeof(s->imsi_str));
    if (map_plmn_pack_home(rt->cfg.gsup_local_mnc, s->visited_plmn_bcd) == 0)
        s->have_visited_plmn = true;
    LOGI("map",
         "[%s] RX BEGIN PurgeMS tid=0x%08x invoke=%u",
         s->imsi_str,
         s->tcap_dialogue_id,
         (unsigned)s->peer_invoke_id);
    if (diameter_send_pur(rt, s) < 0) {
        send_tcap_end_with_error(rt, s, s->peer_invoke_id, MAP_ERR_SYSTEM_FAILURE, 1);
    }
    iwf_imsi_trace_flush_rx(s->imsi_str);
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
    s->peer_invoke_id        = cmp->invoke_id;
    map_sess_store_peer(s, calling);
    memcpy(s->imsi_str, req.imsi_str, sizeof(s->imsi_str));
    LOGI("map",
         "[%s] RX BEGIN CL ct=%u (immediate ack)",
         s->imsi_str,
         req.cancellation_type);
    /* No Diameter side - just acknowledge. */
    send_tcap_end_with_result(rt, s, s->peer_invoke_id,
                              MAP_OP_CODE_CANCEL_LOCATION, NULL, 0);
    iwf_imsi_trace_flush_rx(s->imsi_str);
}

/* ProvideRoamingNumber: allocate MSRN, bind IMSI, TCAP-End with result.
 * Pool miss / exhaustion -> ReturnError(noRoamingNumberAvailable). */
static void handle_begin_prn(struct iwf_runtime *rt,
                             const ss7_sccp_addr_t *calling,
                             const tcap_msg_t *tmsg,
                             const tcap_component_t *cmp)
{
    map_prn_req_t req;
    map_session_t *s = map_sess_create(map_sess_new_tid());
    if (!s) {
        LOGE("map", "PRN: session alloc failed from pc=%u",
             calling ? calling->point_code : 0);
        return;
    }
    s->map_op = MAP_OP_PRN;
    s->state  = MAP_SESS_WAIT_MAP_TX;
    s->peer_tcap_dialogue_id = tmsg->otid;
    s->have_peer_tid         = tmsg->have_otid;
    s->peer_invoke_id        = cmp->invoke_id;
    s->t_dialogue_ms         = rt->cfg.map_t_dialogue_ms > 0
                                 ? rt->cfg.map_t_dialogue_ms : TCAP_DEFAULT_T_MS;
    map_sess_store_peer(s, calling);

    if (map_decode_prn_arg(cmp->parameters, cmp->parameters_len, &req) < 0) {
        LOGW("map",
             "[?] RX BEGIN PRN tid=0x%08x peer_otid=0x%08x: malformed arg "
             "(pc=%u) -> systemFailure",
             s->tcap_dialogue_id, s->peer_tcap_dialogue_id,
             calling ? calling->point_code : 0);
        send_tcap_end_with_error(rt, s, s->peer_invoke_id,
                                 MAP_ERR_SYSTEM_FAILURE, 1);
        return;
    }

    if (req.imsi_bcd_len) {
        memcpy(s->imsi_bcd, req.imsi_bcd, req.imsi_bcd_len);
        s->imsi_bcd_len = req.imsi_bcd_len;
    }
    if (req.imsi_str[0])
        memcpy(s->imsi_str, req.imsi_str, sizeof(s->imsi_str));

    const char *imsi_log = s->imsi_str[0] ? s->imsi_str : "?";
    LOGI("map",
         "[%s] RX BEGIN PRN tid=0x%08x peer_otid=0x%08x invoke=%u msc=%s msisdn=%s",
         imsi_log,
         s->tcap_dialogue_id,
         s->peer_tcap_dialogue_id,
         (unsigned)s->peer_invoke_id,
         req.msc_number[0] ? req.msc_number : "-",
         req.msisdn[0] ? req.msisdn : "-");

    if (!req.imsi_str[0]) {
        LOGW("map",
             "[?] PRN tid=0x%08x: IMSI missing -> systemFailure",
             s->tcap_dialogue_id);
        send_tcap_end_with_error(rt, s, s->peer_invoke_id,
                                 MAP_ERR_SYSTEM_FAILURE, 1);
        return;
    }

    if (!msrn_pool_configured()) {
        LOGW("map",
             "[%s] PRN tid=0x%08x: no msrn_pool configured -> "
             "noRoamingNumberAvailable",
             imsi_log, s->tcap_dialogue_id);
        send_tcap_end_with_error(rt, s, s->peer_invoke_id,
                                 MAP_ERR_NO_ROAMING_NUMBER_AVAILABLE, 0);
        return;
    }

    msrn_binding_t bind;
    if (msrn_pool_alloc(req.imsi_str,
                        req.msisdn[0] ? req.msisdn : NULL,
                        req.msc_number[0] ? req.msc_number : NULL,
                        s->tcap_dialogue_id,
                        &bind) < 0) {
        LOGW("map",
             "[%s] PRN tid=0x%08x: alloc failed (exhausted/unknown MSC) -> "
             "noRoamingNumberAvailable",
             imsi_log, s->tcap_dialogue_id);
        send_tcap_end_with_error(rt, s, s->peer_invoke_id,
                                 MAP_ERR_NO_ROAMING_NUMBER_AVAILABLE, 0);
        return;
    }

    uint8_t params[64];
    int pn = map_encode_prn_res(bind.msrn, params, sizeof(params));
    if (pn < 0) {
        LOGE("map",
             "[%s] PRN tid=0x%08x: encode res failed msrn=%s -> systemFailure",
             imsi_log, s->tcap_dialogue_id, bind.msrn);
        msrn_pool_release(bind.msrn);
        send_tcap_end_with_error(rt, s, s->peer_invoke_id,
                                 MAP_ERR_SYSTEM_FAILURE, 1);
        return;
    }

    LOGI("map",
         "[%s] PRN tid=0x%08x allocated msrn=%s pool=%s",
         imsi_log, s->tcap_dialogue_id, bind.msrn, bind.pool_name);
    send_tcap_end_with_result(rt, s, s->peer_invoke_id,
                              MAP_OP_CODE_PROVIDE_ROAMING_NUMBER,
                              params, (size_t)pn);
    iwf_imsi_trace_flush_rx(s->imsi_str);
}

/* ProvideSubscriberInfo (partner HLR/gsmSCF -> our VLR): answer with the
 * subscriber state so their SMSC/CAMEL logic can proceed. Session-less:
 * decode IMSI, reply TCAP END (AARE echoing their AC) immediately. */
static void handle_begin_psi(struct iwf_runtime *rt,
                             const ss7_sccp_addr_t *calling,
                             const tcap_msg_t *tmsg,
                             const tcap_component_t *c)
{
    char imsi[16] = "";
    (void)map_decode_psi_arg(c->parameters, c->parameters_len,
                             imsi, sizeof(imsi));
    bool attached = false;
#ifdef GSUP_PROXY_ENABLED
    if (imsi[0])
        attached = gsup_map_proxy_imsi_known(imsi, 0);
#endif

    uint8_t params[48];
    int pn = map_encode_psi_res(attached ? 1 : 0,
                                1 /* imsiDetached */, params, sizeof(params));
    if (pn < 0) return;
    uint8_t cmp[128];
    size_t co = 0;
    if (tcap_enc_return_result(cmp, sizeof(cmp), &co, c->invoke_id,
                               MAP_OP_CODE_PROVIDE_SUBSCRIBER_INFO,
                               params, (size_t)pn) < 0)
        return;

    uint8_t dlg[128];
    int dn = 0;
    uint8_t oid[16];
    size_t ol = 0;
    if (tmsg->dialogue && tmsg->dialogue_len &&
        map_decode_aarq_ac_raw(tmsg->dialogue, tmsg->dialogue_len,
                               oid, sizeof(oid), &ol) == 0)
        dn = map_encode_aare_oid(oid, ol, dlg, sizeof(dlg));
    if (dn < 0) dn = 0;

    uint8_t out[512];
    int n = tcap_encode_message(TCAP_MSG_END, 0, false,
                                tmsg->otid, tmsg->have_otid,
                                dn > 0 ? dlg : NULL, dn > 0 ? (size_t)dn : 0,
                                cmp, co, out, sizeof(out));
    if (n < 0) return;

    ss7_sccp_addr_t src;
    memset(&src, 0, sizeof(src));
    if (rt->cfg.map_local_gt[0])
        ss7_gt_from_digits(rt->cfg.map_local_gt, SS7_SSN_VLR, &src);
    src.ssn = SS7_SSN_VLR;
    ss7_link_send_tcap_ex(rt, calling, src.have_gt ? &src : NULL,
                          out, (size_t)n);
    LOGI("map", "[%s] PSI answered state=%s",
         imsi[0] ? imsi : "?",
         attached ? "assumedIdle" : "netDetNotReachable");
}

/* sendRoutingInformation (GMSC -> HLR, MT voice call).
 *
 * Outbound roam: home subscriber on foreign VLR — HSS Mongo has vlr_number
 * from inbound MAP UL; IWF invokes MAP PRN on that VLR and returns the
 * visited MSRN in SRI Res.
 *
 * Inbound roam on our MSC: foreign subscriber on osmo-msc — MSISDN map +
 * GSUP ISD; allocate from our MSRN pool toward our MSC. */
static void sri_send_end(struct iwf_runtime *rt,
                         const ss7_sccp_addr_t *calling,
                         const tcap_msg_t *tmsg,
                         const uint8_t *cmp, size_t co)
{
    uint8_t dlg[128];
    int dn = 0;
    uint8_t oid[16];
    size_t ol = 0;
    if (tmsg->dialogue && tmsg->dialogue_len &&
        map_decode_aarq_ac_raw(tmsg->dialogue, tmsg->dialogue_len,
                               oid, sizeof(oid), &ol) == 0)
        dn = map_encode_aare_oid(oid, ol, dlg, sizeof(dlg));
    if (dn < 0) dn = 0;

    uint8_t out[512];
    int n = tcap_encode_message(TCAP_MSG_END, 0, false,
                                tmsg->otid, tmsg->have_otid,
                                dn > 0 ? dlg : NULL, dn > 0 ? (size_t)dn : 0,
                                cmp, co, out, sizeof(out));
    if (n < 0) return;

    ss7_sccp_addr_t src;
    memset(&src, 0, sizeof(src));
    if (rt->cfg.map_local_gt[0])
        ss7_gt_from_digits(rt->cfg.map_local_gt, SS7_SSN_HLR, &src);
    src.ssn = SS7_SSN_HLR;
    ss7_link_send_tcap_ex(rt, calling, src.have_gt ? &src : NULL,
                          out, (size_t)n);
}

static void sri_send_error(struct iwf_runtime *rt,
                           const ss7_sccp_addr_t *calling,
                           const tcap_msg_t *tmsg,
                           uint8_t invoke_id, int err)
{
    uint8_t cmp[64];
    size_t co = 0;
    if (tcap_enc_return_error(cmp, sizeof(cmp), &co, invoke_id,
                              err, NULL, 0) < 0)
        return;
    sri_send_end(rt, calling, tmsg, cmp, co);
}

static bool vlr_gt_is_local(struct iwf_runtime *rt, const char *vlr_gt)
{
    if (!rt || !vlr_gt || !vlr_gt[0]) return false;
    if (rt->cfg.map_local_gt[0] && !strcmp(vlr_gt, rt->cfg.map_local_gt))
        return true;
    if (rt->cfg.sms_local_msc_gt[0] &&
        !strcmp(vlr_gt, rt->cfg.sms_local_msc_gt))
        return true;
    return false;
}

static int sri_send_local_msrn(struct iwf_runtime *rt,
                               const ss7_sccp_addr_t *calling,
                               const tcap_msg_t *tmsg,
                               const tcap_component_t *c,
                               const char *imsi, const char *msisdn)
{
    if (!msrn_pool_configured()) {
        LOGW("map", "[%s] SRI msisdn=%s: no msrn_pool -> facilityNotSupported",
             imsi, msisdn);
        sri_send_error(rt, calling, tmsg, c->invoke_id,
                       MAP_ERR_FACILITY_NOT_SUPPORTED);
        return -1;
    }
    msrn_binding_t bind;
    if (msrn_pool_alloc(imsi, msisdn, NULL, tmsg->otid, &bind) < 0) {
        LOGW("map", "[%s] SRI msisdn=%s: MSRN alloc failed", imsi, msisdn);
        sri_send_error(rt, calling, tmsg, c->invoke_id,
                       MAP_ERR_SYSTEM_FAILURE);
        return -1;
    }
    uint8_t params[80];
    int pn = map_encode_sri_res(imsi, bind.msrn, params, sizeof(params));
    if (pn < 0) {
        msrn_pool_release(bind.msrn);
        sri_send_error(rt, calling, tmsg, c->invoke_id,
                       MAP_ERR_SYSTEM_FAILURE);
        return -1;
    }
    uint8_t cmp[192];
    size_t co = 0;
    if (tcap_enc_return_result(cmp, sizeof(cmp), &co, c->invoke_id,
                               MAP_OP_CODE_SEND_ROUTING_INFO,
                               params, (size_t)pn) < 0) {
        msrn_pool_release(bind.msrn);
        return -1;
    }
    sri_send_end(rt, calling, tmsg, cmp, co);
    LOGI("map", "[%s] SRI answered (local MSC) msisdn=%s msrn=%s pool=%s",
         imsi, msisdn, bind.msrn, bind.pool_name);
    iwf_imsi_trace_flush_rx(imsi);
    return 0;
}

static int sri_send_prn_to_vlr(struct iwf_runtime *rt,
                               map_session_t *s,
                               const char *vlr_gt,
                               const char *msisdn)
{
    const char *msc = rt->cfg.map_local_gt[0] ? rt->cfg.map_local_gt
                      : (rt->cfg.sms_local_msc_gt[0]
                         ? rt->cfg.sms_local_msc_gt : vlr_gt);
    uint8_t arg[256];
    int an = map_encode_prn_arg(s->imsi_str, msc, msisdn, arg, sizeof(arg));
    if (an < 0) return -1;

    uint8_t cmp[320];
    size_t co = 0;
    if (tcap_enc_invoke(cmp, sizeof(cmp), &co, 1,
                        MAP_OP_CODE_PROVIDE_ROAMING_NUMBER,
                        arg, (size_t)an) < 0)
        return -1;

    uint8_t dlg[128];
    int dn = map_encode_aarq(MAP_AC_ROAMING_NUMBER_ENQUIRY_V3,
                             dlg, sizeof(dlg));
    if (dn < 0) return -1;

    uint8_t out[512];
    int n = tcap_encode_message(TCAP_MSG_BEGIN, s->tcap_dialogue_id, true,
                                0, false, dlg, (size_t)dn, cmp, co,
                                out, sizeof(out));
    if (n < 0) return -1;

    ss7_sccp_addr_t called, calling;
    ss7_gt_from_digits(vlr_gt, SS7_SSN_VLR, &called);
    memset(&calling, 0, sizeof(calling));
    if (rt->cfg.map_local_gt[0])
        ss7_gt_from_digits(rt->cfg.map_local_gt, SS7_SSN_HLR, &calling);
    calling.ssn = SS7_SSN_HLR;

    if (ss7_link_send_tcap_ex(rt, &called,
                              calling.have_gt ? &calling : NULL,
                              out, (size_t)n) < 0)
        return -1;

    LOGI("map",
         "[%s] TX PRN (SRI) vlr=%s msisdn=%s tid=0x%08x",
         s->imsi_str, vlr_gt, msisdn, s->tcap_dialogue_id);
    return 0;
}

static void finish_sri_from_prn(struct iwf_runtime *rt, map_session_t *s,
                                const uint8_t *params, size_t plen)
{
    char msrn[24] = "";
    if (map_decode_prn_res(params, plen, msrn, sizeof(msrn)) < 0) {
        tcap_msg_t fake = {0};
        fake.otid = s->peer_tcap_dialogue_id;
        fake.have_otid = s->have_peer_tid;
        sri_send_error(rt, &s->peer_sccp, &fake, s->peer_invoke_id,
                       MAP_ERR_SYSTEM_FAILURE);
        map_sess_remove(s);
        return;
    }

    uint8_t params_sri[80];
    int pn = map_encode_sri_res(s->imsi_str, msrn, params_sri, sizeof(params_sri));
    if (pn < 0) {
        tcap_msg_t fake = {0};
        fake.otid = s->peer_tcap_dialogue_id;
        fake.have_otid = s->have_peer_tid;
        sri_send_error(rt, &s->peer_sccp, &fake, s->peer_invoke_id,
                       MAP_ERR_SYSTEM_FAILURE);
        map_sess_remove(s);
        return;
    }

    uint8_t cmp[192];
    size_t co = 0;
    if (tcap_enc_return_result(cmp, sizeof(cmp), &co, s->peer_invoke_id,
                               MAP_OP_CODE_SEND_ROUTING_INFO,
                               params_sri, (size_t)pn) < 0) {
        map_sess_remove(s);
        return;
    }

    tcap_msg_t fake = {0};
    fake.otid = s->peer_tcap_dialogue_id;
    fake.have_otid = s->have_peer_tid;
    sri_send_end(rt, &s->peer_sccp, &fake, cmp, co);

    LOGI("map", "[%s] SRI answered (visited VLR) msisdn=%s msrn=%s",
         s->imsi_str,
         s->msisdn_str[0] ? s->msisdn_str : "-",
         msrn);
    iwf_imsi_trace_flush_rx(s->imsi_str);
    map_sess_remove(s);
}

static void handle_begin_sri(struct iwf_runtime *rt,
                             const ss7_sccp_addr_t *calling,
                             const tcap_msg_t *tmsg,
                             const tcap_component_t *c)
{
    char msisdn[24] = "";
    if (map_decode_sri_arg(c->parameters, c->parameters_len,
                           msisdn, sizeof(msisdn)) < 0) {
        LOGW("map", "[?] RX BEGIN SRI otid=0x%08x: no MSISDN -> "
             "unexpectedDataValue", tmsg->otid);
        sri_send_error(rt, calling, tmsg, c->invoke_id,
                       MAP_ERR_UNEXPECTED_DATA_VALUE);
        return;
    }

    char norm[24];
    map_normalize_msisdn_digits(msisdn, norm, sizeof(norm));

    char imsi[16] = "";
    bool cs_active_hss = false;
    bool on_local_msc = false;
    char vlr_gt[24] = "";

    msisdn_db_cs_t cs;
    if (norm[0] && msisdn_db_lookup_cs(norm, &cs) == 0) {
        snprintf(imsi, sizeof(imsi), "%s", cs.imsi);
        cs_active_hss = cs.cs_active;
        if (cs.have_vlr)
            snprintf(vlr_gt, sizeof(vlr_gt), "%s", cs.vlr_number);
        on_local_msc = cs_active_hss && vlr_gt_is_local(rt, vlr_gt);
#ifdef GSUP_PROXY_ENABLED
        if (cs.imsi[0])
            gsup_map_proxy_note_msisdn(cs.imsi, norm);
#endif
    }

#ifdef GSUP_PROXY_ENABLED
    if (!imsi[0] &&
        gsup_map_proxy_imsi_for_msisdn(msisdn, imsi, sizeof(imsi)) == 0) {
        on_local_msc = gsup_map_proxy_cs_conn_for_imsi(imsi) >= 0;
    }
#endif

    if (!imsi[0]) {
        LOGI("map", "[?] SRI msisdn=%s -> unknownSubscriber", msisdn);
        sri_send_error(rt, calling, tmsg, c->invoke_id,
                       MAP_ERR_UNKNOWN_SUBSCRIBER);
        return;
    }

    LOGI("map",
         "[%s] RX BEGIN SRI otid=0x%08x invoke=%u msisdn=%s hss_cs=%d vlr=%s local_msc=%d",
         imsi, tmsg->otid, (unsigned)c->invoke_id, msisdn,
         cs_active_hss ? 1 : 0,
         vlr_gt[0] ? vlr_gt : "-",
         on_local_msc ? 1 : 0);

    if (on_local_msc) {
        (void)sri_send_local_msrn(rt, calling, tmsg, c, imsi,
                                  norm[0] ? norm : msisdn);
        return;
    }

    if (cs_active_hss && vlr_gt[0] && !vlr_gt_is_local(rt, vlr_gt)) {
        map_session_t *s = map_sess_create(map_sess_new_tid());
        if (!s) {
            sri_send_error(rt, calling, tmsg, c->invoke_id,
                           MAP_ERR_SYSTEM_FAILURE);
            return;
        }
        s->map_op = MAP_OP_SRI;
        s->state = MAP_SESS_WAIT_MAP_ACK;
        snprintf(s->imsi_str, sizeof(s->imsi_str), "%s", imsi);
        snprintf(s->msisdn_str, sizeof(s->msisdn_str), "%s",
                 norm[0] ? norm : msisdn);
        s->peer_tcap_dialogue_id = tmsg->otid;
        s->have_peer_tid = tmsg->have_otid;
        s->peer_invoke_id = c->invoke_id;
        s->t_dialogue_ms = rt->cfg.map_t_dialogue_ms > 0
                           ? rt->cfg.map_t_dialogue_ms : TCAP_DEFAULT_T_MS;
        if (calling)
            map_sess_store_peer(s, calling);
        if (sri_send_prn_to_vlr(rt, s, vlr_gt,
                                norm[0] ? norm : msisdn) < 0) {
            sri_send_error(rt, calling, tmsg, c->invoke_id,
                           MAP_ERR_SYSTEM_FAILURE);
            map_sess_remove(s);
        }
        return;
    }

    LOGI("map", "[%s] SRI msisdn=%s -> absentSubscriber", imsi, msisdn);
    sri_send_error(rt, calling, tmsg, c->invoke_id,
                   MAP_ERR_ABSENT_SUBSCRIBER);
}

/* ----- Continue / End handlers (ISD ack from VLR/SGSN) ----------------- */

static void finish_ul_with_result(struct iwf_runtime *rt, map_session_t *s)
{
    uint8_t params[64];
    int pn = encode_loc_up_res(rt, params, sizeof(params));
    if (pn < 0) {
        send_tcap_end_with_error(rt, s, s->peer_invoke_id, MAP_ERR_SYSTEM_FAILURE, 1);
        return;
    }
    send_tcap_end_with_result(rt, s, s->peer_invoke_id,
                              MAP_OP_CODE_UPDATE_LOCATION,
                              params, (size_t)pn);
}

static void finish_ugl_with_result(struct iwf_runtime *rt, map_session_t *s)
{
    uint8_t params[64];
    int pn = encode_loc_up_res(rt, params, sizeof(params));
    if (pn < 0) {
        send_tcap_end_with_error(rt, s, s->peer_invoke_id, MAP_ERR_SYSTEM_FAILURE, 1);
        return;
    }
    send_tcap_end_with_result(rt, s, s->peer_invoke_id,
                              MAP_OP_CODE_UPDATE_GPRS_LOCATION,
                              params, (size_t)pn);
}

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
    map_sess_touch(s);
    iwf_imsi_trace_flush_rx(s->imsi_str);

    /* SRI -> PRN on visited VLR: complete SRI when PRN ReturnResult arrives. */
    if (s->state == MAP_SESS_WAIT_MAP_ACK && s->map_op == MAP_OP_SRI) {
        for (size_t i = 0; i < tmsg->n_components; i++) {
            const tcap_component_t *c = &tmsg->components[i];
            if (c->kind == TCAP_CMP_KIND_ERR) {
                tcap_msg_t fake = {0};
                fake.otid = s->peer_tcap_dialogue_id;
                fake.have_otid = s->have_peer_tid;
                sri_send_error(rt, &s->peer_sccp, &fake, s->peer_invoke_id,
                               MAP_ERR_SYSTEM_FAILURE);
                map_sess_remove(s);
                return;
            }
            if (c->kind == TCAP_CMP_KIND_RES &&
                c->opcode == MAP_OP_CODE_PROVIDE_ROAMING_NUMBER) {
                finish_sri_from_prn(rt, s, c->parameters, c->parameters_len);
                return;
            }
        }
        if (tmsg->type == TCAP_MSG_END) {
            tcap_msg_t fake = {0};
            fake.otid = s->peer_tcap_dialogue_id;
            fake.have_otid = s->have_peer_tid;
            sri_send_error(rt, &s->peer_sccp, &fake, s->peer_invoke_id,
                           MAP_ERR_SYSTEM_FAILURE);
            map_sess_remove(s);
        }
        return;
    }

    /* MAP-C UL: ISD ReturnResult on the same networkLocUp dialogue. */
    if (s->state == MAP_SESS_WAIT_MAP_ACK && s->map_op == MAP_OP_UL) {
        if (tmsg->have_otid) {
            s->peer_tcap_dialogue_id = tmsg->otid;
            s->have_peer_tid = true;
        }
        if (tmsg->type == TCAP_MSG_END) {
            LOGI("map",
                 "[%s] ISD ack via END tid=0x%08x -> TX UL End",
                 s->imsi_str, s->tcap_dialogue_id);
        } else {
            LOGI("map", "[%s] ISD acked on UL dialogue tid=0x%08x -> TX UL End",
                 s->imsi_str, s->tcap_dialogue_id);
        }
        finish_ul_with_result(rt, s);
        return;
    }

    /* Standalone ISD dialogue (UGL path): ack then UGL ReturnResult on parent. */
    if (s->state == MAP_SESS_WAIT_MAP_ACK && s->map_op == MAP_OP_ISD) {
        if (s->have_parent_tid) {
            map_session_t *parent =
                map_sess_find_by_tid(s->parent_tcap_dialogue_id);
            if (parent && parent->map_op == MAP_OP_UGL &&
                parent->state == MAP_SESS_WAIT_MAP_ACK) {
                LOGI("map",
                     "[%s] ISD acked tid=0x%08x -> TX UGL End (parent tid=0x%08x)",
                     parent->imsi_str,
                     s->tcap_dialogue_id,
                     parent->tcap_dialogue_id);
                finish_ugl_with_result(rt, parent);
            }
        } else {
            LOGI("map", "[%s] ISD acked by SGSN tid=0x%08x",
                 s->imsi_str, s->tcap_dialogue_id);
        }
        s->state = MAP_SESS_DONE;
        map_sess_remove(s);
        return;
    }

    LOGD("map", "ignoring CONTINUE/END for tid=0x%08x state=%s op=%s",
         tmsg->dtid, map_sess_state_str(s->state), map_op_str(s->map_op));
}

static void handle_abort(struct iwf_runtime *rt, const tcap_msg_t *tmsg)
{
    if (!tmsg->have_dtid) return;
    map_session_t *s = map_sess_find_by_tid(tmsg->dtid);
    if (!s) return;
    LOGW("map",
         "[%s] RX ABORT tid=0x%08x state=%s",
         s->imsi_str[0] ? s->imsi_str : "?",
         s->tcap_dialogue_id,
         map_sess_state_str(s->state));
    rt->map->stat_timeouts++;
    map_sess_remove(s);
}

/* ----- TC dialogue establishment (empty BEGIN) ---------------------- */
/* Some peers (a roaming partner SMSC/USSD-GW) open the dialogue with an empty
 * BEGIN (AARQ only) and send the actual invoke in a CONTINUE once we
 * confirm with AARE - used when BEGIN + invoke would not fit one UDT.
 * We accept, remember the peer, and route the deferred invoke to the
 * SMS/USSD handlers when it arrives. */

#define DLG_EST_ENTRIES   16
#define DLG_EST_TTL_S     15
#define DLG_EST_OTID_BIT  0x20000000u

struct dlg_est_ent {
    bool            used;
    uint32_t        our_otid;
    uint32_t        peer_otid;
    ss7_sccp_addr_t peer;
    uint8_t         dialogue[240];   /* original AARQ (AC + destinationReference) */
    uint16_t        dlen;
    time_t          ts;
};

static struct dlg_est_ent g_dlg_est[DLG_EST_ENTRIES];
static uint32_t g_dlg_est_ctr;

static struct dlg_est_ent *dlg_est_alloc(void)
{
    time_t now = time(NULL);
    struct dlg_est_ent *free_e = NULL;
    for (int i = 0; i < DLG_EST_ENTRIES; i++) {
        struct dlg_est_ent *e = &g_dlg_est[i];
        if (e->used && now - e->ts > DLG_EST_TTL_S)
            e->used = false;
        if (!e->used && !free_e)
            free_e = e;
    }
    return free_e;
}

static void handle_empty_begin(struct iwf_runtime *rt,
                               const ss7_sccp_addr_t *calling,
                               const tcap_msg_t *tmsg)
{
    uint8_t oid[16];
    size_t ol = 0;
    if (!tmsg->have_otid || !tmsg->dialogue ||
        tmsg->dialogue_len > sizeof(((struct dlg_est_ent *)0)->dialogue) ||
        map_decode_aarq_ac_raw(tmsg->dialogue, tmsg->dialogue_len,
                               oid, sizeof(oid), &ol) < 0) {
        LOGW("map", "BEGIN without Invoke component (no usable AARQ)");
        return;
    }
    /* Only accept ACs whose deferred invoke we can actually serve:
     * shortMsgMT-Relay v1/v2/v3 (0.4.0.0.1.0.25.x) and
     * networkUnstructuredSs v2 (0.4.0.0.1.0.19.2). */
    static const uint8_t pre_smsg[6] = { 0x04,0x00,0x00,0x01,0x00,0x19 };
    static const uint8_t pre_ussd[7] = { 0x04,0x00,0x00,0x01,0x00,0x13,0x02 };
    if (!(ol == 7 && (!memcmp(oid, pre_smsg, sizeof(pre_smsg)) ||
                      !memcmp(oid, pre_ussd, sizeof(pre_ussd))))) {
        LOGW("map", "empty BEGIN with unsupported AC (len=%zu); ignoring", ol);
        return;
    }

    struct dlg_est_ent *e = dlg_est_alloc();
    if (!e) {
        LOGW("map", "dialogue-establishment table full; dropping BEGIN");
        return;
    }

    uint8_t dlg[128];
    int dn = map_encode_aare_oid(oid, ol, dlg, sizeof(dlg));
    if (dn < 0) return;

    uint32_t our = DLG_EST_OTID_BIT | (++g_dlg_est_ctr & 0x0fffffffu);
    uint8_t out[256];
    int n = tcap_encode_message(TCAP_MSG_CONTINUE, our, true,
                                tmsg->otid, true,
                                dlg, (size_t)dn, NULL, 0, out, sizeof(out));
    if (n < 0) return;

    ss7_sccp_addr_t cg;
    memset(&cg, 0, sizeof(cg));
    if (rt->cfg.map_local_gt[0])
        ss7_gt_from_digits(rt->cfg.map_local_gt, SS7_SSN_MSC, &cg);
    cg.ssn = SS7_SSN_MSC;
    if (ss7_link_send_tcap_ex(rt, calling, cg.have_gt ? &cg : NULL,
                              out, (size_t)n) < 0)
        return;

    memset(e, 0, sizeof(*e));
    e->used = true;
    e->our_otid = our;
    e->peer_otid = tmsg->otid;
    e->peer = *calling;
    memcpy(e->dialogue, tmsg->dialogue, tmsg->dialogue_len);
    e->dlen = (uint16_t)tmsg->dialogue_len;
    e->ts = time(NULL);
    LOGI("map",
         "empty BEGIN peer_otid=0x%08x -> TX CONTINUE AARE (our_otid=0x%08x)",
         tmsg->otid, our);
}

/* CONTINUE carrying the deferred invoke of an established dialogue.
 * Returns true if the message belonged to (and consumed) an entry. */
static bool dlg_est_on_tcap(struct iwf_runtime *rt,
                            const ss7_sccp_addr_t *calling,
                            const tcap_msg_t *tmsg)
{
    if (!tmsg->have_dtid) return false;
    struct dlg_est_ent *e = NULL;
    for (int i = 0; i < DLG_EST_ENTRIES; i++) {
        if (g_dlg_est[i].used && g_dlg_est[i].our_otid == tmsg->dtid) {
            e = &g_dlg_est[i];
            break;
        }
    }
    if (!e) return false;
    e->used = false;

    if (tmsg->type != TCAP_MSG_CONTINUE || tmsg->n_components == 0 ||
        tmsg->components[0].kind != TCAP_CMP_KIND_INVOKE) {
        LOGI("map", "established dialogue 0x%08x closed without invoke",
             tmsg->dtid);
        return true;
    }
    const tcap_component_t *c = &tmsg->components[0];
    LOGI("map", "established dialogue 0x%08x: deferred invoke op=%d",
         tmsg->dtid, c->opcode);

    switch (c->opcode) {
#ifdef SMS_IWF_ENABLED
    case MAP_OP_CODE_MT_FORWARD_SM_V3:
    case MAP_OP_CODE_MT_FORWARD_SM:
        if (sms_iwf_enabled(rt)) {
            /* AARE already sent in our CONTINUE: strip the dialogue so
             * the SMS handler's END does not repeat it. */
            tcap_msg_t t2 = *tmsg;
            t2.dialogue = NULL;
            t2.dialogue_len = 0;
            sms_iwf_on_mt_fsm(rt, calling, &t2, c);
        }
        break;
#endif
#ifdef GSUP_PROXY_ENABLED
    case MAP_OP_CODE_USS_REQUEST:
    case MAP_OP_CODE_USS_NOTIFY:
    case MAP_OP_CODE_PROCESS_USS_REQ: {
        /* destinationReference (IMSI) came in the original AARQ. */
        tcap_msg_t t2 = *tmsg;
        t2.dialogue = e->dialogue;
        t2.dialogue_len = e->dlen;
        ussd_iwf_on_ni_begin(rt, calling, &t2, c, true /* aare_done */);
        break;
    }
#endif
    default:
        LOGW("map", "deferred invoke op=%d unsupported; dropping", c->opcode);
        break;
    }
    return true;
}

/* ----- SCCP receive entrypoint (set on ss7_link at init) ----------- */

static void on_sccp_pdu(struct iwf_runtime *rt,
                        const ss7_sccp_addr_t *calling,
                        const uint8_t *tcap, size_t tcap_len)
{
    rt->map->stat_map_rx++;
    iwf_imsi_trace_bind_rx("map", tcap, tcap_len);

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
            /* Dialogue establishment: AARQ only, invoke follows in a
             * CONTINUE after we confirm (a roaming partner SMSC/USSD pattern). */
            handle_empty_begin(rt, calling, &tmsg);
            return;
        }
        const tcap_component_t *c = &tmsg.components[0];
        switch (c->opcode) {
        case MAP_OP_CODE_SEND_AUTH_INFO:        handle_begin_sai  (rt, calling, &tmsg, c); break;
        case MAP_OP_CODE_UPDATE_LOCATION:        handle_begin_ul   (rt, calling, &tmsg, c); break;
        case MAP_OP_CODE_UPDATE_GPRS_LOCATION:  handle_begin_ugl  (rt, calling, &tmsg, c); break;
        case MAP_OP_CODE_PURGE_MS:              handle_begin_purge(rt, calling, &tmsg, c); break;
        case MAP_OP_CODE_CANCEL_LOCATION:       handle_begin_cl   (rt, calling, &tmsg, c); break;
        case MAP_OP_CODE_PROVIDE_ROAMING_NUMBER: handle_begin_prn (rt, calling, &tmsg, c); break;
        case MAP_OP_CODE_PROVIDE_SUBSCRIBER_INFO: handle_begin_psi(rt, calling, &tmsg, c); break;
        case MAP_OP_CODE_SEND_ROUTING_INFO:      handle_begin_sri (rt, calling, &tmsg, c); break;
#ifdef SMS_IWF_ENABLED
        case MAP_OP_CODE_MT_FORWARD_SM_V3:      /* mt-forwardSM (v3)      */
        case MAP_OP_CODE_MT_FORWARD_SM:         /* forwardSM (v1/v2)      */
            if (sms_iwf_enabled(rt)) {
                sms_iwf_on_mt_fsm(rt, calling, &tmsg, c);
                break;
            }
            LOGW("map", "MT forwardSM received but SMS-IWF disabled");
            break;
#endif
#ifdef GSUP_PROXY_ENABLED
        case MAP_OP_CODE_USS_REQUEST:           /* network-initiated USSD */
        case MAP_OP_CODE_USS_NOTIFY:
            ussd_iwf_on_ni_begin(rt, calling, &tmsg, c, false);
            break;
        case MAP_OP_CODE_PROCESS_USS_REQ:
            /* MO USSD from one of our home subscribers roaming abroad -
             * no USSD application behind the IWF to serve it. */
            LOGI("map", "processUnstructuredSS for home subscriber -> "
                 "facilityNotSupported");
            ussd_iwf_reject_begin(rt, calling, &tmsg, c,
                                  MAP_ERR_FACILITY_NOT_SUPPORTED);
            break;
#endif
        default:
            LOGW("map", "unsupported MAP opcode=%d ac=%d in BEGIN",
                 c->opcode, ac);
            break;
        }
        return;
    }

    if (tmsg.type == TCAP_MSG_CONTINUE || tmsg.type == TCAP_MSG_END) {
        if (dlg_est_on_tcap(rt, calling, &tmsg))
            return;
#ifdef SMS_IWF_ENABLED
        if (sms_iwf_enabled(rt) && sms_iwf_on_mo_tcap(rt, &tmsg))
            return;
#endif
#ifdef GSUP_PROXY_ENABLED
        if (ussd_iwf_on_tcap(rt, calling, &tmsg))
            return;
        if (gsup_map_proxy_on_tcap(rt, calling, &tmsg))
            return;
#endif
        handle_continue_or_end(rt, &tmsg);
        return;
    }
    if (tmsg.type == TCAP_MSG_ABORT) {
#ifdef GSUP_PROXY_ENABLED
        if (ussd_iwf_on_tcap(rt, calling, &tmsg))
            return;
        if (gsup_map_proxy_on_tcap(rt, calling, &tmsg))
            return;
#endif
        handle_abort(rt, &tmsg);
        return;
    }
}

void map_iwf_on_sccp_unitdata(struct iwf_runtime *rt,
                              const ss7_sccp_addr_t *calling,
                              const uint8_t *tcap, size_t tcap_len)
{
    if (!rt || !rt->map || !calling || !tcap || !tcap_len)
        return;
    on_sccp_pdu(rt, calling, tcap, tcap_len);
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
        LOGE("map", "[%s] tcap_enc_return_result failed", s->imsi_str);
        return -1;
    }
    /* AARE dialogue portion (omit if already sent on an earlier CONTINUE). */
    uint8_t dlg[128]; int dn = 0;
    const uint8_t *dlg_ptr = NULL;
    if (!s->aare_sent) {
        dn = map_encode_aare(ac_for_op(s->map_op), dlg, sizeof(dlg));
        if (dn < 0) return -1;
        dlg_ptr = dlg;
    }

    uint8_t out[3072];
    int n = tcap_encode_message(TCAP_MSG_END,
                                0, false,
                                s->peer_tcap_dialogue_id, s->have_peer_tid,
                                dlg_ptr, (size_t)dn,
                                cmp, co,
                                out, sizeof(out));
    if (n < 0) return -1;

    int rc = map_send_tcap_to_peer(rt, s, out, (size_t)n);
    if (rc == 0) {
        rt->map->stat_map_tx++;
        LOGI("map",
         "[%s] TX END dtid=0x%08x op=%s len=%d",
         s->imsi_str,
         s->peer_tcap_dialogue_id,
         map_op_str(s->map_op),
         n);
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

    int rc = map_send_tcap_to_peer(rt, s, out, (size_t)n);
    if (rc == 0) {
        rt->map->stat_systemfailures_sent++;
        rt->map->stat_map_tx++;
        LOGW("map",
         "[%s] TX END(Error %d) dtid=0x%08x op=%s",
         s->imsi_str,
         map_error_code,
         s->peer_tcap_dialogue_id,
         map_op_str(s->map_op));
        s->state = MAP_SESS_DONE;
        map_sess_remove(s);
    }
    return rc;
}

/* ====================================================================== */
/* Diameter answer handlers (called by diameter.c)                         */
/* ====================================================================== */

static void avp_copy_octets(uint8_t *dst, size_t dst_len, const diameter_avp_t *a)
{
    if (!dst || !a || !a->data || a->data_len == 0)
        return;
    size_t n = a->data_len > dst_len ? dst_len : a->data_len;
    memcpy(dst, a->data, n);
}

/* Parse one E-UTRAN/UTRAN/GERAN-Vector grouped AVP into map_auth_vector_t. */
static int parse_vector_avp(const uint8_t *body, size_t len,
                            map_auth_vector_t *v)
{
    diameter_avp_t a;
    memset(v, 0, sizeof(*v));

    if (diameter_avp_find_3gpp_recursive(body, len, AVP_3GPP_RAND, &a) == 0)
        avp_copy_octets(v->rand, sizeof(v->rand), &a);
    if (diameter_avp_find_3gpp_recursive(body, len, AVP_3GPP_XRES, &a) == 0) {
        avp_copy_octets(v->xres, sizeof(v->xres), &a);
        v->xres_len = (uint8_t)(a.data_len > 16 ? 16 : a.data_len);
    }
    if (diameter_avp_find_3gpp_recursive(body, len, AVP_3GPP_AUTN, &a) == 0)
        avp_copy_octets(v->autn, sizeof(v->autn), &a);
    if (diameter_avp_find_3gpp_recursive(body, len, AVP_3GPP_CK, &a) == 0)
        avp_copy_octets(v->ck, sizeof(v->ck), &a);
    if (diameter_avp_find_3gpp_recursive(body, len, AVP_3GPP_IK, &a) == 0)
        avp_copy_octets(v->ik, sizeof(v->ik), &a);

    /* GERAN-Vector: Kc/SRES when CK/IK absent. */
    if (diameter_avp_find_3gpp_recursive(body, len, AVP_3GPP_KC, &a) == 0) {
        avp_copy_octets(v->kc, sizeof(v->kc), &a);
        if (!v->ck[0] && !v->ck[1])
            memcpy(v->ck, v->kc, sizeof(v->kc));
        v->have_triplet = true;
    }
    if (diameter_avp_find_3gpp_recursive(body, len, AVP_3GPP_SRES, &a) == 0) {
        avp_copy_octets(v->sres, sizeof(v->sres), &a);
        if (v->xres_len == 0) {
            size_t n = a.data_len > 16 ? 16 : a.data_len;
            memcpy(v->xres, a.data, n);
            v->xres_len = (uint8_t)n;
        }
    }

    v->have_quintuplet = v->rand[0] || v->rand[1];
    return 0;
}

static bool auth_vector_has_ckik(const map_auth_vector_t *v)
{
    for (int i = 0; i < 16; i++) {
        if (v->ck[i] || v->ik[i])
            return true;
    }
    return false;
}

static int auth_vector_find_rand(map_session_t *s, const uint8_t rand[16])
{
    for (uint8_t i = 0; i < s->n_av; i++) {
        if (!memcmp(s->av[i].rand, rand, 16))
            return (int)i;
    }
    return -1;
}

static void auth_vector_merge_ckik(map_auth_vector_t *dst,
                                 const map_auth_vector_t *src)
{
    if (auth_vector_has_ckik(dst) || !auth_vector_has_ckik(src))
        return;
    if (memcmp(dst->rand, src->rand, 16))
        return;
    memcpy(dst->ck, src->ck, 16);
    memcpy(dst->ik, src->ik, 16);
}

static void aia_collect_vectors(const uint8_t *buf, size_t len,
                                map_session_t *s, int depth)
{
    diameter_avp_t it;
    if (!buf || len < 8 || depth > 8 || !s)
        return;
    if (diameter_avp_first(buf, len, &it) < 0)
        return;
    for (;;) {
        bool is_vec = (it.code == AVP_3GPP_E_UTRAN_VECTOR ||
                       it.code == AVP_3GPP_UTRAN_VECTOR  ||
                       it.code == AVP_3GPP_GERAN_VECTOR) &&
                      (it.vendor_id == DIAMETER_VENDOR_3GPP ||
                       !(it.flags & DIAM_AVP_FLAG_VENDOR));
        if (is_vec && s->n_av < MAP_AUTH_VECTOR_MAX) {
            map_auth_vector_t tmp;
            parse_vector_avp(it.data, it.data_len, &tmp);
            if (tmp.have_quintuplet || tmp.have_triplet) {
                int idx = auth_vector_find_rand(s, tmp.rand);
                if (idx >= 0)
                    auth_vector_merge_ckik(&s->av[idx], &tmp);
                else
                    s->av[s->n_av++] = tmp;
            }
        } else if (it.data_len >= 8) {
            aia_collect_vectors(it.data, it.data_len, s, depth + 1);
        }
        if (diameter_avp_next(buf, len, &it) < 0)
            break;
    }
}

static void aia_finalize_vectors(map_session_t *s)
{
    for (uint8_t i = 0; i < s->n_av; i++) {
        for (uint8_t j = 0; j < s->n_av; j++)
            if (i != j)
                auth_vector_merge_ckik(&s->av[i], &s->av[j]);
    }
    for (uint8_t i = 1; i < s->n_av; i++) {
        if (auth_vector_has_ckik(&s->av[i]) &&
            !auth_vector_has_ckik(&s->av[0])) {
            map_auth_vector_t tmp = s->av[0];
            s->av[0] = s->av[i];
            s->av[i] = tmp;
        }
    }
}

void map_iwf_on_aia(struct iwf_runtime *rt, map_session_t *s,
                    const uint8_t *body, size_t body_len)
{
    const bool is_cmd_test = s->cmd_test;

    s->n_av = 0;
    aia_collect_vectors(body, body_len, s, 0);
    aia_finalize_vectors(s);

    LOGI("map",
         "[%s] AIA vectors=%u -> emitting MAP SAI Resp",
         s->imsi_str,
         s->n_av);
    if (s->gsup_originated && s->n_av > 0 && !auth_vector_has_ckik(&s->av[0]))
        LOGW("map",
         "[%s] AIA: no CK/IK (Confidentiality-Key/625, Integrity-Key/626)",
         s->imsi_str);

    if (s->n_av == 0) {
        LOGW("map", "[%s] AIA: no auth vectors in answer", s->imsi_str);
        if (is_cmd_test) {
            cmd_test_abort(s, "no_vectors");
            return;
        }
        if (s->gsup_originated) {
#ifdef GSUP_PROXY_ENABLED
            gsup_map_proxy_diameter_error(rt, s, 0);
#endif
            return;
        }
        send_tcap_end_with_error(rt, s, s->peer_invoke_id, MAP_ERR_SYSTEM_FAILURE, 1);
        return;
    }

    if (is_cmd_test) {
        int fd = s->cmd_test_reply_fd;
        s->cmd_test_reply_fd = -1;
        s->cmd_test = false;
        if (fd >= 0) {
            test_cmd_reply_ok(fd, (unsigned)s->n_av,
                              s->av[0].rand, s->av[0].autn);
            close(fd);
        } else {
            LOGI("map",
         "[%s] cmd-test SAI OK vectors=%u",
         s->imsi_str,
         (unsigned)s->n_av);
        }
        map_sess_remove(s);
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
        send_tcap_end_with_error(rt, s, s->peer_invoke_id, MAP_ERR_SYSTEM_FAILURE, 1);
        return;
    }
    send_tcap_end_with_result(rt, s, s->peer_invoke_id,
                              MAP_OP_CODE_SEND_AUTH_INFO,
                              params, (size_t)pn);
}

/* Extract subscription data from ULA (MSISDN, APN config, AMBR). */
static int ula_parse_served_party_ip(const uint8_t *data, size_t len,
                                     bool *has_v4, uint8_t v4[4],
                                     bool *has_v6, uint8_t v6[16])
{
    if (!data || len < 2)
        return -1;

    uint16_t addr_type = (uint16_t)((data[0] << 8) | data[1]);
    if (addr_type == 1 && len >= 6) {
        if (has_v4) *has_v4 = true;
        if (v4) memcpy(v4, data + 2, 4);
        return 0;
    }
    if (addr_type == 2 && len >= 18) {
        if (has_v6) *has_v6 = true;
        if (v6) memcpy(v6, data + 2, 16);
        return 0;
    }
    return -1;
}

/* Parse the serving PGW (IPv4 and/or FQDN) from MIP6-Agent-Info (RFC 5447)
 * inside one APN-Configuration. The PGW IPv4 is MIP-Home-Agent-Address (334,
 * Address: 2-byte family + addr, family 1 = IPv4); the PGW FQDN is
 * Destination-Host (293) inside MIP-Home-Agent-Host (348). These are IETF
 * AVPs carried without a vendor flag, so look them up with vendor_id 0.
 * PDN-GW-Allocation-Type (1438, 3GPP) records static vs dynamic. */
static void ula_parse_pgw_from_apnc(const diameter_avp_t *apnc,
                                    map_ula_apn_entry_t *e)
{
    diameter_avp_t mip6;
    if (diameter_avp_find(apnc->data, apnc->data_len,
                          AVP_MIP6_AGENT_INFO, 0, &mip6) == 0) {
        diameter_avp_t haa;
        if (diameter_avp_find(mip6.data, mip6.data_len,
                              AVP_MIP_HOME_AGENT_ADDRESS, 0, &haa) == 0 &&
            haa.data_len >= 6) {
            uint16_t fam = (uint16_t)((haa.data[0] << 8) | haa.data[1]);
            if (fam == 1) {                 /* IANA address family IPv4 */
                memcpy(e->pgw_ipv4, haa.data + 2, 4);
                e->has_pgw_ipv4 = true;
            }
        }
        diameter_avp_t hah;
        if (diameter_avp_find(mip6.data, mip6.data_len,
                              AVP_MIP_HOME_AGENT_HOST, 0, &hah) == 0) {
            diameter_avp_t dh;
            if (diameter_avp_find(hah.data, hah.data_len,
                                  AVP_DESTINATION_HOST, 0, &dh) == 0 &&
                dh.data_len > 0) {
                size_t n = dh.data_len < sizeof(e->pgw_fqdn) - 1
                               ? dh.data_len : sizeof(e->pgw_fqdn) - 1;
                memcpy(e->pgw_fqdn, dh.data, n);
                e->pgw_fqdn[n] = '\0';
            }
        }
    }

    diameter_avp_t alloc;
    if (diameter_avp_find(apnc->data, apnc->data_len,
                          AVP_3GPP_PDN_GW_ALLOCATION_TYPE,
                          DIAMETER_VENDOR_3GPP, &alloc) == 0 &&
        alloc.data_len >= 4) {
        e->pgw_alloc_dynamic = (iwf_be32(alloc.data) == 1) ? 1 : 0;
    }
}

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

    diameter_avp_t ip_it;
    if (diameter_avp_first(apnc->data, apnc->data_len, &ip_it) == 0) {
        for (;;) {
            if (ip_it.code == AVP_3GPP_SERVED_PARTY_IP_ADDRESS &&
                ip_it.vendor_id == DIAMETER_VENDOR_3GPP) {
                bool hv4 = false, hv6 = false;
                uint8_t v4[4], v6[16];
                if (ula_parse_served_party_ip(ip_it.data, ip_it.data_len,
                                              &hv4, v4, &hv6, v6) == 0) {
                    if (hv4) {
                        e->has_ue_ipv4 = true;
                        memcpy(e->ue_ipv4, v4, 4);
                    }
                    if (hv6) {
                        e->has_ue_ipv6 = true;
                        memcpy(e->ue_ipv6, v6, 16);
                    }
                }
            }
            if (diameter_avp_next(apnc->data, apnc->data_len, &ip_it) < 0)
                break;
        }
    }

    ula_parse_pgw_from_apnc(apnc, e);

    s->n_ula_apns++;
    return 0;
}

static void decode_ula_msisdn(const uint8_t *data, size_t n, char *out, size_t cap)
{
    map_msisdn_avp_to_str(data, n, out, cap);
}

static void ula_collect_apn_configs(map_session_t *s,
                                  const uint8_t *buf, size_t len)
{
    diameter_avp_t it;
    if (!s || !buf || len < 8) return;
    if (diameter_avp_first(buf, len, &it) < 0) return;
    for (;;) {
        if (it.code == AVP_3GPP_APN_CONFIGURATION &&
            it.vendor_id == DIAMETER_VENDOR_3GPP)
            (void)ula_add_apn_entry(s, &it);
        if (it.data_len >= 8)
            ula_collect_apn_configs(s, it.data, it.data_len);
        if (diameter_avp_next(buf, len, &it) < 0)
            break;
    }
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
    s->have_ula_subdata = false;

    diameter_avp_t msisdn_avp;
    if (diameter_avp_find_recursive(body, body_len, AVP_3GPP_MSISDN,
                                    DIAMETER_VENDOR_3GPP, &msisdn_avp) == 0)
        decode_ula_msisdn(msisdn_avp.data, msisdn_avp.data_len,
                          s->msisdn_str, sizeof(s->msisdn_str));

    diameter_avp_t sd;
    if (diameter_avp_find_recursive(body, body_len, AVP_3GPP_SUBSCRIPTION_DATA,
                          DIAMETER_VENDOR_3GPP, &sd) < 0) {
        if (s->msisdn_str[0]) {
            s->have_ula_subdata = true;
            LOGI("map",
         "[%s] ULA msisdn=%s (no Subscription-Data AVP)",
         s->imsi_str,
         s->msisdn_str);
        } else {
            LOGW("map",
         "[%s] ULA: no Subscription-Data and no MSISDN (check Open5GS subscriber msisdn[] in MongoDB)",
         s->imsi_str);
        }
        return;
    }

    s->have_ula_subdata = true;

    if (!s->msisdn_str[0] &&
        diameter_avp_find(sd.data, sd.data_len, AVP_3GPP_MSISDN,
                          DIAMETER_VENDOR_3GPP, &msisdn_avp) == 0)
        decode_ula_msisdn(msisdn_avp.data, msisdn_avp.data_len,
                          s->msisdn_str, sizeof(s->msisdn_str));

    /* CS (MAP UL or GSUP CN=CS): MSISDN only toward VLR/MSC; skip GPRS APN walk. */
#ifdef GSUP_PROXY_ENABLED
    const bool want_apn =
        !(s->map_op == MAP_OP_UL ||
          (s->gsup_originated && s->gsup_cn_domain == GSUP_CN_DOMAIN_CS));
#else
    const bool want_apn = (s->map_op != MAP_OP_UL);
#endif

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

    if (want_apn && s->n_ula_apns == 0)
        ula_collect_apn_configs(s, sd.data, sd.data_len);

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

    /* Bridge the HSS-advertised PGW into the GTP path. The Gn Create PDP
     * Context arrives later, after this MAP/Diameter session is gone, so the
     * cache (keyed by IMSI+APN) lets translate.c anchor the S5/S8 session at
     * the PGW the subscriber's HSS selected — home PGW for home-routed
     * roamers, local PGW for home subscribers (no static [smf] required). */
    for (uint8_t i = 0; i < s->n_ula_apns; i++) {
        const map_ula_apn_entry_t *a = &s->ula_apns[i];
        if (!a->apn[0])
            continue;
        uint32_t pgw = a->has_pgw_ipv4
            ? ((uint32_t)a->pgw_ipv4[0] << 24 | (uint32_t)a->pgw_ipv4[1] << 16 |
               (uint32_t)a->pgw_ipv4[2] << 8  | (uint32_t)a->pgw_ipv4[3])
            : 0;
        if (pgw || a->pgw_fqdn[0])
            subscr_cache_put_pgw(s->imsi_str, a->apn, pgw,
                                 a->pgw_fqdn, a->pgw_alloc_dynamic);
    }

    if (s->n_ula_apns <= 1) {
        LOGI("map",
         "[%s] ULA msisdn=%s apn=%s ambr=%lu/%lu bps",
         s->imsi_str,
         s->msisdn_str[0] ? s->msisdn_str : "(none)",
         s->ula_apn[0]   ? s->ula_apn   : "(none)",
         (unsigned long)s->ula_ambr_ul_bps,
         (unsigned long)s->ula_ambr_dl_bps);
    } else {
        LOGI("map",
         "[%s] ULA msisdn=%s apns=%u default_ctx=%u ambr=%lu/%lu bps",
         s->imsi_str,
         s->msisdn_str[0] ? s->msisdn_str : "(none)",
         (unsigned)s->n_ula_apns,
         (unsigned)s->ula_default_context_id,
         (unsigned long)s->ula_ambr_ul_bps,
         (unsigned long)s->ula_ambr_dl_bps);
        for (uint8_t i = 0; i < s->n_ula_apns; i++) {
            const map_ula_apn_entry_t *a = &s->ula_apns[i];
            char pgw[64] = "";
            if (a->has_pgw_ipv4)
                snprintf(pgw, sizeof(pgw), " pgw=%u.%u.%u.%u",
                         (unsigned)a->pgw_ipv4[0], (unsigned)a->pgw_ipv4[1],
                         (unsigned)a->pgw_ipv4[2], (unsigned)a->pgw_ipv4[3]);
            else if (a->pgw_fqdn[0])
                snprintf(pgw, sizeof(pgw), " pgw_fqdn=%s", a->pgw_fqdn);
            if (a->has_ue_ipv4) {
                LOGI("map", "  ULA APN[%u] ctx=%u apn=%s pdp=0x%02x static_v4=%u.%u.%u.%u%s",
                     (unsigned)i, (unsigned)a->context_id, a->apn,
                     (unsigned)a->pdn_type_nr,
                     (unsigned)a->ue_ipv4[0], (unsigned)a->ue_ipv4[1],
                     (unsigned)a->ue_ipv4[2], (unsigned)a->ue_ipv4[3], pgw);
            } else {
                LOGI("map", "  ULA APN[%u] ctx=%u apn=%s pdp=0x%02x%s",
                     (unsigned)i, (unsigned)a->context_id, a->apn,
                     (unsigned)a->pdn_type_nr, pgw);
            }
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
static void send_isd_invoke(struct iwf_runtime *rt, map_session_t *parent,
                            bool isd_before_loc_up);

/* UpdateLocationRes / UpdateGprsLocationRes: hlr-Number = local_gt when set. */
static int encode_loc_up_res(struct iwf_runtime *rt,
                             uint8_t *params, size_t params_cap)
{
    uint8_t buf[16];
    size_t len = 0;
    if (rt && rt->cfg.map_local_gt[0]) {
        buf[0] = 0x91;
        int n = map_str_to_bcd(rt->cfg.map_local_gt, buf + 1, sizeof(buf) - 1);
        if (n > 0)
            len = (size_t)(n + 1);
    }
    if (!len) {
        buf[0] = 0x00;
        len = 1;
    }
    return map_encode_ugl_res(buf, len, params, params_cap);
}

static int loc_up_result_opcode(map_op_t op)
{
    return (op == MAP_OP_UL) ? MAP_OP_CODE_UPDATE_LOCATION
                             : MAP_OP_CODE_UPDATE_GPRS_LOCATION;
}

void map_iwf_on_ula(struct iwf_runtime *rt, map_session_t *s,
                    const uint8_t *body, size_t body_len)
{
    if (s->gsup_originated) {
#ifdef GSUP_PROXY_ENABLED
        extract_ula_subdata(s, body, body_len);
        /* CS: ISD_REQ (step 3) must carry MSISDN before UL_RES (step 5).
         * PS: ISD carries PDP/APN; UL_RES may repeat subscription IEs. */
        if (s->gsup_cn_domain == GSUP_CN_DOMAIN_CS) {
            if (!s->msisdn_str[0]) {
                LOGE("map",
         "[%s] CS ULA: no MSISDN for ISD (Open5GS subscriber msisdn[] required)",
         s->imsi_str);
                gsup_map_proxy_abort_ugl(rt, s);
                return;
            }
            if (gsup_map_proxy_send_isd(rt, s) < 0)
                gsup_map_proxy_abort_ugl(rt, s);
            return;
        }
        bool need_isd = s->msisdn_str[0] != '\0' || s->n_ula_apns > 0;
        if (s->have_ula_subdata && need_isd) {
            if (gsup_map_proxy_send_isd(rt, s) < 0)
                gsup_map_proxy_abort_ugl(rt, s);
        } else {
            gsup_map_proxy_finish_ugl(rt, s);
        }
#endif
        return;
    }
    extract_ula_subdata(s, body, body_len);

    if (s->map_op == MAP_OP_UL && !s->msisdn_str[0]) {
        LOGE("map",
             "[%s] CS ULA: no MSISDN for ISD (Open5GS subscriber msisdn[] required)",
             s->imsi_str);
        send_tcap_end_with_error(rt, s, s->peer_invoke_id,
                                 MAP_ERR_UNKNOWN_SUBSCRIBER, 1);
        return;
    }

    bool need_isd = (s->map_op == MAP_OP_UL && s->msisdn_str[0]) ||
                    (s->map_op == MAP_OP_UGL && s->n_ula_apns > 0);
    if (s->have_ula_subdata && need_isd) {
#ifdef GSUP_PROXY_ENABLED
        /* Outbound roam: foreign VLR UL updates HSS; home MSC still needs
         * GSUP ISD so MT-SMS / SGs delivery has a local VLR record. */
        if (s->map_op == MAP_OP_UL && s->msisdn_str[0])
            (void)gsup_map_proxy_push_cs_isd(rt, s->imsi_str, s->msisdn_str);
#endif
        send_isd_invoke(rt, s, rt->cfg.map_isd_before_loc_up);
        return;
    }
    uint8_t params[64];
    int pn = encode_loc_up_res(rt, params, sizeof(params));
    if (pn < 0) {
        send_tcap_end_with_error(rt, s, s->peer_invoke_id, MAP_ERR_SYSTEM_FAILURE, 1);
        return;
    }
    send_tcap_end_with_result(rt, s, s->peer_invoke_id,
                              loc_up_result_opcode(s->map_op),
                              params, (size_t)pn);
}

static void send_isd_invoke(struct iwf_runtime *rt, map_session_t *parent,
                            bool isd_before_loc_up)
{
    const bool cs_vlr_isd = (parent->map_op == MAP_OP_UL);
    /* CS MAP UL: MSISDN only (no GPRS PDP list toward VLR). */
    const map_ula_apn_entry_t *apns = parent->ula_apns;
    size_t n_apns = parent->n_ula_apns;
    if (parent->map_op == MAP_OP_UL) {
        apns = NULL;
        n_apns = 0;
    }

    uint8_t arg[1024];
    int an = map_encode_isd_arg(parent->imsi_str,
                                parent->msisdn_str,
                                apns,
                                n_apns,
                                parent->ula_default_context_id,
                                cs_vlr_isd,
                                arg, sizeof(arg));
    if (an < 0) {
        LOGE("map", "[%s] ISD: encode failed", parent->imsi_str);
        send_tcap_end_with_error(rt, parent, parent->peer_invoke_id,
                                 MAP_ERR_SYSTEM_FAILURE, 1);
        return;
    }

    /* Loc-up ReturnResult first, then ISD on a separate dialogue. */
    if (!isd_before_loc_up) {
        ss7_sccp_addr_t peer_sccp = parent->peer_sccp;
        bool have_peer = parent->have_peer_sccp;
        char imsi[MAP_IMSI_STR_MAX];
        char msisdn[MAP_MSISDN_STR_MAX];
        int t_dialogue_ms = parent->t_dialogue_ms;
        map_op_t loc_op = parent->map_op;

        memcpy(imsi, parent->imsi_str, sizeof(imsi));
        memcpy(msisdn, parent->msisdn_str, sizeof(msisdn));

        if (loc_op == MAP_OP_UL)
            finish_ul_with_result(rt, parent);
        else if (loc_op == MAP_OP_UGL)
            finish_ugl_with_result(rt, parent);
        else
            return;

        map_session_t *isd = map_sess_create(map_sess_new_tid());
        if (!isd) {
            LOGE("map", "[%s] ISD: alloc failed (after loc-up End)", imsi);
            return;
        }
        isd->map_op = MAP_OP_ISD;
        isd->state  = MAP_SESS_WAIT_MAP_ACK;
        isd->t_dialogue_ms = t_dialogue_ms;
        memcpy(isd->imsi_str, imsi, sizeof(isd->imsi_str));

        uint8_t cmp[1200]; size_t co = 0;
        if (tcap_enc_invoke(cmp, sizeof(cmp), &co, 1,
                            MAP_OP_CODE_INSERT_SUBSCRIBER_DATA,
                            arg, (size_t)an) < 0) {
            map_sess_remove(isd);
            return;
        }
        uint8_t dlg[128];
        int dn = map_encode_aarq(MAP_AC_SUBSCRIBER_DATA_MGMT_V3, dlg, sizeof(dlg));
        if (dn < 0) {
            map_sess_remove(isd);
            return;
        }
        uint8_t out[2048];
        int n = tcap_encode_message(TCAP_MSG_BEGIN,
                                    isd->tcap_dialogue_id, true,
                                    0, false,
                                    dlg, (size_t)dn,
                                    cmp, co,
                                    out, sizeof(out));
        if (n < 0) {
            map_sess_remove(isd);
            return;
        }
        if (have_peer) {
            isd->peer_sccp = peer_sccp;
            isd->have_peer_sccp = true;
        }
        if (map_send_tcap_to_peer(rt, isd, out, (size_t)n) < 0) {
            LOGE("map", "[%s] ISD: SCCP send failed (after loc-up End)", imsi);
            map_sess_remove(isd);
            return;
        }
        rt->map->stat_map_tx++;
        LOGI("map",
             "[%s] TX loc-up End then BEGIN ISD tid=0x%08x apns=%u op=%s msisdn=%s",
             imsi,
             isd->tcap_dialogue_id,
             (unsigned)n_apns,
             map_op_str(loc_op),
             msisdn[0] ? msisdn : "(none)");
        return;
    }

    /*
     * ISD before loc-up result (TS 29.002): MAP-C UL uses the same dialogue
     * (TC-CONTINUE + AARE + ISD). UGL uses a child ISD dialogue, then UGL End.
     */
    if (parent->map_op == MAP_OP_UL) {
        const uint8_t isd_iid = 1;
        uint8_t cmp[1200]; size_t co = 0;
        if (tcap_enc_invoke(cmp, sizeof(cmp), &co,
                            isd_iid,
                            MAP_OP_CODE_INSERT_SUBSCRIBER_DATA,
                            arg, (size_t)an) < 0) {
            send_tcap_end_with_error(rt, parent, parent->peer_invoke_id,
                                     MAP_ERR_SYSTEM_FAILURE, 1);
            return;
        }
        uint8_t dlg[128];
        int dn = map_encode_aare(MAP_AC_NETWORK_LOC_UP_V3, dlg, sizeof(dlg));
        if (dn < 0) {
            send_tcap_end_with_error(rt, parent, parent->peer_invoke_id,
                                     MAP_ERR_SYSTEM_FAILURE, 1);
            return;
        }

        uint8_t out[2048];
        int n = tcap_encode_message(TCAP_MSG_CONTINUE,
                                    parent->tcap_dialogue_id, true,
                                    parent->peer_tcap_dialogue_id,
                                    parent->have_peer_tid,
                                    dlg, (size_t)dn,
                                    cmp, co,
                                    out, sizeof(out));
        if (n < 0) {
            send_tcap_end_with_error(rt, parent, parent->peer_invoke_id,
                                     MAP_ERR_SYSTEM_FAILURE, 1);
            return;
        }
        if (map_send_tcap_to_peer(rt, parent, out, (size_t)n) < 0) {
            LOGE("map", "[%s] ISD CONTINUE: SCCP send failed", parent->imsi_str);
            send_tcap_end_with_error(rt, parent, parent->peer_invoke_id,
                                     MAP_ERR_SYSTEM_FAILURE, 1);
            return;
        }
        rt->map->stat_map_tx++;
        parent->aare_sent = true;
        parent->isd_invoke_id = isd_iid;
        parent->state = MAP_SESS_WAIT_MAP_ACK;
        map_sess_touch(parent);
        LOGI("map",
             "[%s] TX CONTINUE ISD tid=0x%08x peer=0x%08x msisdn=%s "
             "(await ISD ack then UL End)",
             parent->imsi_str,
             parent->tcap_dialogue_id,
             parent->peer_tcap_dialogue_id,
             parent->msisdn_str[0] ? parent->msisdn_str : "(none)");
        return;
    }

    /* UGL: separate subscriberDataMngt dialogue; UGL End after ISD ack. */
    map_session_t *isd = map_sess_create(map_sess_new_tid());
    if (!isd) {
        LOGE("map", "[%s] ISD: alloc failed", parent->imsi_str);
        return;
    }
    isd->map_op = MAP_OP_ISD;
    isd->state  = MAP_SESS_WAIT_MAP_ACK;
    isd->t_dialogue_ms = parent->t_dialogue_ms;
    isd->parent_tcap_dialogue_id = parent->tcap_dialogue_id;
    isd->have_parent_tid = true;
    memcpy(isd->imsi_str, parent->imsi_str, sizeof(isd->imsi_str));

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

    if (parent->have_peer_sccp) {
        isd->peer_sccp = parent->peer_sccp;
        isd->have_peer_sccp = true;
    }
    if (map_send_tcap_to_peer(rt, isd, out, (size_t)n) < 0) {
        LOGE("map", "[%s] ISD: SCCP send failed", parent->imsi_str);
        map_sess_remove(isd);
        return;
    }
    rt->map->stat_map_tx++;
    parent->state = MAP_SESS_WAIT_MAP_ACK;
    map_sess_touch(parent);
    LOGI("map",
         "[%s] TX BEGIN ISD tid=0x%08x apns=%u (%s parent tid=0x%08x msisdn=%s) "
         "(await ISD ack then UGL End)",
         parent->imsi_str,
         isd->tcap_dialogue_id,
         (unsigned)n_apns,
         map_op_str(parent->map_op),
         parent->tcap_dialogue_id,
         parent->msisdn_str[0] ? parent->msisdn_str : "(none)");
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
    iwf_imsi_trace_packet(imsi, "map", "tx", out, (size_t)n);

    rt->map->stat_map_tx++;
    LOGI("map",
         "[%s] TX BEGIN CL tid=0x%08x type=%u (HSS CLR)",
         imsi,
         tid,
         (unsigned)cancellation_type);
    return 0;
}

/* Map Diameter Destination-Host to GSUP CN domain.
 * CS when dest matches origin_host_cs (or contains "vlr");
 * PS when dest matches origin_host; 0 = both / unknown. */
static uint8_t cn_domain_from_dest_host(const iwf_config_t *cfg,
                                        const char *dest)
{
    if (!cfg || !dest || !dest[0])
        return 0;
    if (cfg->diam_origin_host_cs[0] &&
        !strcasecmp(dest, cfg->diam_origin_host_cs))
        return GSUP_CN_DOMAIN_CS;
    if (cfg->diam_origin_host[0] &&
        !strcasecmp(dest, cfg->diam_origin_host))
        return GSUP_CN_DOMAIN_PS;
    if (strcasestr(dest, "vlr"))
        return GSUP_CN_DOMAIN_CS;
    return 0;
}

static const char *origin_host_for_dest(const iwf_config_t *cfg,
                                        const char *dest)
{
    if (dest && dest[0])
        return dest;
    return cfg->diam_origin_host;
}

void map_iwf_on_clr(struct iwf_runtime *rt,
                    const uint8_t *body, size_t body_len,
                    uint32_t hop_by_hop, uint32_t end_to_end,
                    int peer_idx)
{
    char sid[DIAMETER_SESSION_ID_MAX];
    char imsi[MAP_IMSI_STR_MAX];
    char dest_host[128];
    uint32_t cancel_type = 0;
    const iwf_config_t *cfg = &rt->cfg;
    bool forwarded = false;

    sid[0] = '\0';
    dest_host[0] = '\0';
    (void)diameter_get_session_id(body, body_len, sid, sizeof(sid));
    (void)diameter_get_os_avp(body, body_len, AVP_DESTINATION_HOST, 0,
                              dest_host, sizeof(dest_host));

    if (diameter_get_user_name(body, body_len, imsi, sizeof(imsi)) < 0) {
        LOGW("map", "CLR: missing User-Name");
        (void)diameter_send_cla_answer(rt, hop_by_hop, end_to_end, sid,
                                       DIAM_RC_UNABLE_TO_DELIVER,
                                       origin_host_for_dest(cfg, dest_host),
                                       peer_idx);
        return;
    }

    (void)diameter_get_uint32_avp(body, body_len, AVP_3GPP_CANCELLATION_TYPE,
                                  DIAMETER_VENDOR_3GPP, &cancel_type);

    uint8_t cn = cn_domain_from_dest_host(cfg, dest_host);
    const char *origin = origin_host_for_dest(cfg, dest_host);

    LOGI("map",
         "[%s] RX CLR cancel_type=%u sid=%s dest=%s cn=%s",
         imsi,
         (unsigned)cancel_type,
         sid[0] ? sid : "-",
         dest_host[0] ? dest_host : "-",
         cn == GSUP_CN_DOMAIN_CS ? "CS" :
         cn == GSUP_CN_DOMAIN_PS ? "PS" : "CS+PS");

#ifdef GSUP_PROXY_ENABLED
    if (gsup_map_proxy_hss_clr(rt, imsi, (uint8_t)cancel_type, cn))
        forwarded = true;
#endif
    /* Do not fall back to MAP CancelLocation: CdPA was SSN-only (no GT) and
     * never reached a real SGSN. Per 3GPP TS 29.272, unknown IMSI / no
     * serving peer for this CN domain still gets DIAMETER_SUCCESS in CLA. */
    if (!forwarded)
        LOGW("map",
         "[%s] CLR: no GSUP LOC-CANCEL for cn=%s (IMSI unknown / no peer) "
         "-> CLA Success",
         imsi,
         cn == GSUP_CN_DOMAIN_CS ? "CS" :
             cn == GSUP_CN_DOMAIN_PS ? "PS" : "CS+PS");

    (void)diameter_send_cla_answer(rt, hop_by_hop, end_to_end, sid,
                                   DIAM_RC_SUCCESS, origin, peer_idx);
}

void map_iwf_on_idr(struct iwf_runtime *rt,
                    const uint8_t *body, size_t body_len,
                    uint32_t hop_by_hop, uint32_t end_to_end,
                    int peer_idx)
{
    char sid[DIAMETER_SESSION_ID_MAX];
    char imsi[MAP_IMSI_STR_MAX];
    char dest_host[128];
    uint32_t idr_flags = 0;
    const iwf_config_t *cfg = &rt->cfg;

    sid[0] = '\0';
    dest_host[0] = '\0';
    (void)diameter_get_session_id(body, body_len, sid, sizeof(sid));

    if (diameter_get_user_name(body, body_len, imsi, sizeof(imsi)) < 0) {
        LOGW("map", "IDR: missing User-Name");
        (void)diameter_send_ida_answer(rt, hop_by_hop, end_to_end, sid,
                                       DIAM_RC_UNABLE_TO_DELIVER, NULL, peer_idx);
        return;
    }

    (void)diameter_get_uint32_avp(body, body_len, AVP_3GPP_IDR_FLAGS,
                                  DIAMETER_VENDOR_3GPP, &idr_flags);
    (void)diameter_get_os_avp(body, body_len, AVP_DESTINATION_HOST, 0,
                              dest_host, sizeof(dest_host));

    const char *origin = origin_host_for_dest(cfg, dest_host);
    uint8_t cn = cn_domain_from_dest_host(cfg, dest_host);
    /* Ambiguous dest → prefer CS when origin_host_cs is configured (IDR to
     * iwf-vlr is the common HSS path); else PS. */
    if (cn == 0)
        cn = cfg->diam_origin_host_cs[0] ? GSUP_CN_DOMAIN_CS
                                         : GSUP_CN_DOMAIN_PS;

    LOGI("map",
         "[%s] RX IDR idr_flags=0x%x sid=%s dest=%s cn=%s",
         imsi,
         (unsigned)idr_flags,
         sid[0] ? sid : "-",
         dest_host[0] ? dest_host : "-",
         cn == GSUP_CN_DOMAIN_CS ? "CS" : "PS");

    diameter_avp_t sub_avp;
    bool has_sub = (diameter_avp_find(body, body_len, AVP_3GPP_SUBSCRIPTION_DATA,
                                      DIAMETER_VENDOR_3GPP, &sub_avp) == 0);
    bool has_urrp = (idr_flags & IDR_FLAG_UE_REACHABILITY) != 0;

    if (!has_urrp && !has_sub) {
        LOGW("map",
         "[%s] IDR: unsupported flags=0x%x",
         imsi,
         (unsigned)idr_flags);
        (void)diameter_send_ida_answer(rt, hop_by_hop, end_to_end, sid,
                                       DIAM_RC_UNABLE_TO_DELIVER, origin, peer_idx);
        return;
    }

    bool pushed = false;
#ifdef GSUP_PROXY_ENABLED
    if (has_sub) {
        map_session_t tmp;
        memset(&tmp, 0, sizeof(tmp));
        strncpy(tmp.imsi_str, imsi, sizeof(tmp.imsi_str) - 1);
        tmp.gsup_originated = true;
        tmp.gsup_cn_domain = cn;
        extract_ula_subdata(&tmp, body, body_len);
        pushed = gsup_map_proxy_hss_idr(rt, imsi, cn, tmp.msisdn_str,
                                        tmp.ula_apns, tmp.n_ula_apns);
        if (pushed)
            LOGI("map",
         "[%s] IDR: GSUP ISD pushed cn=%s msisdn=%s apns=%u",
         imsi,
         cn == GSUP_CN_DOMAIN_CS ? "CS" : "PS",
         tmp.msisdn_str[0] ? tmp.msisdn_str : "-",
         (unsigned)tmp.n_ula_apns);
        else if (!gsup_map_proxy_imsi_known(imsi, cn))
            LOGW("map",
         "[%s] IDR: IMSI not known on %s GSUP",
         imsi,
         cn == GSUP_CN_DOMAIN_CS ? "CS" : "PS");
    }
#else
    (void)has_sub;
#endif

    uint32_t rc = DIAM_RC_SUCCESS;
    if (has_sub && !pushed) {
#ifdef GSUP_PROXY_ENABLED
        if (!gsup_map_proxy_imsi_known(imsi, cn))
            rc = DIAM_EXP_RC_USER_UNKNOWN;
        else
            rc = DIAM_RC_UNABLE_TO_DELIVER;
#else
        rc = DIAM_RC_SUCCESS; /* no GSUP build: ack only */
#endif
    }

    (void)diameter_send_ida_answer(rt, hop_by_hop, end_to_end, sid,
                                   rc, origin, peer_idx);

    if (has_urrp) {
#ifdef GSUP_PROXY_ENABLED
        gsup_map_proxy_on_urrp(rt, imsi, origin);
#else
        (void)diameter_send_nor(rt, imsi, origin, UE_REACHABILITY_REACHABLE);
#endif
    }
}

void map_iwf_on_cla(struct iwf_runtime *rt, map_session_t *s,
                    const uint8_t *body, size_t body_len)
{
    (void)body; (void)body_len;
    /* The CL flow originates HSS-side (we get the CLR from PyHSS and then
     * Invoke MAP CancelLocation toward the SGSN).  CLA acknowledges that
     * our Diameter request was accepted; the SGSN-facing dialogue should
     * already be settled.  Nothing further to do here. */
    LOGI("map", "[%s] CLA rc=%u", s->imsi_str, s->diameter_result_code);
    map_sess_remove(s);
}

void map_iwf_on_pua(struct iwf_runtime *rt, map_session_t *s,
                    const uint8_t *body, size_t body_len)
{
    (void)body; (void)body_len;
    uint8_t params[16];
    int pn = map_encode_purge_res(false, params, sizeof(params));
    if (pn < 0) {
        send_tcap_end_with_error(rt, s, s->peer_invoke_id, MAP_ERR_SYSTEM_FAILURE, 1);
        return;
    }
    send_tcap_end_with_result(rt, s, s->peer_invoke_id, MAP_OP_CODE_PURGE_MS, params, (size_t)pn);
}

void map_iwf_diameter_error(struct iwf_runtime *rt, map_session_t *s,
                            uint32_t rc)
{
    if (s->gsup_originated) {
#ifdef GSUP_PROXY_ENABLED
        /* 3G GSUP: never fall back to 1408 — E-UTRAN vectors lack CK/IK. */
        gsup_map_proxy_diameter_error(rt, s, rc);
#endif
        return;
    }
    LOGW("map",
         "[%s] Diameter error rc=%u op=%s; sending MAP SystemFailure",
         s->imsi_str,
         (unsigned)rc,
         map_op_str(s->map_op));
    if (s->cmd_test) {
        char buf[48];
        snprintf(buf, sizeof(buf), "diameter_%u", (unsigned)rc);
        cmd_test_abort(s, buf);
        return;
    }
    int map_err = MAP_ERR_SYSTEM_FAILURE;
    if (rc == DIAM_EXP_RC_USER_UNKNOWN)        map_err = MAP_ERR_UNKNOWN_SUBSCRIBER;
    else if (rc == DIAM_EXP_RC_ROAMING_NOT_ALLOWED) map_err = MAP_ERR_ROAMING_NOT_ALLOWED;
    send_tcap_end_with_error(rt, s, s->peer_invoke_id ? s->peer_invoke_id : 1,
                             map_err, /*nrc=hlr*/ 1);
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
void map_iwf_on_diameter_readable(struct iwf_runtime *rt)
{
    diameter_on_readable(rt, 0);
}

void map_iwf_on_diameter_peer_readable(struct iwf_runtime *rt, int peer_idx)
{
    diameter_on_readable(rt, peer_idx);
}
void map_iwf_on_dwa_timer_tick   (struct iwf_runtime *rt) { diameter_on_dwa_tick(rt); }

void map_iwf_on_ttimer_tick(struct iwf_runtime *rt)
{
    if (!rt || !rt->map) return;
    uint64_t exp;
    ssize_t r = read(rt->map->t_timer_fd, &exp, sizeof(exp));
    (void)r;
    int killed = map_sess_sweep(time(NULL), map_sess_timeout_hook_cmd, rt);
    if (killed) rt->map->stat_timeouts += (uint64_t)killed;
    msrn_pool_sweep(time(NULL));
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
    rt->map->ss7.fd     = -1;

    map_sess_init();
    msrn_pool_init(&rt->cfg);

    if (ss7_link_init(rt) < 0) {
        LOGE("map", "SS7 link bring-up failed");
        msrn_pool_shutdown();
        free(rt->map); rt->map = NULL;
        return -1;
    }
    ss7_link_set_recv_cb(rt, on_sccp_pdu);

    if (diameter_init(rt) < 0) {
        LOGE("map", "Diameter bring-up failed");
        ss7_link_shutdown(rt);
        msrn_pool_shutdown();
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
        msrn_pool_shutdown();
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

    LOGI("map", "MAP-IWF ready (SS7=M3UA; diameter peers=%d origin=%s realm=%s)",
         rt->cfg.diam_n_peers,
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
    msrn_pool_shutdown();
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

    LOGI("map",
         "[%s] cmd-test TX AIR tid=0x%08x",
         s->imsi_str,
         s->tcap_dialogue_id);

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
    LOGI("map", "[001010000000003] SIGUSR1: cmd-test SAI");
    (void)map_iwf_cmd_test_sai(rt, "001010000000003", -1);
}
