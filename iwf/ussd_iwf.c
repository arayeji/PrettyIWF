/*
 * ussd_iwf.c - GSUP session-based SS/USSD <-> MAP USSD dialogue relay.
 */

#include "ussd_iwf.h"
#include "gsup_router.h"
#include "gsup_server.h"
#include "gsup_map_proxy.h"
#include "map_codec.h"
#include "runtime.h"
#include "config.h"
#include "logging.h"
#include "uthash.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#define USSD_DIR_MO      1   /* our MSC -> partner HLR  */
#define USSD_DIR_NI      2   /* partner -> our MSC      */

#define USSD_OTID_BIT    0x40000000u
#define USSD_SESS_TTL_S  30

typedef struct ussd_session {
    uint32_t        otid;           /* our TCAP transaction id (hash key) */
    UT_hash_handle  hh;
    uint8_t         dir;
    char            imsi[16];
    int             gsup_conn;
    uint32_t        gsup_session_id;
    uint32_t        peer_otid;      /* partner TCAP transaction id */
    bool            have_peer_otid;
    uint8_t         peer_invoke_id; /* NI: invoke to answer on local error */
    ss7_sccp_addr_t peer_addr;
    bool            aare_pending;   /* NI: AARE due on first backward msg  */
    uint8_t         aare_oid[16];
    uint8_t         aare_oid_len;
    time_t          created;
} ussd_session_t;

static ussd_session_t *g_sessions;
static uint32_t g_otid_ctr;
static uint32_t g_ni_session_ctr;

static ussd_session_t *ussd_find(uint32_t otid)
{
    ussd_session_t *s = NULL;
    HASH_FIND(hh, g_sessions, &otid, sizeof(otid), s);
    return s;
}

static ussd_session_t *ussd_find_gsup(uint32_t session_id, const char *imsi)
{
    ussd_session_t *s, *tmp;
    HASH_ITER(hh, g_sessions, s, tmp) {
        if (s->gsup_session_id != session_id) continue;
        if (imsi && imsi[0] && strcmp(s->imsi, imsi) != 0) continue;
        return s;
    }
    return NULL;
}

static void ussd_remove(ussd_session_t *s)
{
    if (!s) return;
    HASH_DEL(g_sessions, s);
    free(s);
}

static uint32_t ussd_new_otid(void)
{
    return USSD_OTID_BIT | (++g_otid_ctr & 0x0fffffffu);
}

/* Local CgPA for USSD (we act as MSC): local GT, SSN 8. */
static void ussd_local_calling(struct iwf_runtime *rt, const char *src_gt,
                               ss7_sccp_addr_t *calling)
{
    memset(calling, 0, sizeof(*calling));
    const char *gt = (src_gt && src_gt[0]) ? src_gt : rt->cfg.map_local_gt;
    if (gt && gt[0])
        ss7_gt_from_digits(gt, SS7_SSN_MSC, calling);
    calling->ssn = SS7_SSN_MSC;
}

static int ussd_tx_tcap(struct iwf_runtime *rt, ussd_session_t *s,
                        tcap_msg_type_t type,
                        const uint8_t *dlg, size_t dlen,
                        const uint8_t *cmp, size_t clen)
{
    uint8_t out[768];
    int n = tcap_encode_message(type,
                                s->otid, type != TCAP_MSG_END,
                                s->peer_otid,
                                type != TCAP_MSG_BEGIN && s->have_peer_otid,
                                dlg, dlen, cmp, clen, out, sizeof(out));
    if (n < 0) return -1;
    ss7_sccp_addr_t calling;
    ussd_local_calling(rt, NULL, &calling);
    return ss7_link_send_tcap_ex(rt, &s->peer_addr,
                                 calling.have_gt ? &calling : NULL,
                                 out, (size_t)n);
}

/* TCAP END with returnError toward the partner (NI failure paths). */
static void ussd_ni_reply_error(struct iwf_runtime *rt,
                                const ss7_sccp_addr_t *peer,
                                uint32_t peer_otid, uint8_t invoke_id,
                                const uint8_t *dialogue, size_t dialogue_len,
                                int map_err)
{
    uint8_t cmp[64];
    size_t co = 0;
    if (tcap_enc_return_error(cmp, sizeof(cmp), &co, invoke_id,
                              map_err, NULL, 0) < 0)
        return;
    uint8_t dlg[128];
    int dn = 0;
    uint8_t oid[16];
    size_t ol = 0;
    if (dialogue && dialogue_len &&
        map_decode_aarq_ac_raw(dialogue, dialogue_len, oid,
                               sizeof(oid), &ol) == 0)
        dn = map_encode_aare_oid(oid, ol, dlg, sizeof(dlg));
    if (dn < 0) dn = 0;
    uint8_t out[512];
    int n = tcap_encode_message(TCAP_MSG_END, 0, false, peer_otid, true,
                                dn > 0 ? dlg : NULL, (size_t)(dn > 0 ? dn : 0),
                                cmp, co, out, sizeof(out));
    if (n < 0) return;
    ss7_sccp_addr_t calling;
    ussd_local_calling(rt, NULL, &calling);
    ss7_link_send_tcap_ex(rt, peer, calling.have_gt ? &calling : NULL,
                          out, (size_t)n);
}

static void ussd_gsup_err(int conn_id, const char *imsi,
                          uint32_t session_id, uint8_t session_state)
{
    uint8_t gsup[64];
    int n = gsup_build_proc_ss(GSUP_MSG_PROC_SS_ERR, imsi, session_id,
                               session_state, NULL, 0, gsup, sizeof(gsup));
    if (n > 0)
        gsup_server_send(conn_id, gsup, (size_t)n);
}

static void ussd_expire(struct iwf_runtime *rt)
{
    time_t now = time(NULL);
    ussd_session_t *s, *tmp;
    HASH_ITER(hh, g_sessions, s, tmp) {
        if (now - s->created < USSD_SESS_TTL_S) continue;
        LOGW("ussd", "[%s] session timeout otid=0x%08x dir=%u",
             s->imsi, s->otid, s->dir);
        if (s->dir == USSD_DIR_MO) {
            ussd_gsup_err(s->gsup_conn, s->imsi, s->gsup_session_id,
                          GSUP_SESSION_STATE_END);
        } else if (s->have_peer_otid) {
            uint8_t cmp[64];
            size_t co = 0;
            if (tcap_enc_return_error(cmp, sizeof(cmp), &co,
                                      s->peer_invoke_id,
                                      MAP_ERR_SYSTEM_FAILURE, NULL, 0) >= 0)
                ussd_tx_tcap(rt, s, TCAP_MSG_END,
                             NULL, 0, cmp, co);
        }
        ussd_remove(s);
    }
}

/* ----- MO USSD: GSUP from the MSC -> MAP toward the home HLR ---------- */

static void ussd_mo_begin(struct iwf_runtime *rt, int conn_id,
                          const gsup_parsed_t *m)
{
    if (!m->ss_info_len) {
        LOGW("ussd", "[%s] PROC_SS BEGIN without SS_INFO", m->imsi);
        ussd_gsup_err(conn_id, m->imsi, m->session_id,
                      GSUP_SESSION_STATE_END);
        return;
    }

    gsup_route_t route;
    if (gsup_router_lookup(&rt->cfg, m->imsi, &route) < 0 ||
        (!route.hlr_gt[0] && !route.e214_prefix[0])) {
        LOGW("ussd", "[%s] MO USSD: no MAP HLR route (hlr_gt/e214_prefix)",
             m->imsi);
        ussd_gsup_err(conn_id, m->imsi, m->session_id,
                      GSUP_SESSION_STATE_END);
        return;
    }

    ussd_session_t *s = calloc(1, sizeof(*s));
    if (!s) {
        ussd_gsup_err(conn_id, m->imsi, m->session_id,
                      GSUP_SESSION_STATE_END);
        return;
    }
    s->otid = ussd_new_otid();
    s->dir = USSD_DIR_MO;
    s->gsup_conn = conn_id;
    s->gsup_session_id = m->session_id;
    s->created = time(NULL);
    strncpy(s->imsi, m->imsi, sizeof(s->imsi) - 1);

    /* CdPA: E.214 MGT (prefix + MSIN) or fixed HLR GT - same routing the
     * outbound UL uses. */
    if (route.e214_prefix[0]) {
        char mgt[40];
        size_t skip = 3 + (route.mnc_digits == 3 ? 3u : 2u);
        size_t il = strlen(route.imsi);
        snprintf(mgt, sizeof(mgt), "%s%s", route.e214_prefix,
                 il > skip ? route.imsi + skip : "");
        ss7_gt_from_digits(mgt, route.hlr_ssn ? route.hlr_ssn : SS7_SSN_HLR,
                           &s->peer_addr);
        s->peer_addr.gt_np_e214 = true;
    } else {
        ss7_gt_from_digits(route.hlr_gt,
                           route.hlr_ssn ? route.hlr_ssn : SS7_SSN_HLR,
                           &s->peer_addr);
    }

    uint8_t dlg[128];
    int dn = map_encode_aarq(MAP_AC_NETWORK_UNSTRUCTURED_SS_V2,
                             dlg, sizeof(dlg));
    if (dn < 0) {
        free(s);
        ussd_gsup_err(conn_id, m->imsi, m->session_id,
                      GSUP_SESSION_STATE_END);
        return;
    }

    uint8_t out[768];
    int n = tcap_encode_message(TCAP_MSG_BEGIN, s->otid, true, 0, false,
                                dlg, (size_t)dn,
                                m->ss_info, m->ss_info_len,
                                out, sizeof(out));
    ss7_sccp_addr_t calling;
    ussd_local_calling(rt, route.src_gt, &calling);
    if (n < 0 ||
        ss7_link_send_tcap_ex(rt, &s->peer_addr,
                              calling.have_gt ? &calling : NULL,
                              out, (size_t)n) < 0) {
        free(s);
        ussd_gsup_err(conn_id, m->imsi, m->session_id,
                      GSUP_SESSION_STATE_END);
        return;
    }
    HASH_ADD(hh, g_sessions, otid, sizeof(s->otid), s);
    LOGI("ussd",
         "[%s] MO USSD sid=0x%08x -> MAP BEGIN otid=0x%08x cdpa=%s%s",
         s->imsi, s->gsup_session_id, s->otid, s->peer_addr.gt_digits,
         s->peer_addr.gt_np_e214 ? " (E.214)" : "");
}

void ussd_iwf_on_gsup_ss(struct iwf_runtime *rt, int conn_id,
                         const gsup_parsed_t *m)
{
    if (!rt || !m) return;
    ussd_expire(rt);
    if (!m->have_imsi || !m->have_session_id || !m->have_session_state) {
        LOGW("ussd", "PROC_SS 0x%02x missing imsi/session ies", m->msg_type);
        return;
    }

    ussd_session_t *s = ussd_find_gsup(m->session_id, m->imsi);

    if (!s) {
        if (m->msg_type == GSUP_MSG_PROC_SS_REQ &&
            m->session_state == GSUP_SESSION_STATE_BEGIN) {
            ussd_mo_begin(rt, conn_id, m);
        } else {
            LOGW("ussd", "[%s] PROC_SS 0x%02x state=%u for unknown sid=0x%08x",
                 m->imsi, m->msg_type, m->session_state, m->session_id);
        }
        return;
    }

    if (s->dir == USSD_DIR_MO) {
        /* Follow-up from the MSC inside an MO dialogue (e.g. the user's
         * answer to a network prompt), or session teardown. */
        if (!s->have_peer_otid) {
            LOGW("ussd", "[%s] MO USSD sid=0x%08x: MSC msg before HLR reply",
                 s->imsi, s->gsup_session_id);
            ussd_gsup_err(s->gsup_conn, s->imsi, s->gsup_session_id,
                          GSUP_SESSION_STATE_END);
            ussd_remove(s);
            return;
        }
        if (m->msg_type == GSUP_MSG_PROC_SS_ERR ||
            m->session_state == GSUP_SESSION_STATE_END) {
            ussd_tx_tcap(rt, s, TCAP_MSG_END, NULL, 0,
                         m->ss_info_len ? m->ss_info : NULL, m->ss_info_len);
            LOGI("ussd", "[%s] MO USSD sid=0x%08x closed by MSC -> TCAP END",
                 s->imsi, s->gsup_session_id);
            ussd_remove(s);
            return;
        }
        if (m->ss_info_len)
            ussd_tx_tcap(rt, s, TCAP_MSG_CONTINUE, NULL, 0,
                         m->ss_info, m->ss_info_len);
        return;
    }

    /* NI session: MSC/phone answered our forwarded request. */
    uint8_t dlg[128];
    int dn = 0;
    if (s->aare_pending && s->aare_oid_len) {
        dn = map_encode_aare_oid(s->aare_oid, s->aare_oid_len,
                                 dlg, sizeof(dlg));
        if (dn < 0) dn = 0;
    }
    bool end = (m->msg_type == GSUP_MSG_PROC_SS_ERR ||
                m->session_state == GSUP_SESSION_STATE_END);
    const uint8_t *cmp = m->ss_info_len ? m->ss_info : NULL;
    size_t clen = m->ss_info_len;
    uint8_t errcmp[64];
    if (!cmp && m->msg_type == GSUP_MSG_PROC_SS_ERR) {
        size_t co = 0;
        if (tcap_enc_return_error(errcmp, sizeof(errcmp), &co,
                                  s->peer_invoke_id,
                                  MAP_ERR_SYSTEM_FAILURE, NULL, 0) >= 0) {
            cmp = errcmp;
            clen = co;
        }
    }
    ussd_tx_tcap(rt, s, end ? TCAP_MSG_END : TCAP_MSG_CONTINUE,
                 dn > 0 ? dlg : NULL, (size_t)(dn > 0 ? dn : 0), cmp, clen);
    s->aare_pending = false;
    LOGI("ussd", "[%s] NI USSD sid=0x%08x -> TCAP %s (ss_info=%zu)",
         s->imsi, s->gsup_session_id, end ? "END" : "CONTINUE", clen);
    if (end)
        ussd_remove(s);
}

void ussd_iwf_reject_begin(struct iwf_runtime *rt,
                           const ss7_sccp_addr_t *calling,
                           const tcap_msg_t *tmsg,
                           const tcap_component_t *c, int map_err)
{
    if (!rt || !calling || !tmsg->have_otid) return;
    ussd_ni_reply_error(rt, calling, tmsg->otid, c->invoke_id,
                        tmsg->dialogue, tmsg->dialogue_len, map_err);
}

/* ----- NI USSD: MAP BEGIN from a partner -> GSUP toward the MSC ------- */

void ussd_iwf_on_ni_begin(struct iwf_runtime *rt,
                          const ss7_sccp_addr_t *calling,
                          const tcap_msg_t *tmsg,
                          const tcap_component_t *c, bool aare_done)
{
    if (!rt || !calling || !tmsg->have_otid || !c->raw || !c->raw_len)
        return;
    ussd_expire(rt);

    /* Error replies must not repeat the AARE once it has been sent. */
    const uint8_t *err_dlg = aare_done ? NULL : tmsg->dialogue;
    size_t err_dlen = aare_done ? 0 : tmsg->dialogue_len;

    char imsi[16];
    if (map_decode_dialogue_dest_ref(tmsg->dialogue, tmsg->dialogue_len,
                                     imsi, sizeof(imsi)) < 0) {
        LOGW("ussd", "NI USSD op=%d: no destinationReference IMSI -> error",
             c->opcode);
        ussd_ni_reply_error(rt, calling, tmsg->otid, c->invoke_id,
                            err_dlg, err_dlen, MAP_ERR_SYSTEM_FAILURE);
        return;
    }

    int conn = gsup_map_proxy_cs_conn_for_imsi(imsi);
    if (conn < 0) {
        LOGI("ussd", "[%s] NI USSD op=%d: no MSC GSUP conn -> absent",
             imsi, c->opcode);
        ussd_ni_reply_error(rt, calling, tmsg->otid, c->invoke_id,
                            err_dlg, err_dlen, MAP_ERR_ABSENT_SUBSCRIBER);
        return;
    }

    ussd_session_t *s = calloc(1, sizeof(*s));
    if (!s) return;
    s->otid = ussd_new_otid();
    s->dir = USSD_DIR_NI;
    s->gsup_conn = conn;
    s->gsup_session_id = 0x80000000u | (++g_ni_session_ctr & 0x7fffffffu);
    s->peer_otid = tmsg->otid;
    s->have_peer_otid = true;
    s->peer_invoke_id = c->invoke_id;
    s->peer_addr = *calling;
    s->aare_pending = !aare_done;
    s->created = time(NULL);
    strncpy(s->imsi, imsi, sizeof(s->imsi) - 1);
    if (!aare_done && tmsg->dialogue && tmsg->dialogue_len) {
        size_t ol = 0;
        if (map_decode_aarq_ac_raw(tmsg->dialogue, tmsg->dialogue_len,
                                   s->aare_oid, sizeof(s->aare_oid),
                                   &ol) == 0)
            s->aare_oid_len = (uint8_t)ol;
    }

    uint8_t gsup[600];
    int n = gsup_build_proc_ss(GSUP_MSG_PROC_SS_REQ, imsi,
                               s->gsup_session_id, GSUP_SESSION_STATE_BEGIN,
                               c->raw, c->raw_len, gsup, sizeof(gsup));
    if (n < 0 || gsup_server_send(conn, gsup, (size_t)n) < 0) {
        LOGW("ussd", "[%s] NI USSD: GSUP send failed conn=%d", imsi, conn);
        ussd_ni_reply_error(rt, calling, tmsg->otid, c->invoke_id,
                            tmsg->dialogue, tmsg->dialogue_len,
                            MAP_ERR_SYSTEM_FAILURE);
        free(s);
        return;
    }
    HASH_ADD(hh, g_sessions, otid, sizeof(s->otid), s);
    LOGI("ussd",
         "[%s] NI USSD op=%d peer_otid=0x%08x -> GSUP conn=%d sid=0x%08x",
         imsi, c->opcode, s->peer_otid, conn, s->gsup_session_id);
}

/* ----- TCAP responses from the partner --------------------------------- */

bool ussd_iwf_on_tcap(struct iwf_runtime *rt,
                      const ss7_sccp_addr_t *calling,
                      const tcap_msg_t *tmsg)
{
    if (!rt || !tmsg->have_dtid) return false;
    ussd_session_t *s = ussd_find(tmsg->dtid);
    if (!s) return false;

    if (calling)
        s->peer_addr = *calling;
    if (tmsg->have_otid) {
        s->peer_otid = tmsg->otid;
        s->have_peer_otid = true;
    }
    s->created = time(NULL);   /* refresh TTL on activity */

    bool end = (tmsg->type == TCAP_MSG_END || tmsg->type == TCAP_MSG_ABORT);
    const uint8_t *cmp = NULL;
    size_t clen = 0;
    if (tmsg->n_components > 0 && tmsg->components[0].raw) {
        cmp = tmsg->components[0].raw;
        clen = tmsg->components[0].raw_len;
    }

    uint8_t msgt;
    if (s->dir == USSD_DIR_MO)
        msgt = (tmsg->type == TCAP_MSG_ABORT || (end && !cmp))
               ? GSUP_MSG_PROC_SS_ERR : GSUP_MSG_PROC_SS_RES;
    else
        msgt = GSUP_MSG_PROC_SS_REQ;   /* HLR-originated leg of NI session */

    uint8_t gsup[600];
    int n = gsup_build_proc_ss(msgt, s->imsi, s->gsup_session_id,
                               end ? GSUP_SESSION_STATE_END
                                   : GSUP_SESSION_STATE_CONTINUE,
                               cmp, clen, gsup, sizeof(gsup));
    if (n > 0)
        gsup_server_send(s->gsup_conn, gsup, (size_t)n);
    LOGI("ussd",
         "[%s] TCAP %s dtid=0x%08x -> GSUP 0x%02x state=%s (ss_info=%zu)",
         s->imsi,
         tmsg->type == TCAP_MSG_END ? "END" :
         tmsg->type == TCAP_MSG_ABORT ? "ABORT" : "CONTINUE",
         tmsg->dtid, msgt, end ? "END" : "CONTINUE", clen);
    if (end)
        ussd_remove(s);
    return true;
}
