#include "gsup_map_proxy.h"
#include "gsup_server.h"
#include "gsup_router.h"
#include "gsup_proto.h"
#include "map_session.h"
#include "map_codec.h"
#include "tcap.h"
#include "diameter.h"
#include "ss7_link.h"
#include "runtime.h"
#include "logging.h"
#include "imsi_trace.h"
#include "uthash.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef enum {
    GPEND_WAIT_MAP      = 0,  /* awaiting MAP ReturnResult / ISD Invoke */
    GPEND_WAIT_GSUP_ISD = 1,  /* sent GSUP ISD_REQ; wait MSC ISD_RES     */
} gsup_pend_state_t;

typedef struct gsup_pending {
    uint32_t    tcap_tid;           /* our OTID / peer DTID */
    uint32_t    peer_otid;          /* HLR OTID (for CONTINUE) */
    int         have_peer_otid;
    int         conn_id;
    char        imsi[16];
    map_op_t    map_op;
    uint8_t     invoke_id;          /* our outbound Invoke id */
    uint8_t     isd_invoke_id;      /* HLR ISD Invoke id to ack */
    uint8_t     cn_domain;
    gsup_pend_state_t state;
    char        msisdn[24];
    char        hlr_digits[24];
    char        src_gt[24];
    ss7_sccp_addr_t peer_addr;      /* HLR calling address for CONTINUE */
    int         have_peer_addr;
    uint8_t     deferred_ul_res[256];
    size_t      deferred_ul_res_len;
    time_t      created;
    int         timeout_ms;
    UT_hash_handle hh;
} gsup_pending_t;

static iwf_runtime_t *g_rt;
static gsup_pending_t *g_pending;

/* Last GSUP TCP conn per IMSI, split by CN domain (SGSN=PS, MSC=CS). */
typedef struct {
    char imsi[16];
    int  ps_conn_id;
    int  cs_conn_id;
    UT_hash_handle hh;
} gsup_imsi_conn_t;
static gsup_imsi_conn_t *g_imsi_conn;

static void gsup_track_conn(const char *imsi, int conn_id, uint8_t cn_domain)
{
    if (!imsi || !imsi[0] || conn_id < 0) return;
    gsup_imsi_conn_t *e = NULL;
    HASH_FIND_STR(g_imsi_conn, imsi, e);
    if (!e) {
        e = calloc(1, sizeof(*e));
        if (!e) return;
        strncpy(e->imsi, imsi, sizeof(e->imsi) - 1);
        e->ps_conn_id = -1;
        e->cs_conn_id = -1;
        HASH_ADD_STR(g_imsi_conn, imsi, e);
    }
    if (cn_domain == GSUP_CN_DOMAIN_CS)
        e->cs_conn_id = conn_id;
    else
        e->ps_conn_id = conn_id;
}

static int gsup_conn_for_imsi(const char *imsi, uint8_t cn_domain)
{
    gsup_imsi_conn_t *e = NULL;
    if (imsi && imsi[0])
        HASH_FIND_STR(g_imsi_conn, imsi, e);
    if (!e) return -1;
    int cid = (cn_domain == GSUP_CN_DOMAIN_CS) ? e->cs_conn_id : e->ps_conn_id;
    if (cid < 0 || !gsup_server_conn_valid(cid))
        return -1;
    return cid;
}

static void gsup_forget_imsi_cn(const char *imsi, uint8_t cn_domain);

static void gsup_forget_imsi_conn(const char *imsi)
{
    gsup_forget_imsi_cn(imsi, 0);
}

static void gsup_purge_conn_id(int conn_id)
{
    gsup_imsi_conn_t *e, *tmp;
    HASH_ITER(hh, g_imsi_conn, e, tmp) {
        if (e->ps_conn_id == conn_id)
            e->ps_conn_id = -1;
        if (e->cs_conn_id == conn_id)
            e->cs_conn_id = -1;
        if (e->ps_conn_id < 0 && e->cs_conn_id < 0) {
            HASH_DEL(g_imsi_conn, e);
            free(e);
        }
    }
}

static int gsup_resolve_conn(map_session_t *s)
{
    if (!s) return -1;
    int tracked = gsup_conn_for_imsi(s->imsi_str, s->gsup_cn_domain);
    if (tracked >= 0 && tracked != s->gsup_conn_id) {
        LOGW("gsup",
         "[%s] conn refresh cn=%s %d->%d peer=%s",
         s->imsi_str,
         s->gsup_cn_domain == GSUP_CN_DOMAIN_CS ? "CS" : "PS",
         s->gsup_conn_id,
         tracked,
         gsup_server_conn_peer(tracked));
        s->gsup_conn_id = tracked;
    }
    if (!gsup_server_conn_valid(s->gsup_conn_id)) {
        LOGW("gsup",
         "[%s] conn stale conn=%d cn=%s",
         s->imsi_str,
         s->gsup_conn_id,
         s->gsup_cn_domain == GSUP_CN_DOMAIN_CS ? "CS" : "PS");
        return -1;
    }
    return s->gsup_conn_id;
}

static int proxy_send_gsup(int conn_id, const uint8_t *gsup, size_t len)
{
    if (!gsup_server_conn_valid(conn_id)) {
        LOGW("gsup", "send on dead conn=%d", conn_id);
        return -1;
    }
    gsup_parsed_t req;
    if (gsup_parse_payload(gsup, len, &req) == 0 && req.have_imsi)
        iwf_imsi_trace_packet(req.imsi, "gsup", "tx", gsup, len);
    int rc = gsup_server_send(conn_id, gsup, len);
    if (rc < 0)
        LOGW("gsup", "send failed conn=%d peer=%s len=%zu",
             conn_id, gsup_server_conn_peer(conn_id), len);
    return rc;
}

static void pending_remove(gsup_pending_t *p)
{
    if (!p) return;
    HASH_DEL(g_pending, p);
    free(p);
}

static gsup_pending_t *pending_add(uint32_t tid, int conn_id, map_op_t op,
                                   const char *imsi, const char *src_gt,
                                   uint8_t cn_domain)
{
    gsup_pending_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    p->tcap_tid   = tid;
    p->conn_id    = conn_id;
    p->map_op     = op;
    p->invoke_id  = 1;
    p->cn_domain  = cn_domain;
    p->state      = GPEND_WAIT_MAP;
    p->created    = time(NULL);
    p->timeout_ms = g_rt && g_rt->cfg.gsup_timeout_ms > 0
                    ? g_rt->cfg.gsup_timeout_ms : 10000;
    strncpy(p->imsi, imsi, sizeof(p->imsi) - 1);
    if (src_gt && src_gt[0])
        strncpy(p->src_gt, src_gt, sizeof(p->src_gt) - 1);
    HASH_ADD(hh, g_pending, tcap_tid, sizeof(p->tcap_tid), p);
    return p;
}

static gsup_pending_t *pending_find(uint32_t tid)
{
    gsup_pending_t *p = NULL;
    HASH_FIND(hh, g_pending, &tid, sizeof(tid), p);
    return p;
}

static gsup_pending_t *pending_find_isd_wait(const char *imsi)
{
    gsup_pending_t *p, *tmp;
    if (!imsi || !imsi[0]) return NULL;
    HASH_ITER(hh, g_pending, p, tmp) {
        if (p->state == GPEND_WAIT_GSUP_ISD && !strcmp(p->imsi, imsi))
            return p;
    }
    return NULL;
}

static int map_pending_ack_isd(gsup_pending_t *p);

static int gsup_backend_for_cn(uint8_t cn)
{
    if (!g_rt) return GSUP_BACKEND_DIAMETER;
    if (cn == GSUP_CN_DOMAIN_CS)
        return g_rt->cfg.gsup_cs_backend;
    return g_rt->cfg.gsup_ps_backend;
}

static const char *vlr_gt_digits(void)
{
    if (g_rt && g_rt->cfg.map_local_gt[0])
        return g_rt->cfg.map_local_gt;
    return NULL;
}

static void reply_gsup_err(int conn_id, const char *imsi,
                           uint8_t req_type, uint8_t cause)
{
    uint8_t gsup[256];
    int n;
    if (req_type == GSUP_MSG_SAI_REQ)
        n = gsup_build_sai_err(imsi, cause, gsup, sizeof(gsup));
    else if (req_type == GSUP_MSG_UL_REQ)
        n = gsup_build_ul_err(imsi, cause, gsup, sizeof(gsup));
    else
        return;
    if (n > 0) {
        LOGI("gsup",
         "[%s] TX GSUP err type=0x%02x cause=0x%02x conn=%d len=%d",
         imsi,
         gsup[0],
         cause,
         conn_id,
         n);
        (void)proxy_send_gsup(conn_id, gsup, (size_t)n);
    }
}

static int sgsn_number_bcd(iwf_runtime_t *rt, uint8_t *out, size_t cap)
{
    const char *gt = rt->cfg.map_local_gt;
    if (!gt[0]) return -1;
    return map_str_to_bcd(gt, out, cap);
}

static int sgsn_addr_ipv4(iwf_runtime_t *rt, uint8_t *out, size_t cap)
{
    const char *ip = rt->cfg.local_ip[0] ? rt->cfg.local_ip : rt->cfg.listen_ip;
    struct in_addr ia;
    if (inet_pton(AF_INET, ip, &ia) != 1 || cap < 5)
        return -1;
    out[0] = 4;
    memcpy(out + 1, &ia, 4);
    return 5;
}

static int send_map_to_hlr(gsup_route_t *route, map_op_t op,
                           const uint8_t *arg, size_t arg_len,
                           int conn_id, uint8_t cn_domain)
{
    if (!ss7_link_is_active(g_rt)) {
        LOGW("gsup",
         "[%s] MAP %s: M3UA ASP not active (wait for STP)",
         route->imsi,
         map_op_str(op));
        return -1;
    }
    if (!route->hlr_gt[0]) {
        LOGW("gsup",
         "[%s] MAP %s: no hlr_gt (set [roaming_hlr] mncNNN_hlr_gt)",
         route->imsi,
         map_op_str(op));
        return -1;
    }

    uint32_t tid = map_sess_new_tid();
    map_app_ctx_t ac;
    int opcode;
    if (op == MAP_OP_SAI) {
        ac = MAP_AC_INFO_RETRIEVAL_V3;
        opcode = MAP_OP_CODE_SEND_AUTH_INFO;
    } else if (op == MAP_OP_UL) {
        ac = MAP_AC_NETWORK_LOC_UP_V3;
        opcode = MAP_OP_CODE_UPDATE_LOCATION;
    } else {
        ac = MAP_AC_GPRS_LOCATION_UPDATE_V3;
        opcode = MAP_OP_CODE_UPDATE_GPRS_LOCATION;
    }

    uint8_t cmp[1200];
    size_t co = 0;
    if (tcap_enc_invoke(cmp, sizeof(cmp), &co, 1, opcode, arg, arg_len) < 0)
        return -1;

    uint8_t dlg[128];
    int dn = map_encode_aarq(ac, dlg, sizeof(dlg));
    if (dn < 0) return -1;

    uint8_t out[2048];
    int n = tcap_encode_message(TCAP_MSG_BEGIN, tid, true,
                                0, false, dlg, (size_t)dn, cmp, co,
                                out, sizeof(out));
    if (n < 0) return -1;

    ss7_sccp_addr_t called, calling;
    ss7_gt_from_digits(route->hlr_gt, route->hlr_ssn, &called);
    memset(&calling, 0, sizeof(calling));
    /* MAP-C networkLocUp is VLR↔HLR; CS auth also from VLR. PS uses SGSN SSN. */
    uint8_t orig_ssn = (cn_domain == GSUP_CN_DOMAIN_CS)
                       ? SS7_SSN_VLR : g_rt->cfg.map_local_ssn;
    if (route->src_gt[0])
        ss7_gt_from_digits(route->src_gt, orig_ssn, &calling);
    else
        ss7_link_make_local_addr(g_rt, &calling);
    if (cn_domain == GSUP_CN_DOMAIN_CS)
        calling.ssn = orig_ssn;

    if (ss7_link_send_tcap_ex(g_rt, &called,
                              calling.have_gt ? &calling : NULL,
                              out, (size_t)n) < 0)
        return -1;

    iwf_imsi_trace_packet(route->imsi, "map", "tx", out, (size_t)n);

    if (!pending_add(tid, conn_id, op, route->imsi, route->src_gt, cn_domain))
        return -1;

    LOGI("gsup",
         "[%s] TX MAP %s cn=%s tid=0x%08x hlr_gt=%s src_gt=%s ssn=%u",
         route->imsi,
         map_op_str(op),
         cn_domain == GSUP_CN_DOMAIN_CS ? "CS" : "PS",
         tid,
         route->hlr_gt,
         route->src_gt[0] ? route->src_gt : g_rt->cfg.map_local_gt,
         (unsigned)orig_ssn);
    return 0;
}

/* Diameter S6d toward DRA/HSS (home or roaming partner realm). */
static void session_set_diam_dest(map_session_t *s, gsup_route_t *route,
                                  const iwf_config_t *cfg)
{
    if (!s || !route || !cfg) return;
    s->diam_dest_realm[0] = '\0';
    s->diam_dest_host[0]  = '\0';
    if (route->kind == GSUP_ROUTE_DIAM_HSS) {
        if (route->dest_realm[0])
            strncpy(s->diam_dest_realm, route->dest_realm,
                    sizeof(s->diam_dest_realm) - 1);
        if (route->dest_host[0])
            strncpy(s->diam_dest_host, route->dest_host,
                    sizeof(s->diam_dest_host) - 1);
    } else if (route->kind == GSUP_ROUTE_LOCAL) {
        if (cfg->diam_dest_realm[0])
            strncpy(s->diam_dest_realm, cfg->diam_dest_realm,
                    sizeof(s->diam_dest_realm) - 1);
        if (cfg->diam_dest_host[0])
            strncpy(s->diam_dest_host, cfg->diam_dest_host,
                    sizeof(s->diam_dest_host) - 1);
    }
}

static int start_diameter(gsup_route_t *route, gsup_parsed_t *req,
                          int conn_id, map_op_t op, uint8_t gsup_req_type)
{
    if (!g_rt || !route)
        return -1;
    if (!diameter_is_open(g_rt)) {
        LOGW("gsup",
         "[%s] Diameter: no peer open (check [diameter_s6d])",
         route->imsi);
        return -1;
    }

    map_session_t *s = map_sess_create(map_sess_new_tid());
    if (!s)
        return -1;

    s->map_op          = op;
    s->state           = MAP_SESS_WAIT_DIAMETER;
    s->gsup_originated = true;
    s->gsup_conn_id    = conn_id;
    s->gsup_req_type   = gsup_req_type;
    s->gsup_cn_domain  = (req && req->have_cn_domain)
                         ? req->cn_domain : GSUP_CN_DOMAIN_PS;
    s->diam_peer_idx   = -1;
    session_set_diam_dest(s, route, &g_rt->cfg);
    if (req && req->have_num_vectors)
        s->gsup_num_vectors = req->num_vectors;
    if (req && gsup_parsed_have_resync(req)) {
        memcpy(s->resync_rand, req->resync_rand, sizeof(s->resync_rand));
        memcpy(s->resync_auts, req->resync_auts, sizeof(s->resync_auts));
        s->have_resync = true;
    }

    int bn = map_str_to_bcd(route->imsi, s->imsi_bcd, sizeof(s->imsi_bcd));
    if (bn < 0) {
        map_sess_remove(s);
        return -1;
    }
    s->imsi_bcd_len = (uint8_t)bn;
    strncpy(s->imsi_str, route->imsi, sizeof(s->imsi_str) - 1);
    s->imsi_str[sizeof(s->imsi_str) - 1] = '\0';

    if (map_plmn_pack_home(g_rt->cfg.gsup_local_mnc, s->visited_plmn_bcd) == 0)
        s->have_visited_plmn = true;

    if (g_rt->cfg.gsup_timeout_ms > 0)
        s->t_dialogue_ms = g_rt->cfg.gsup_timeout_ms;
    else if (g_rt->cfg.diam_request_timeout_ms > 0)
        s->t_dialogue_ms = g_rt->cfg.diam_request_timeout_ms;
    else
        s->t_dialogue_ms = 10000;
    map_sess_touch(s);

    int rc;
    if (op == MAP_OP_SAI) {
        LOGI("gsup",
         "[%s] Diameter AIR conn=%d realm=%s%s",
         route->imsi,
         conn_id,
         s->diam_dest_realm[0] ? s->diam_dest_realm : g_rt->cfg.diam_dest_realm,
         s->have_resync ? " resync=1" : "");
        rc = diameter_send_air(g_rt, s);
    } else {
        LOGI("gsup",
         "[%s] Diameter ULR conn=%d realm=%s",
         route->imsi,
         conn_id,
         s->diam_dest_realm[0] ? s->diam_dest_realm : g_rt->cfg.diam_dest_realm);
        rc = diameter_send_ulr(g_rt, s);
    }
    if (rc < 0) {
        map_sess_remove(s);
        return -1;
    }
    return 0;
}

static void gsup_forget_imsi_cn(const char *imsi, uint8_t cn_domain)
{
    gsup_imsi_conn_t *e = NULL;
    if (!imsi || !imsi[0]) return;
    HASH_FIND_STR(g_imsi_conn, imsi, e);
    if (!e) return;
    if (cn_domain == 0 || cn_domain == GSUP_CN_DOMAIN_PS)
        e->ps_conn_id = -1;
    if (cn_domain == 0 || cn_domain == GSUP_CN_DOMAIN_CS)
        e->cs_conn_id = -1;
    if (e->ps_conn_id < 0 && e->cs_conn_id < 0) {
        HASH_DEL(g_imsi_conn, e);
        free(e);
    }
}

bool gsup_map_proxy_imsi_known(const char *imsi, uint8_t cn_domain)
{
    if (!imsi || !imsi[0]) return false;
    if (cn_domain == 0)
        return gsup_conn_for_imsi(imsi, GSUP_CN_DOMAIN_CS) >= 0 ||
               gsup_conn_for_imsi(imsi, GSUP_CN_DOMAIN_PS) >= 0;
    return gsup_conn_for_imsi(imsi, cn_domain) >= 0;
}

bool gsup_map_proxy_hss_clr(iwf_runtime_t *rt, const char *imsi,
                            uint8_t cancel_type, uint8_t cn_domain)
{
    if (!rt || !imsi || !imsi[0]) return false;

    uint8_t gsup[128];
    int n = gsup_build_loc_cancel_req(imsi, cancel_type, gsup, sizeof(gsup));
    if (n <= 0) return false;

    bool sent = false;
    uint8_t domains[2];
    size_t nd = 0;
    if (cn_domain == 0 || cn_domain == GSUP_CN_DOMAIN_PS)
        domains[nd++] = GSUP_CN_DOMAIN_PS;
    if (cn_domain == 0 || cn_domain == GSUP_CN_DOMAIN_CS)
        domains[nd++] = GSUP_CN_DOMAIN_CS;

    for (size_t i = 0; i < nd; i++) {
        int conn_id = gsup_conn_for_imsi(imsi, domains[i]);
        if (conn_id < 0) continue;
        if (proxy_send_gsup(conn_id, gsup, (size_t)n) < 0) continue;
        LOGI("gsup",
         "[%s] TX LOC-CANCEL conn=%d cn=%s type=%u (HSS CLR)",
         imsi,
         conn_id,
         domains[i] == GSUP_CN_DOMAIN_CS ? "CS" : "PS",
         (unsigned)cancel_type);
        sent = true;
        gsup_forget_imsi_cn(imsi, domains[i]);
    }
    return sent;
}

bool gsup_map_proxy_hss_idr(iwf_runtime_t *rt, const char *imsi,
                            uint8_t cn_domain, const char *msisdn,
                            const map_ula_apn_entry_t *apns, size_t n_apns)
{
    if (!rt || !imsi || !imsi[0]) return false;
    if (cn_domain != GSUP_CN_DOMAIN_CS && cn_domain != GSUP_CN_DOMAIN_PS)
        return false;

    int conn_id = gsup_conn_for_imsi(imsi, cn_domain);
    if (conn_id < 0) {
        LOGW("gsup",
         "[%s] IDR ISD: no %s GSUP conn",
         imsi,
         cn_domain == GSUP_CN_DOMAIN_CS ? "CS" : "PS");
        return false;
    }

    /* CS: MSISDN (+ optional HLR GT). PS: APN list when present. */
    const map_ula_apn_entry_t *use_apns = NULL;
    size_t use_n = 0;
    if (cn_domain == GSUP_CN_DOMAIN_PS && apns && n_apns > 0) {
        use_apns = apns;
        use_n = n_apns;
    }
    if (cn_domain == GSUP_CN_DOMAIN_CS && (!msisdn || !msisdn[0]) && use_n == 0) {
        LOGW("gsup", "[%s] IDR ISD CS: no MSISDN in Subscription-Data", imsi);
        /* Still send IMSI-only ISD so MSC refreshes presence if possible. */
    }

    const char *hlr = rt->cfg.map_local_gt[0] ? rt->cfg.map_local_gt : NULL;
    uint8_t gsup[2048];
    int n = gsup_build_isd_req(imsi, msisdn, use_apns, use_n,
                               cn_domain, hlr, gsup, sizeof(gsup));
    if (n <= 0) return false;
    if (proxy_send_gsup(conn_id, gsup, (size_t)n) < 0)
        return false;

    LOGI("gsup",
         "[%s] TX ISD_REQ (HSS IDR) msisdn=%s cn=%s pdp=%zu conn=%d",
         imsi,
         msisdn && msisdn[0] ? msisdn : "-",
         cn_domain == GSUP_CN_DOMAIN_CS ? "CS" : "PS",
         use_n,
         conn_id);
    return true;
}

void gsup_map_proxy_on_urrp(iwf_runtime_t *rt, const char *imsi,
                            const char *diam_origin_host)
{
    if (!rt || !imsi || !imsi[0]) return;

    int cs = gsup_conn_for_imsi(imsi, GSUP_CN_DOMAIN_CS);
    int ps = gsup_conn_for_imsi(imsi, GSUP_CN_DOMAIN_PS);
    uint32_t reach = (cs >= 0 || ps >= 0)
                     ? UE_REACHABILITY_REACHABLE
                     : UE_REACHABILITY_UNREACHABLE;

    LOGI("gsup",
         "[%s] URRP cs_conn=%d ps_conn=%d -> NOR reach=%u",
         imsi,
         cs,
         ps,
         (unsigned)reach);

    if (diameter_send_nor(rt, imsi, diam_origin_host, reach) < 0)
        LOGW("gsup", "[%s] NOR send failed", imsi);
}

int gsup_map_proxy_send_isd(iwf_runtime_t *rt, map_session_t *s)
{
    if (!rt || !s || !s->gsup_originated) return -1;
    if (gsup_resolve_conn(s) < 0) return -1;
    if (s->gsup_cn_domain == GSUP_CN_DOMAIN_CS && !s->msisdn_str[0])
        return -1;

    const char *hlr = rt->cfg.map_local_gt[0] ? rt->cfg.map_local_gt : NULL;
    uint8_t gsup[2048];
    int n = gsup_build_isd_req(s->imsi_str, s->msisdn_str,
                               s->ula_apns, s->n_ula_apns,
                               s->gsup_cn_domain, hlr,
                               gsup, sizeof(gsup));
    if (n <= 0) return -1;
    if (proxy_send_gsup(s->gsup_conn_id, gsup, (size_t)n) < 0)
        return -1;

    s->state = MAP_SESS_WAIT_MAP_ACK;
    s->gsup_isd_sent = true;
    map_sess_touch(s);
    {
        char hexbuf[512] = {0};
        int hlen = n < 150 ? n : 150;
        for (int i = 0; i < hlen; i++)
            snprintf(hexbuf + (size_t)i * 3, sizeof(hexbuf) - (size_t)i * 3,
                     "%02x ", gsup[i]);
        LOGI("gsup",
         "[%s] TX ISD_REQ msisdn=%s cn=%s pdp=%u conn=%d peer=%s len=%d hex=%s",
         s->imsi_str,
         s->msisdn_str[0] ? s->msisdn_str : "(none)",
         s->gsup_cn_domain == GSUP_CN_DOMAIN_CS ? "CS" : "PS",
         (unsigned)(s->gsup_cn_domain == GSUP_CN_DOMAIN_CS
                        ? 0 : s->n_ula_apns),
         s->gsup_conn_id,
         gsup_server_conn_peer(s->gsup_conn_id),
         n,
         hexbuf);
    }
    return 0;
}

static int handle_sai(gsup_route_t *route, gsup_parsed_t *req, int conn_id,
                      const uint8_t *raw_gsup, size_t raw_len)
{
    (void)raw_gsup;
    (void)raw_len;
    if (route->kind == GSUP_ROUTE_REJECT) {
        reply_gsup_err(conn_id, route->imsi, GSUP_MSG_SAI_REQ,
                       GSUP_CAUSE_IMSI_UNKNOWN);
        return 0;
    }
    uint8_t cn = (req && req->have_cn_domain) ? req->cn_domain : GSUP_CN_DOMAIN_PS;
    int want_map = (gsup_backend_for_cn(cn) == GSUP_BACKEND_MAP && route->hlr_gt[0]);
    if (!want_map) {
        if (gsup_backend_for_cn(cn) == GSUP_BACKEND_MAP && !route->hlr_gt[0])
            LOGI("gsup",
         "[%s] SAI cn=%s: no hlr_gt, falling back to Diameter",
         route->imsi,
         cn == GSUP_CN_DOMAIN_CS ? "CS" : "PS");
        if (route->kind == GSUP_ROUTE_MAP_HLR &&
            !route->dest_realm[0] && !g_rt->cfg.diam_dest_realm[0]) {
            LOGW("gsup",
         "[%s] SAI cn=%s wants Diameter but no dest_realm",
         route->imsi,
         cn == GSUP_CN_DOMAIN_CS ? "CS" : "PS");
            return -1;
        }
        return start_diameter(route, req, conn_id, MAP_OP_SAI, GSUP_MSG_SAI_REQ);
    }

    uint8_t arg[128];
    uint8_t nv = req->have_num_vectors ? req->num_vectors : 3;
    int an = map_encode_sai_arg(route->imsi, nv, arg, sizeof(arg));
    if (an < 0) return -1;
    return send_map_to_hlr(route, MAP_OP_SAI, arg, (size_t)an, conn_id, cn);
}

static int handle_ul(gsup_route_t *route, gsup_parsed_t *req, int conn_id,
                     const uint8_t *raw_gsup, size_t raw_len)
{
    (void)raw_gsup;
    (void)raw_len;
    if (route->kind == GSUP_ROUTE_REJECT) {
        reply_gsup_err(conn_id, route->imsi, GSUP_MSG_UL_REQ,
                       GSUP_CAUSE_IMSI_UNKNOWN);
        return 0;
    }
    uint8_t cn = (req && req->have_cn_domain) ? req->cn_domain : GSUP_CN_DOMAIN_PS;
    int want_map = (gsup_backend_for_cn(cn) == GSUP_BACKEND_MAP && route->hlr_gt[0]);

    if (!want_map) {
        if (gsup_backend_for_cn(cn) == GSUP_BACKEND_MAP && !route->hlr_gt[0])
            LOGI("gsup",
         "[%s] UL cn=%s: no hlr_gt, falling back to Diameter",
         route->imsi,
         cn == GSUP_CN_DOMAIN_CS ? "CS" : "PS");
        if (route->kind == GSUP_ROUTE_MAP_HLR &&
            !route->dest_realm[0] && !g_rt->cfg.diam_dest_realm[0]) {
            LOGW("gsup",
         "[%s] UL cn=%s wants Diameter but no dest_realm",
         route->imsi,
         cn == GSUP_CN_DOMAIN_CS ? "CS" : "PS");
            return -1;
        }
        return start_diameter(route, req, conn_id, MAP_OP_UGL, GSUP_MSG_UL_REQ);
    }

    /* MAP backend (CS → MAP-C updateLocation; PS → Gr UGL) */
    if (cn == GSUP_CN_DOMAIN_CS) {
        const char *gt = vlr_gt_digits();
        if (!gt) {
            LOGW("gsup", "[%s] CS MAP-C UL: set [map_iwf].local_gt", route->imsi);
            return -1;
        }
        uint8_t arg[256];
        int an = map_encode_ul_arg(route->imsi, gt, gt, arg, sizeof(arg));
        if (an < 0) return -1;
        return send_map_to_hlr(route, MAP_OP_UL, arg, (size_t)an, conn_id, cn);
    }

    uint8_t sn_bcd[8];
    int snl = sgsn_number_bcd(g_rt, sn_bcd, sizeof(sn_bcd));
    uint8_t saddr[8];
    int sal = sgsn_addr_ipv4(g_rt, saddr, sizeof(saddr));
    uint8_t arg[256];
    int an = map_encode_ugl_arg(route->imsi,
                                snl > 0 ? sn_bcd : NULL, snl > 0 ? (size_t)snl : 0,
                                sal > 0 ? saddr : NULL, sal > 0 ? (size_t)sal : 0,
                                arg, sizeof(arg));
    if (an < 0) return -1;
    return send_map_to_hlr(route, MAP_OP_UGL, arg, (size_t)an, conn_id, cn);
}

void gsup_map_proxy_on_gsup(iwf_runtime_t *rt, int conn_id,
                            const uint8_t *gsup, size_t len)
{
    if (!rt || !gsup || len < 1) return;
    gsup_parsed_t req;
    if (gsup_parse_payload(gsup, len, &req) < 0 || !req.have_imsi) {
        LOGW("gsup", "conn=%d malformed GSUP (no IMSI)", conn_id);
        return;
    }
    iwf_imsi_trace_packet(req.imsi, "gsup", "rx", gsup, len);

    gsup_route_t route;
    if (gsup_router_lookup(&rt->cfg, req.imsi, &route) < 0) {
        reply_gsup_err(conn_id, req.imsi, req.msg_type, GSUP_CAUSE_IMSI_UNKNOWN);
        return;
    }

    const char *lip = gsup_server_conn_bind_ip(conn_id);
    const char *peer = gsup_server_conn_peer(conn_id);
    if (req.msg_type == GSUP_MSG_SAI_REQ &&
        (req.have_resync_rand ^ req.have_resync_auts)) {
        LOGW("gsup",
         "[%s] SAI resync incomplete rand=%d auts=%d",
         req.imsi,
         req.have_resync_rand,
         req.have_resync_auts);
    }
    LOGI("gsup",
         "[%s] RX msg=0x%02x cn=%s route=%d conn=%d peer=%s listen=%s src_ip=%s%s",
         req.imsi,
         req.msg_type,
         req.have_cn_domain
             ? (req.cn_domain == GSUP_CN_DOMAIN_CS ? "CS" : "PS")
             : "PS(default)",
         (int)route.kind,
         conn_id,
         peer ? peer : "?",
         lip ? lip : "?",
         route.src_ip[0] ? route.src_ip : "(default)",
         (req.msg_type == GSUP_MSG_SAI_REQ && gsup_parsed_have_resync(&req))
             ? " resync=1" : "");

    /* ISD result completes a Diameter UL or MAP-C UL (CSFB) transaction. */
    if (req.msg_type == GSUP_MSG_ISD_RES || req.msg_type == GSUP_MSG_ISD_ERR) {
        gsup_pending_t *mp = pending_find_isd_wait(req.imsi);
        if (mp) {
            if (req.msg_type == GSUP_MSG_ISD_ERR) {
                reply_gsup_err(mp->conn_id, mp->imsi, GSUP_MSG_UL_REQ,
                               GSUP_CAUSE_IMSI_UNKNOWN);
                pending_remove(mp);
                return;
            }
            if (conn_id != mp->conn_id) {
                LOGW("gsup",
         "[%s] MAP ISD_RES conn mismatch expect=%d got=%d",
         req.imsi,
         mp->conn_id,
         conn_id);
                return;
            }
            LOGI("gsup", "[%s] RX ISD_RES (MAP-C) conn=%d", req.imsi, conn_id);
            if (map_pending_ack_isd(mp) < 0) {
                reply_gsup_err(mp->conn_id, mp->imsi, GSUP_MSG_UL_REQ,
                               GSUP_CAUSE_IMSI_UNKNOWN);
                pending_remove(mp);
            }
            return;
        }
        map_session_t *s = map_sess_find_gsup_pending(req.imsi, MAP_OP_UGL);
        if (!s) {
            LOGD("gsup", "[%s] ISD response for unknown session", req.imsi);
            return;
        }
        if (req.msg_type == GSUP_MSG_ISD_ERR) {
            reply_gsup_err(s->gsup_conn_id, s->imsi_str, GSUP_MSG_UL_REQ,
                           GSUP_CAUSE_IMSI_UNKNOWN);
            s->gsup_originated = false;
            map_sess_remove(s);
            return;
        }
        if (conn_id != s->gsup_conn_id) {
            LOGW("gsup",
         "[%s] ISD_RES conn mismatch expect=%d got=%d peer=%s",
         req.imsi,
         s->gsup_conn_id,
         conn_id,
         gsup_server_conn_peer(conn_id));
            return;
        }
        LOGI("gsup",
         "[%s] RX ISD_RES conn=%d peer=%s",
         req.imsi,
         conn_id,
         gsup_server_conn_peer(conn_id));
        gsup_map_proxy_finish_ugl(rt, s);
        return;
    }

    if (req.msg_type != GSUP_MSG_SAI_REQ && req.msg_type != GSUP_MSG_UL_REQ) {
        LOGD("gsup",
         "[%s] unsupported GSUP msg type 0x%02x",
         req.imsi,
         req.msg_type);
        return;
    }

    int rc = -1;
    switch (req.msg_type) {
    case GSUP_MSG_SAI_REQ: {
        uint8_t cn = (req.have_cn_domain ? req.cn_domain : GSUP_CN_DOMAIN_PS);
        gsup_track_conn(req.imsi, conn_id, cn);
        rc = handle_sai(&route, &req, conn_id, gsup, len);
        break;
    }
    case GSUP_MSG_UL_REQ: {
        uint8_t cn = (req.have_cn_domain ? req.cn_domain : GSUP_CN_DOMAIN_PS);
        gsup_track_conn(req.imsi, conn_id, cn);
        rc = handle_ul(&route, &req, conn_id, gsup, len);
        break;
    }
    default:
        return;
    }
    if (rc < 0)
        reply_gsup_err(conn_id, req.imsi, req.msg_type, GSUP_CAUSE_IMSI_UNKNOWN);
}

void gsup_map_proxy_finish_sai(iwf_runtime_t *rt, map_session_t *s)
{
    if (!rt || !s || !s->gsup_originated) return;
    if (gsup_resolve_conn(s) < 0) {
        reply_gsup_err(s->gsup_conn_id, s->imsi_str, GSUP_MSG_SAI_REQ,
                       GSUP_CAUSE_IMSI_UNKNOWN);
        s->gsup_originated = false;
        map_sess_remove(s);
        return;
    }
    uint8_t gsup[2048];
    int n = gsup_build_sai_res(s->imsi_str, s->av, s->n_av, gsup, sizeof(gsup));
    if (n < 0 || s->n_av == 0) {
        reply_gsup_err(s->gsup_conn_id, s->imsi_str, GSUP_MSG_SAI_REQ,
                       GSUP_CAUSE_IMSI_UNKNOWN);
    } else {
        char hexbuf[512] = {0};
        int hlen = n < 150 ? n : 150;
        for (int _i = 0; _i < hlen; _i++)
            snprintf(hexbuf + _i*3, sizeof(hexbuf) - _i*3, "%02x ", gsup[_i]);
        LOGI("gsup",
         "[%s] TX SAI_RES vectors=%u conn=%d peer=%s len=%d xres_len=%u hex=%s",
         s->imsi_str,
         (unsigned)s->n_av,
         s->gsup_conn_id,
         gsup_server_conn_peer(s->gsup_conn_id),
         n,
         (unsigned)s->av[0].xres_len,
         hexbuf);
        (void)proxy_send_gsup(s->gsup_conn_id, gsup, (size_t)n);
    }
    s->gsup_originated = false;
    map_sess_remove(s);
}

void gsup_map_proxy_abort_ugl(iwf_runtime_t *rt, map_session_t *s)
{
    if (!rt || !s || !s->gsup_originated) return;
    reply_gsup_err(s->gsup_conn_id, s->imsi_str, GSUP_MSG_UL_REQ,
                   GSUP_CAUSE_IMSI_UNKNOWN);
    s->gsup_originated = false;
    map_sess_remove(s);
}

void gsup_map_proxy_finish_ugl(iwf_runtime_t *rt, map_session_t *s)
{
    if (!rt || !s || !s->gsup_originated) return;
    if (gsup_resolve_conn(s) < 0) {
        gsup_map_proxy_abort_ugl(rt, s);
        return;
    }

    const char *hlr = rt->cfg.map_local_gt[0] ? rt->cfg.map_local_gt : NULL;
    const map_ula_apn_entry_t *apns = NULL;
    size_t n_apns = 0;
    uint8_t cn = s->gsup_cn_domain;

    /* CS: MSISDN is delivered in ISD_REQ (step 3); UL_RES is IMSI + HLR/CN only.
     * PS: repeat MSISDN in UL_RES when ISD was skipped; PDP/APN stay ISD-first. */
    const char *msisdn = NULL;
    if (cn == GSUP_CN_DOMAIN_CS && s->gsup_isd_sent) {
        msisdn = NULL;
    } else if (s->msisdn_str[0]) {
        msisdn = s->msisdn_str;
    }

    if (!s->gsup_isd_sent && cn != GSUP_CN_DOMAIN_CS && s->n_ula_apns > 0) {
        apns = s->ula_apns;
        n_apns = s->n_ula_apns;
    }

    uint8_t gsup[2048];
    int n = gsup_build_ul_res(s->imsi_str, msisdn, apns, n_apns, cn, hlr,
                              gsup, sizeof(gsup));
    if (n <= 0) {
        LOGW("gsup", "[%s] UL_RES build failed", s->imsi_str);
        reply_gsup_err(s->gsup_conn_id, s->imsi_str, GSUP_MSG_UL_REQ,
                       GSUP_CAUSE_IMSI_UNKNOWN);
    } else {
        char hexbuf[512] = {0};
        int hlen = n < 150 ? n : 150;
        for (int i = 0; i < hlen; i++)
            snprintf(hexbuf + (size_t)i * 3, sizeof(hexbuf) - (size_t)i * 3,
                     "%02x ", gsup[i]);
        if (proxy_send_gsup(s->gsup_conn_id, gsup, (size_t)n) < 0) {
            LOGW("gsup",
         "[%s] UL_RES send failed conn=%d",
         s->imsi_str,
         s->gsup_conn_id);
        } else {
            LOGI("gsup",
         "[%s] TX UL_RES isd=%d msisdn=%s cn=%s pdp=%u conn=%d peer=%s len=%d hex=%s",
         s->imsi_str,
         s->gsup_isd_sent ? 1 : 0,
         msisdn ? msisdn : "(none)",
         cn ? (s->gsup_cn_domain == GSUP_CN_DOMAIN_CS ? "CS" : "PS")
                    : "(none)",
         (unsigned)n_apns,
         s->gsup_conn_id,
         gsup_server_conn_peer(s->gsup_conn_id),
         n,
         hexbuf);
        }
    }
    s->gsup_originated = false;
    map_sess_remove(s);
}

void gsup_map_proxy_on_timeout(iwf_runtime_t *rt, map_session_t *s)
{
    if (!rt || !s || !s->gsup_originated) return;
    reply_gsup_err(s->gsup_conn_id, s->imsi_str, s->gsup_req_type,
                   GSUP_CAUSE_IMSI_UNKNOWN);
    s->gsup_originated = false;
}

void gsup_map_proxy_diameter_error(iwf_runtime_t *rt, map_session_t *s,
                                   uint32_t diameter_result_code)
{
    if (!rt || !s || !s->gsup_originated) return;
    LOGW("gsup",
         "[%s] Diameter error rc=%u -> SAI/UL err",
         s->imsi_str,
         (unsigned)diameter_result_code);
    reply_gsup_err(s->gsup_conn_id, s->imsi_str, s->gsup_req_type,
                   GSUP_CAUSE_IMSI_UNKNOWN);
    s->gsup_originated = false;
    map_sess_remove(s);
}

static void map_to_gsup_sai(gsup_pending_t *p, const uint8_t *params, size_t plen)
{
    map_auth_vector_t av[MAP_AUTH_VECTOR_MAX];
    size_t n = 0;
    if (map_decode_sai_res(params, plen, av, MAP_AUTH_VECTOR_MAX, &n) < 0 || n == 0) {
        reply_gsup_err(p->conn_id, p->imsi, GSUP_MSG_SAI_REQ, GSUP_CAUSE_IMSI_UNKNOWN);
        return;
    }
    uint8_t gsup[2048];
    int gn = gsup_build_sai_res(p->imsi, av, n, gsup, sizeof(gsup));
    if (gn > 0) {
        (void)proxy_send_gsup(p->conn_id, gsup, (size_t)gn);
        LOGI("gsup",
         "[%s] TX SAI_RES (MAP) vectors=%zu conn=%d",
         p->imsi,
         n,
         p->conn_id);
    }
}

static void map_to_gsup_ul_res(gsup_pending_t *p, const uint8_t *params, size_t plen)
{
    char hlr_digits[24] = {0};
    (void)map_decode_ul_res(params, plen, NULL, 0, NULL,
                            hlr_digits, sizeof(hlr_digits));
    if (hlr_digits[0])
        strncpy(p->hlr_digits, hlr_digits, sizeof(p->hlr_digits) - 1);

    const char *hlr = p->hlr_digits[0] ? p->hlr_digits
                     : (g_rt && g_rt->cfg.map_local_gt[0] ? g_rt->cfg.map_local_gt
                                                          : NULL);
    /* CS: MSISDN already via ISD; UL_RES is IMSI + CN (+ optional HLR). */
    const char *msisdn = NULL;
    if (p->cn_domain != GSUP_CN_DOMAIN_CS && p->msisdn[0])
        msisdn = p->msisdn;

    uint8_t gsup[256];
    int gn = gsup_build_ul_res(p->imsi, msisdn, NULL, 0,
                               p->cn_domain, hlr, gsup, sizeof(gsup));
    if (gn > 0) {
        (void)proxy_send_gsup(p->conn_id, gsup, (size_t)gn);
        LOGI("gsup",
         "[%s] TX UL_RES (MAP) cn=%s msisdn=%s hlr=%s conn=%d",
         p->imsi,
         p->cn_domain == GSUP_CN_DOMAIN_CS ? "CS" : "PS",
         msisdn ? msisdn : "(none)",
         hlr ? hlr : "(none)",
         p->conn_id);
    }
}

static int map_pending_send_isd_gsup(gsup_pending_t *p)
{
    if (!p || !p->msisdn[0]) return -1;
    const char *hlr = g_rt && g_rt->cfg.map_local_gt[0] ? g_rt->cfg.map_local_gt
                                                        : NULL;
    uint8_t gsup[512];
    int n = gsup_build_isd_req(p->imsi, p->msisdn, NULL, 0,
                               p->cn_domain, hlr, gsup, sizeof(gsup));
    if (n <= 0) return -1;
    if (proxy_send_gsup(p->conn_id, gsup, (size_t)n) < 0) return -1;
    p->state = GPEND_WAIT_GSUP_ISD;
    LOGI("gsup",
         "[%s] TX ISD_REQ (MAP-C) msisdn=%s cn=CS conn=%d",
         p->imsi,
         p->msisdn,
         p->conn_id);
    return 0;
}

/* After MSC ISD_RES: ReturnResult ISD toward HLR, keep dialogue open for UL Res. */
static int map_pending_ack_isd(gsup_pending_t *p)
{
    if (!p || !p->have_peer_otid || !p->have_peer_addr) return -1;

    uint8_t cmp[64];
    size_t co = 0;
    if (tcap_enc_return_result(cmp, sizeof(cmp), &co, p->isd_invoke_id,
                               MAP_OP_CODE_INSERT_SUBSCRIBER_DATA,
                               NULL, 0) < 0)
        return -1;

    uint8_t out[512];
    int n = tcap_encode_message(TCAP_MSG_CONTINUE,
                                p->tcap_tid, true,
                                p->peer_otid, true,
                                NULL, 0, cmp, co,
                                out, sizeof(out));
    if (n < 0) return -1;

    ss7_sccp_addr_t calling;
    memset(&calling, 0, sizeof(calling));
    uint8_t ssn = SS7_SSN_VLR;
    if (p->src_gt[0])
        ss7_gt_from_digits(p->src_gt, ssn, &calling);
    else if (g_rt)
        ss7_link_make_local_addr(g_rt, &calling);
    calling.ssn = ssn;

    if (ss7_link_send_tcap_ex(g_rt, &p->peer_addr,
                              calling.have_gt ? &calling : NULL,
                              out, (size_t)n) < 0)
        return -1;

    p->state = GPEND_WAIT_MAP;
    LOGI("gsup",
         "[%s] TX MAP ISD ReturnResult tid=0x%08x peer=0x%08x",
         p->imsi,
         p->tcap_tid,
         p->peer_otid);
    if (p->deferred_ul_res_len) {
        map_to_gsup_ul_res(p, p->deferred_ul_res, p->deferred_ul_res_len);
        p->deferred_ul_res_len = 0;
        pending_remove(p);
        return 0;
    }
    return 0;
}

static int map_pending_on_isd_invoke(gsup_pending_t *p,
                                     const ss7_sccp_addr_t *calling,
                                     const tcap_msg_t *tmsg,
                                     const tcap_component_t *c)
{
    char msisdn[24] = {0};
    if (map_decode_isd_arg(c->parameters, c->parameters_len,
                           NULL, 0, msisdn, sizeof(msisdn)) < 0 || !msisdn[0]) {
        LOGW("gsup", "[%s] MAP ISD Invoke without MSISDN", p->imsi);
        return -1;
    }
    strncpy(p->msisdn, msisdn, sizeof(p->msisdn) - 1);
    p->isd_invoke_id = c->invoke_id;
    if (tmsg->have_otid) {
        p->peer_otid = tmsg->otid;
        p->have_peer_otid = 1;
    }
    if (calling) {
        p->peer_addr = *calling;
        p->have_peer_addr = 1;
    }
    return map_pending_send_isd_gsup(p);
}

bool gsup_map_proxy_on_tcap(iwf_runtime_t *rt,
                            const ss7_sccp_addr_t *calling,
                            const tcap_msg_t *tmsg)
{
    if (!rt || !tmsg || !tmsg->have_dtid)
        return false;

    gsup_pending_t *p = pending_find(tmsg->dtid);
    if (!p)
        return false;

    iwf_imsi_trace_bind_rx("map", tmsg->raw, tmsg->raw_len);
    iwf_imsi_trace_flush_rx(p->imsi);

    if (tmsg->have_otid) {
        p->peer_otid = tmsg->otid;
        p->have_peer_otid = 1;
    }
    if (calling) {
        p->peer_addr = *calling;
        p->have_peer_addr = 1;
    }

    if (tmsg->type == TCAP_MSG_ABORT) {
        reply_gsup_err(p->conn_id, p->imsi,
                       p->map_op == MAP_OP_SAI ? GSUP_MSG_SAI_REQ : GSUP_MSG_UL_REQ,
                       GSUP_CAUSE_IMSI_UNKNOWN);
        pending_remove(p);
        return true;
    }

    if (tmsg->type != TCAP_MSG_END && tmsg->type != TCAP_MSG_CONTINUE)
        return true;

    if (tmsg->n_components == 0) {
        if (tmsg->type == TCAP_MSG_END)
            pending_remove(p);
        return true;
    }

    /* Process all components: ISD Invoke(s) then UL/SAI Result. */
    int finished = 0;
    int saw_isd = 0;
    for (size_t i = 0; i < tmsg->n_components; i++) {
        const tcap_component_t *c = &tmsg->components[i];
        if (c->kind == TCAP_CMP_KIND_ERR) {
            reply_gsup_err(p->conn_id, p->imsi,
                           p->map_op == MAP_OP_SAI ? GSUP_MSG_SAI_REQ
                                                   : GSUP_MSG_UL_REQ,
                           GSUP_CAUSE_IMSI_UNKNOWN);
            pending_remove(p);
            return true;
        }
        if (c->kind == TCAP_CMP_KIND_INVOKE &&
            c->opcode == MAP_OP_CODE_INSERT_SUBSCRIBER_DATA) {
            if (map_pending_on_isd_invoke(p, calling, tmsg, c) < 0) {
                reply_gsup_err(p->conn_id, p->imsi, GSUP_MSG_UL_REQ,
                               GSUP_CAUSE_IMSI_UNKNOWN);
                pending_remove(p);
                return true;
            }
            saw_isd = 1;
            continue;
        }
        if (c->kind != TCAP_CMP_KIND_RES)
            continue;

        if (p->map_op == MAP_OP_SAI) {
            map_to_gsup_sai(p, c->parameters, c->parameters_len);
            finished = 1;
        } else if (p->map_op == MAP_OP_UL || p->map_op == MAP_OP_UGL) {
            /* Defer UL_RES until after MSC ISD_RES when ISD was in this PDU. */
            if (saw_isd || p->state == GPEND_WAIT_GSUP_ISD) {
                size_t copy = c->parameters_len;
                if (copy > sizeof(p->deferred_ul_res))
                    copy = sizeof(p->deferred_ul_res);
                if (c->parameters && copy) {
                    memcpy(p->deferred_ul_res, c->parameters, copy);
                    p->deferred_ul_res_len = copy;
                }
                LOGI("gsup",
         "[%s] defer MAP UL Res until after GSUP ISD len=%zu",
         p->imsi,
         copy);
                continue;
            }
            map_to_gsup_ul_res(p, c->parameters, c->parameters_len);
            finished = 1;
        }
    }

    if (finished && p->state != GPEND_WAIT_GSUP_ISD)
        pending_remove(p);
    else if (tmsg->type == TCAP_MSG_END && p->state != GPEND_WAIT_GSUP_ISD &&
             !finished && !saw_isd)
        pending_remove(p);
    return true;
}

void gsup_map_proxy_sweep(iwf_runtime_t *rt, time_t now)
{
    if (!rt) return;
    gsup_pending_t *p, *tmp;
    HASH_ITER(hh, g_pending, p, tmp) {
        if ((now - p->created) * 1000 >= p->timeout_ms) {
            LOGW("gsup",
         "[%s] pending timeout tid=0x%08x",
         p->imsi,
         p->tcap_tid);
            reply_gsup_err(p->conn_id, p->imsi,
                           p->map_op == MAP_OP_SAI ? GSUP_MSG_SAI_REQ
                                                   : GSUP_MSG_UL_REQ,
                           GSUP_CAUSE_IMSI_UNKNOWN);
            pending_remove(p);
        }
    }
}

static void abort_gsup_on_closed(map_session_t *s, void *ctx)
{
    int cid = *(int *)ctx;
    if (!s->gsup_originated || s->gsup_conn_id != cid)
        return;
    LOGW("gsup",
         "[%s] abort GSUP session op=%s: conn=%d closed",
         s->imsi_str,
         map_op_str(s->map_op),
         cid);
    s->gsup_originated = false;
    map_sess_remove(s);
}

void gsup_map_proxy_on_conn_closed(int conn_id)
{
    LOGI("gsup", "conn=%d closed", conn_id);
    gsup_purge_conn_id(conn_id);
    map_sess_iterate(abort_gsup_on_closed, &conn_id);
}

void gsup_map_proxy_init(iwf_runtime_t *rt)
{
    g_rt = rt;
    /* LOCAL auth/UL uses Diameter S6d unless cs_backend/ps_backend override. */
    if (rt && rt->cfg.gsup_cs_backend == GSUP_BACKEND_MAP) {
        /* HLR replies to VLR SSN on networkLocUp; bind so CONTINUE/END arrive. */
        if (ss7_link_bind_extra_ssn(rt, SS7_SSN_VLR, "iwf-vlr") < 0)
            LOGW("gsup", "CS MAP-C: failed to bind VLR SSN %u",
                 (unsigned)SS7_SSN_VLR);
        if (ss7_link_bind_extra_ssn(rt, SS7_SSN_MSC, "iwf-msc") < 0)
            LOGW("gsup", "CS MAP-C: failed to bind MSC SSN %u",
                 (unsigned)SS7_SSN_MSC);
        LOGI("gsup", "combine mode: cs_backend=map ps_backend=%s",
             rt->cfg.gsup_ps_backend == GSUP_BACKEND_MAP ? "map" : "diameter");
    }
}

void gsup_map_proxy_shutdown(void)
{
    gsup_pending_t *p, *tmp;
    HASH_ITER(hh, g_pending, p, tmp) {
        pending_remove(p);
    }
    gsup_imsi_conn_t *c, *ctmp;
    HASH_ITER(hh, g_imsi_conn, c, ctmp) {
        HASH_DEL(g_imsi_conn, c);
        free(c);
    }
    g_rt = NULL;
}
