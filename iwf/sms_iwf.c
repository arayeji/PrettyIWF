/*
 * sms_iwf.c - MAP SMS interworking (inbound MT SRI-SM + outbound MO via SMPP).
 */

#include "sms_iwf.h"
#include "map_iwf.h"
#include "gsup_client.h"
#include "gsup_server.h"
#include "gsup_map_proxy.h"
#include "gsup_router.h"
#include "smpp_server.h"
#include "runtime.h"
#include "config.h"
#include "logging.h"
#include "ss7_link.h"
#include "map_codec.h"
#include "tcap.h"
#include "uthash.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>

#define SMS_DIR_INBOUND         1
#define SMS_DIR_OUTBOUND        2
#define SMS_DIR_MT_IN           3   /* partner SMSC -> our roamer via MSC */
#define SMS_DIR_MO_OUT          4   /* our subscriber -> home SMSC        */
#define SMS_DIR_ALERT_OUT       5   /* readyForSM toward the home HLR     */

#define SMS_STATE_WAIT_GSUP     1
#define SMS_STATE_WAIT_SRI_SM   2
#define SMS_STATE_WAIT_FWDSM    3
#define SMS_STATE_WAIT_GSUP_MT  4
#define SMS_STATE_WAIT_MO_FSM   5
#define SMS_STATE_WAIT_RFSM     6
#define SMS_STATE_WAIT_LU       7   /* MT parked: CS LU still in flight     */
#define SMS_STATE_WAIT_LU_GRACE 8   /* LU landed (or retry due): short hold */

/* Longest we hold an MT-SMS for an in-flight CS Location Update before
 * pushing it at the MSC anyway.  Well inside sms_fwdsm_timeout_ms and the
 * SMSC's own MAP dialogue timer. */
#define SMS_MT_LU_WAIT_MS     5000
/* Grace after the LU lands, so osmo-msc finishes the VLR record and gets
 * LU-ACCEPT out before the SM shows up. */
#define SMS_MT_LU_GRACE_MS     150
/* A GMM 17 that comes back this fast is "no VLR record yet"; a real paging
 * or delivery failure only surfaces after the MSC's own timers (seconds). */
#define SMS_MT_FAST_FAIL_MS   2000
#define SMS_MT_RETRY_MS        700

#define SMS_OTID_OUTBOUND_BIT   0x80000000u

typedef struct sms_session {
    uint32_t            otid;
    UT_hash_handle      hh;
    uint8_t             direction;
    uint8_t             state;
    uint32_t            smpp_seq;
    char                msisdn[20];
    char                src_addr[20];
    char                imsi[16];
    char                partner_vmsc_gt[24];
    int                 partner_idx;
    uint8_t             user_data[256];
    uint8_t             user_data_len;
    uint8_t             tpdu[256];
    uint16_t            tpdu_len;
    uint8_t             data_coding;
    uint8_t             esm_class;
    ss7_sccp_addr_t     ret_addr;
    uint8_t             peer_invoke_id;
    uint32_t            peer_otid;
    bool                have_peer_otid;
    int                 timer_fd;
    /* MT-in (partner SMSC -> roamer) */
    int                 mt_op;          /* invoke opcode to echo (44 or 46) */
    uint8_t             sm_rp_mr;       /* GSUP correlation                  */
    uint8_t             aare_oid[16];   /* AC OID from AARQ, echoed in AARE  */
    uint8_t             aare_oid_len;
    uint8_t             mt_sc_addr[12]; /* SM-RP-OA, kept for re-send        */
    uint8_t             mt_sc_len;
    uint8_t             mt_ui[255];     /* SM-RP-UI (the TPDU)               */
    uint8_t             mt_ui_len;
    uint8_t             mt_more;
    uint8_t             mt_retried;     /* one retry per SM                  */
    uint64_t            mt_req_ms;      /* when the GSUP MT req went out     */
    /* MO-out (subscriber -> home SMSC) */
    int                 gsup_conn;      /* MSC conn awaiting the MO result   */
} sms_session_t;

static struct iwf_runtime *g_rt;
static sms_session_t *g_sessions;
static uint32_t g_out_otid = SMS_OTID_OUTBOUND_BIT;
static uint8_t g_mt_mr;
static int g_epfd = -1;

static sms_session_t *sms_sess_find(uint32_t otid)
{
    sms_session_t *s = NULL;
    HASH_FIND(hh, g_sessions, &otid, sizeof(otid), s);
    return s;
}

static void sms_sess_remove(sms_session_t *s)
{
    if (!s) return;
    if (s->timer_fd >= 0) {
        if (g_epfd >= 0)
            epoll_ctl(g_epfd, EPOLL_CTL_DEL, s->timer_fd, NULL);
        close(s->timer_fd);
        s->timer_fd = -1;
    }
    HASH_DEL(g_sessions, s);
    free(s);
}

static const char *sms_msc_gt(void);
static const char *sms_mo_cgpa_gt(void);

static void sms_arm_timer(sms_session_t *s, int timeout_ms)
{
    if (s->timer_fd < 0) {
        s->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
        if (s->timer_fd < 0) return;
        struct epoll_event ev = { .events = EPOLLIN,
                                  .data = { .u64 = SMS_EPOLL_ROLE_SMS_TIMER } };
        epoll_ctl(g_epfd, EPOLL_CTL_ADD, s->timer_fd, &ev);
    }
    struct itimerspec its = {
        .it_value.tv_sec  = (time_t)(timeout_ms / 1000),
        .it_value.tv_nsec = (long)(timeout_ms % 1000) * 1000000L,
    };
    timerfd_settime(s->timer_fd, 0, &its, NULL);
}

static uint64_t sms_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

static uint32_t sms_new_out_otid(void)
{
    uint32_t t = g_out_otid++ | SMS_OTID_OUTBOUND_BIT;
    if (!(t & SMS_OTID_OUTBOUND_BIT))
        t |= SMS_OTID_OUTBOUND_BIT;
    return t;
}

static int partner_for_msisdn(const char *dst)
{
    if (!dst || !g_rt) return -1;
    for (int i = 0; i < g_rt->cfg.sms_n_partners; i++) {
        for (int p = 0; p < g_rt->cfg.sms_partners[i].n_prefixes; p++) {
            const char *pre = g_rt->cfg.sms_partners[i].prefix[p];
            size_t n = strlen(pre);
            if (n && !strncmp(dst, pre, n))
                return i;
        }
    }
    return -1;
}

static int gsm7_udl(uint8_t sm_len) { return sm_len; }

static int build_sms_deliver_tpdu(const char *src_addr, uint8_t data_coding,
                                  uint8_t esm_class, const uint8_t *ud,
                                  uint8_t ud_len, uint8_t *out, size_t cap)
{
    struct tm tm;
    time_t now = time(NULL);
    gmtime_r(&now, &tm);
    uint8_t ts[7];
    ts[0] = (uint8_t)(((tm.tm_year % 100) / 10 << 4) | (tm.tm_year % 10));
    ts[1] = (uint8_t)(((tm.tm_mon + 1) / 10 << 4) | ((tm.tm_mon + 1) % 10));
    ts[2] = (uint8_t)(((tm.tm_mday / 10) << 4) | (tm.tm_mday % 10));
    ts[3] = (uint8_t)(((tm.tm_hour / 10) << 4) | (tm.tm_hour % 10));
    ts[4] = (uint8_t)(((tm.tm_min / 10) << 4) | (tm.tm_min % 10));
    ts[5] = (uint8_t)(((tm.tm_sec / 10) << 4) | (tm.tm_sec % 10));
    ts[6] = 0x00;

    size_t o = 0;
    uint8_t flags = 0x00;
    if (esm_class & 0x40) flags |= 0x40;
    if (o >= cap) return -1;
    out[o++] = flags;

    uint8_t oa[12];
    oa[0] = 0x91;
    int digits = 0;
    for (size_t i = 0; src_addr && src_addr[i]; i++) {
        if (src_addr[i] < '0' || src_addr[i] > '9') continue;
        uint8_t d = (uint8_t)(src_addr[i] - '0');
        size_t off = 1u + (size_t)(digits / 2);
        if (off >= sizeof(oa)) break;
        if ((digits & 1) == 0) oa[off] = d;
        else oa[off] = (uint8_t)(oa[off] | (d << 4));
        digits++;
    }
    if (digits & 1) {
        size_t off = 1u + (size_t)(digits / 2);
        if (off < sizeof(oa)) oa[off] = (uint8_t)((oa[off] & 0x0f) | 0xf0);
    }
    size_t oa_len = 1u + (size_t)((digits + 1) / 2);
    if (o + 1 + oa_len > cap) return -1;
    out[o++] = (uint8_t)digits;
    memcpy(out + o, oa, oa_len);
    o += oa_len;

    if (o + 10 + ud_len > cap) return -1;
    out[o++] = 0x00;
    out[o++] = data_coding;
    memcpy(out + o, ts, 7);
    o += 7;
    out[o++] = (uint8_t)gsm7_udl(ud_len);
    memcpy(out + o, ud, ud_len);
    o += ud_len;
    return (int)o;
}

static int sms_send_tcap_end_result(sms_session_t *s, int opcode,
                                    const uint8_t *params, size_t plen)
{
    uint8_t cmp[256];
    size_t co = 0;
    if (tcap_enc_return_result(cmp, sizeof(cmp), &co, s->peer_invoke_id,
                               opcode, params, plen) < 0)
        return -1;
    uint8_t out[512];
    int n = tcap_encode_message(TCAP_MSG_END, 0, false,
                                s->peer_otid, s->have_peer_otid,
                                NULL, 0, cmp, co, out, sizeof(out));
    if (n < 0) return -1;
    return ss7_link_send_tcap_ex(g_rt, &s->ret_addr, NULL, out, (size_t)n);
}

static int sms_send_tcap_end_error(sms_session_t *s, int err_code)
{
    uint8_t cmp[64];
    size_t co = 0;
    if (tcap_enc_return_error(cmp, sizeof(cmp), &co, s->peer_invoke_id,
                              err_code, NULL, 0) < 0)
        return -1;
    uint8_t out[512];
    int n = tcap_encode_message(TCAP_MSG_END, 0, false,
                                s->peer_otid, s->have_peer_otid,
                                NULL, 0, cmp, co, out, sizeof(out));
    if (n < 0) return -1;
    return ss7_link_send_tcap_ex(g_rt, &s->ret_addr, NULL, out, (size_t)n);
}

static void sms_fail_inbound(sms_session_t *s)
{
    sms_send_tcap_end_error(s, MAP_ERR_SYSTEM_FAILURE);
    sms_sess_remove(s);
}

static void sms_fail_outbound(sms_session_t *s)
{
    if (s->smpp_seq)
        smpp_server_send_submit_resp(s->smpp_seq, SMPP_ESME_RSUBMITFAIL);
    sms_sess_remove(s);
}

/* ----- Inbound MT-SMS delivery (partner SMSC -> our roamer) ------------ */

/* TCAP END back to the SMSC: returnResult(op) or returnError(code), with an
 * AARE echoing the AC OID proposed in the BEGIN (required first backward
 * message on a structured dialogue). */
static int sms_mt_send_end(sms_session_t *s, int is_error, int code,
                           const uint8_t *params, size_t plen)
{
    uint8_t cmp[300];
    size_t co = 0;
    int rc;
    if (is_error)
        rc = tcap_enc_return_error(cmp, sizeof(cmp), &co, s->peer_invoke_id,
                                   code, NULL, 0);
    else
        rc = tcap_enc_return_result(cmp, sizeof(cmp), &co, s->peer_invoke_id,
                                    code, params, plen);
    if (rc < 0) return -1;

    uint8_t dlg[128];
    int dn = 0;
    if (s->aare_oid_len)
        dn = map_encode_aare_oid(s->aare_oid, s->aare_oid_len,
                                 dlg, sizeof(dlg));
    if (dn < 0) dn = 0;

    uint8_t out[512];
    int n = tcap_encode_message(TCAP_MSG_END, 0, false,
                                s->peer_otid, s->have_peer_otid,
                                dn > 0 ? dlg : NULL, dn > 0 ? (size_t)dn : 0,
                                cmp, co, out, sizeof(out));
    if (n < 0) return -1;

    /* CgPA = the MSC GT the SMSC addressed (our local GT), SSN 8. */
    ss7_sccp_addr_t calling;
    memset(&calling, 0, sizeof(calling));
    if (g_rt->cfg.map_local_gt[0])
        ss7_gt_from_digits(g_rt->cfg.map_local_gt, SS7_SSN_MSC, &calling);
    calling.ssn = SS7_SSN_MSC;
    return ss7_link_send_tcap_ex(g_rt, &s->ret_addr,
                                 calling.have_gt ? &calling : NULL,
                                 out, (size_t)n);
}

static int sms_mt_err_absent(const sms_session_t *s)
{
    return s->mt_op == MAP_OP_CODE_MT_FORWARD_SM_V3
           ? MAP_ERR_ABSENT_SUBSCRIBER_SM : MAP_ERR_ABSENT_SUBSCRIBER;
}

/* MAP error for MT-ForwardSM failure relayed from osmo-msc over GSUP.
 * MSC returns GMM cause 0x02 (IMSI unknown in VLR) when the subscriber
 * never LU'd here — map to unidentifiedSubscriber so the SMSC/HLR treat
 * this as "not at this MSC", not an IWF crash (systemFailure). */
static int sms_mt_map_error(const sms_session_t *s, const gsup_parsed_t *m)
{
    if (m->have_cause) {
        switch (m->cause) {
        case GSUP_CAUSE_IMSI_UNKNOWN:
            return MAP_ERR_UNIDENTIFIED_SUBSCRIBER;
        case GSUP_CAUSE_ROAM_NOTALLOWED:
        case GSUP_CAUSE_PLMN_NOTALLOWED:
            return MAP_ERR_ROAMING_NOT_ALLOWED;
        default:
            break;
        }
    }
    if (m->have_sm_rp_cause) {
        uint8_t rp = m->sm_rp_cause;
        /* GSM 04.11: UE unreachable / unknown at this node. */
        if (rp == 27 || rp == 28 || rp == 30)
            return sms_mt_err_absent(s);
    }
    /* GMM 17 is the MSC's catch-all transient.  Fast means it still had no
     * VLR record (an LU raced the SM): subscriberBusyForMT-SMS asks the SMSC
     * to retry in seconds.  Slow means paging or the RP-ACK actually failed:
     * absentSubscriber sets MNRF at the home HLR, so it re-delivers when we
     * relay the MSC's readyForSM instead of dropping the message. */
    if (m->have_cause && m->cause == GSUP_CAUSE_NET_FAIL) {
        /* Error 31 only exists from shortMsgMT-Relay v2 on; a bare v1
         * dialogue (no AARQ, so no AC OID to echo) gets absent instead. */
        if (s->aare_oid_len &&
            sms_now_ms() - s->mt_req_ms < SMS_MT_FAST_FAIL_MS)
            return MAP_ERR_SUBSCRIBER_BUSY_MT_SMS;
        return sms_mt_err_absent(s);
    }
    return MAP_ERR_SYSTEM_FAILURE;
}

/* Build and send the GSUP MT-ForwardSM toward the serving MSC.  Returns 0
 * with the session left in WAIT_GSUP_MT, or -1 after ending the MAP dialogue
 * (caller drops the session). */
static int sms_mt_dispatch_gsup(sms_session_t *s)
{
    int conn = gsup_map_proxy_cs_conn_for_imsi(s->imsi);
    if (conn < 0) {
        LOGI("sms", "[%s] MT-FSM: no MSC GSUP conn -> absent", s->imsi);
        sms_mt_send_end(s, 1, sms_mt_err_absent(s), NULL, 0);
        return -1;
    }
    uint8_t gsup[512];
    int n = gsup_build_mt_fsm_req(s->imsi, s->sm_rp_mr,
                                  s->mt_sc_len ? s->mt_sc_addr : NULL,
                                  s->mt_sc_len,
                                  s->mt_ui, s->mt_ui_len, s->mt_more,
                                  gsup, sizeof(gsup));
    if (n < 0 || gsup_server_send(conn, gsup, (size_t)n) < 0) {
        LOGW("sms", "[%s] MT-FSM: GSUP MT req failed conn=%d", s->imsi, conn);
        sms_mt_send_end(s, 1, MAP_ERR_SYSTEM_FAILURE, NULL, 0);
        return -1;
    }
    s->state = SMS_STATE_WAIT_GSUP_MT;
    s->mt_req_ms = sms_now_ms();
    sms_arm_timer(s, g_rt->cfg.sms_fwdsm_timeout_ms);
    return 0;
}

void sms_iwf_on_mt_fsm(struct iwf_runtime *rt,
                       const ss7_sccp_addr_t *calling,
                       const tcap_msg_t *tmsg,
                       const tcap_component_t *c)
{
    (void)rt;
    if (!g_rt || !calling || !tmsg->have_otid) return;

    if (sms_sess_find(tmsg->otid & ~SMS_OTID_OUTBOUND_BIT))
        return;  /* retransmission of an in-flight dialogue */

    sms_session_t *s = calloc(1, sizeof(*s));
    if (!s) return;
    s->otid = tmsg->otid & ~SMS_OTID_OUTBOUND_BIT;
    s->direction = SMS_DIR_MT_IN;
    s->state = SMS_STATE_WAIT_GSUP_MT;
    s->peer_otid = tmsg->otid;
    s->have_peer_otid = true;
    s->peer_invoke_id = c->invoke_id;
    s->ret_addr = *calling;
    s->timer_fd = -1;
    s->mt_op = c->opcode;
    if (tmsg->dialogue && tmsg->dialogue_len) {
        size_t ol = 0;
        if (map_decode_aarq_ac_raw(tmsg->dialogue, tmsg->dialogue_len,
                                   s->aare_oid, sizeof(s->aare_oid), &ol) == 0)
            s->aare_oid_len = (uint8_t)ol;
    }

    uint8_t sc_addr[12];
    size_t sc_len = 0;
    const uint8_t *ui = NULL;
    size_t ui_len = 0;
    int more = 0;
    if (map_decode_mt_fsm_arg(c->parameters, c->parameters_len,
                              s->imsi, sizeof(s->imsi),
                              sc_addr, sizeof(sc_addr), &sc_len,
                              &ui, &ui_len, &more) < 0 || ui_len > 255) {
        LOGW("sms", "MT-FSM op=%d: bad argument", c->opcode);
        sms_mt_send_end(s, 1, MAP_ERR_UNEXPECTED_DATA_VALUE, NULL, 0);
        free(s);
        return;
    }

    int conn = gsup_map_proxy_cs_conn_for_imsi(s->imsi);
    if (conn < 0) {
        LOGI("sms", "[%s] MT-FSM: no MSC GSUP conn -> absent", s->imsi);
        sms_mt_send_end(s, 1, sms_mt_err_absent(s), NULL, 0);
        free(s);
        return;
    }

    s->sm_rp_mr = g_mt_mr++;
    s->mt_sc_len = (uint8_t)(sc_len > sizeof(s->mt_sc_addr) ? 0 : sc_len);
    if (s->mt_sc_len)
        memcpy(s->mt_sc_addr, sc_addr, s->mt_sc_len);
    s->mt_ui_len = (uint8_t)ui_len;
    if (ui_len)
        memcpy(s->mt_ui, ui, ui_len);
    s->mt_more = (uint8_t)(more ? 1 : 0);

    HASH_ADD(hh, g_sessions, otid, sizeof(s->otid), s);

    /* The home HLR flushes queued MT SMS as soon as it has ISD-acked, which
     * is before it answers our updateLocation - so the SM routinely arrives
     * while the MSC is still mid-LU with no VLR record to deliver to.  Park
     * it; sms_iwf_on_cs_lu_done() releases it when the LU lands. */
    if (gsup_map_proxy_cs_lu_in_flight(s->imsi)) {
        s->state = SMS_STATE_WAIT_LU;
        sms_arm_timer(s, SMS_MT_LU_WAIT_MS);
        LOGI("sms",
             "[%s] RX MT-FSM op=%d otid=0x%08x ui_len=%zu more=%d -> parked, "
             "CS LU in flight",
             s->imsi, s->mt_op, s->peer_otid, ui_len, more);
        return;
    }

    if (sms_mt_dispatch_gsup(s) < 0) {
        sms_sess_remove(s);
        return;
    }
    LOGI("sms",
         "[%s] RX MT-FSM op=%d otid=0x%08x ui_len=%zu more=%d -> GSUP conn=%d mr=%u",
         s->imsi, s->mt_op, s->peer_otid, ui_len, more, conn,
         (unsigned)s->sm_rp_mr);
}

void sms_iwf_on_cs_lu_done(const char *imsi)
{
    if (!g_rt || !imsi || !imsi[0]) return;
    sms_session_t *s, *tmp;
    HASH_ITER(hh, g_sessions, s, tmp) {
        if (s->direction != SMS_DIR_MT_IN) continue;
        if (s->state != SMS_STATE_WAIT_LU) continue;
        if (strcmp(s->imsi, imsi) != 0) continue;
        s->state = SMS_STATE_WAIT_LU_GRACE;
        sms_arm_timer(s, SMS_MT_LU_GRACE_MS);
        LOGI("sms", "[%s] CS LU done -> release parked MT-FSM in %d ms",
             s->imsi, SMS_MT_LU_GRACE_MS);
    }
}

void sms_iwf_on_gsup_mt_resp(const gsup_parsed_t *m)
{
    if (!g_rt || !m) return;
    sms_session_t *s, *tmp, *found = NULL, *by_imsi = NULL;

    /* Prefer exact (IMSI, MR) match.  osmo-msc has been seen returning
     * SM-RP-MR=0 on MT-FSM-RES/ERR even when we sent a non-zero MR, so fall
     * back to a unique IMSI match when the echoed MR does not line up. */
    HASH_ITER(hh, g_sessions, s, tmp) {
        if (s->direction != SMS_DIR_MT_IN) continue;
        /* Parked sessions have nothing outstanding at the MSC. */
        if (s->state != SMS_STATE_WAIT_GSUP_MT) continue;
        if (m->have_imsi && s->imsi[0] && strcmp(s->imsi, m->imsi) != 0)
            continue;
        if (!by_imsi)
            by_imsi = s;
        if (m->have_sm_rp_mr && s->sm_rp_mr == m->sm_rp_mr) {
            found = s;
            break;
        }
    }
    if (!found && by_imsi &&
        (!m->have_sm_rp_mr || m->sm_rp_mr == 0 ||
         by_imsi->sm_rp_mr != m->sm_rp_mr)) {
        if (m->have_sm_rp_mr && m->sm_rp_mr != by_imsi->sm_rp_mr)
            LOGW("sms",
                 "[%s] MT-FSM resp mr=%u != session mr=%u; matching by IMSI",
                 by_imsi->imsi, (unsigned)m->sm_rp_mr,
                 (unsigned)by_imsi->sm_rp_mr);
        found = by_imsi;
    }
    if (!found) {
        LOGW("sms", "MT-FSM resp without session (mr=%u imsi=%s)",
             (unsigned)m->sm_rp_mr, m->have_imsi ? m->imsi : "?");
        return;
    }
    if (m->msg_type == GSUP_MSG_MT_FSM_RES) {
        LOGI("sms", "[%s] MT-FSM delivered mr=%u -> result to SMSC",
             found->imsi, (unsigned)found->sm_rp_mr);
        sms_mt_send_end(found, 0, found->mt_op, NULL, 0);
    } else {
        /* Fast GMM 17 = the MSC had no VLR record yet, not a delivery
         * failure.  The LU it is racing lands within a few hundred ms, so
         * try once more before telling the SMSC anything. */
        if (m->msg_type == GSUP_MSG_MT_FSM_ERR &&
            m->have_cause && m->cause == GSUP_CAUSE_NET_FAIL &&
            !found->mt_retried &&
            sms_now_ms() - found->mt_req_ms < SMS_MT_FAST_FAIL_MS) {
            found->mt_retried = 1;
            found->state = SMS_STATE_WAIT_LU_GRACE;
            sms_arm_timer(found, SMS_MT_RETRY_MS);
            LOGI("sms",
                 "[%s] MT-FSM fast reject (gsup_cause=0x%02x) -> retry in %d ms",
                 found->imsi, (unsigned)m->cause, SMS_MT_RETRY_MS);
            return;
        }
        int ec = sms_mt_map_error(found, m);
        if (m->have_cause)
            LOGI("sms",
                 "[%s] MT-FSM failed gsup_cause=0x%02x rp_cause=%u -> MAP err=%d",
                 found->imsi, (unsigned)m->cause,
                 m->have_sm_rp_cause ? (unsigned)m->sm_rp_cause : 255u, ec);
        else
            LOGI("sms",
                 "[%s] MT-FSM failed rp_cause=%u -> MAP err=%d",
                 found->imsi,
                 m->have_sm_rp_cause ? (unsigned)m->sm_rp_cause : 255u, ec);
        sms_mt_send_end(found, 1, ec, NULL, 0);
    }
    sms_sess_remove(found);
}

/* TCAP END with SRI-SM-Res (IMSI + our MSC GT) back to the SMSC. */
static void sms_sri_sm_answer(sms_session_t *s, const char *imsi)
{
    strncpy(s->imsi, imsi, sizeof(s->imsi) - 1);
    uint8_t params[64];
    int plen = map_encode_sri_sm_res(imsi, sms_msc_gt(),
                                     params, sizeof(params));
    if (plen < 0) {
        sms_fail_inbound(s);
        return;
    }
    if (sms_send_tcap_end_result(s, MAP_OP_CODE_SEND_ROUTING_INFO_SM,
                                 params, (size_t)plen) < 0)
        sms_fail_inbound(s);
    else
        sms_sess_remove(s);
}

static void on_gsup_result(uint32_t corr_id, int error, const char *imsi)
{
    sms_session_t *s = sms_sess_find(corr_id);
    if (!s || s->direction != SMS_DIR_INBOUND) return;
    if (error || !imsi || !imsi[0]) {
        sms_fail_inbound(s);
        return;
    }
    sms_sri_sm_answer(s, imsi);
}

static void handle_inbound_begin(const ss7_sccp_addr_t *calling,
                                 const tcap_msg_t *tmsg,
                                 const tcap_component_t *cmp)
{
    char msisdn[20];
    if (map_decode_sri_sm_arg(cmp->parameters, cmp->parameters_len,
                              msisdn, sizeof(msisdn)) < 0) {
        LOGW("sms", "SRI-SM: bad MSISDN argument");
        return;
    }
    sms_session_t *s = calloc(1, sizeof(*s));
    if (!s) return;
    s->otid = tmsg->otid & ~SMS_OTID_OUTBOUND_BIT;
    s->direction = SMS_DIR_INBOUND;
    s->state = SMS_STATE_WAIT_GSUP;
    s->peer_otid = tmsg->otid;
    s->have_peer_otid = tmsg->have_otid;
    s->peer_invoke_id = cmp->invoke_id;
    s->ret_addr = *calling;
    s->timer_fd = -1;
    snprintf(s->msisdn, sizeof(s->msisdn), "%s", msisdn);
    HASH_ADD(hh, g_sessions, otid, sizeof(s->otid), s);

    LOGI("sms", "RX inbound SRI-SM msisdn=%s otid=0x%08x", msisdn, s->otid);

    /* Resolve MSISDN -> IMSI locally: in-memory msisdn map (fed by ISD),
     * then the HSS Mongo (pretty5gs "subscribers" collection).  Same data
     * the voice SRI path uses; answered synchronously, no external HLR. */
    char imsi[16];
    if (gsup_map_proxy_imsi_for_msisdn(msisdn, imsi, sizeof(imsi)) == 0 &&
        imsi[0]) {
        LOGI("sms", "[%s] SRI-SM: resolved msisdn=%s locally (map/HSS DB)",
             imsi, msisdn);
        sms_sri_sm_answer(s, imsi);
        return;
    }

    /* Legacy fallback: GSUP SRI-SM query toward an external backend
     * ([gsup_client]).  Only useful when such a backend exists. */
    sms_arm_timer(s, g_rt->cfg.sms_gsup_timeout_ms);
    if (gsup_client_send_sri_sm_req(msisdn, s->otid) < 0) {
        LOGW("sms", "SRI-SM: msisdn=%s unknown (map/HSS DB miss, no GSUP "
             "backend) -> unknownSubscriber", msisdn);
        sms_send_tcap_end_error(s, MAP_ERR_UNKNOWN_SUBSCRIBER);
        sms_sess_remove(s);
    }
}

static int sms_send_map_begin(uint32_t otid, int opcode,
                              const uint8_t *params, size_t plen,
                              const uint8_t *dlg, size_t dlen,
                              const ss7_sccp_addr_t *called,
                              const ss7_sccp_addr_t *calling)
{
    uint8_t cmp[512];
    size_t co = 0;
    if (tcap_enc_invoke(cmp, sizeof(cmp), &co, 1, opcode, params, plen) < 0)
        return -1;
    uint8_t out[768];
    int n = tcap_encode_message(TCAP_MSG_BEGIN, otid, true,
                                0, false, dlg, dlen, cmp, co, out, sizeof(out));
    if (n < 0) return -1;
    return ss7_link_send_tcap_ex(g_rt, called, calling, out, (size_t)n);
}

static void start_outbound_sri_sm(sms_session_t *s)
{
    uint8_t arg[64];
    int alen = map_encode_sri_sm_arg(s->msisdn, arg, sizeof(arg));
    if (alen < 0) { sms_fail_outbound(s); return; }

    ss7_sccp_addr_t called, calling;
    ss7_gt_from_digits(g_rt->cfg.sms_partners[s->partner_idx].hlr_gt,
                       g_rt->cfg.sms_hlr_ssn, &called);
    ss7_gt_from_digits(g_rt->cfg.sms_local_smsc_gt, SS7_SSN_MSC, &calling);

    s->state = SMS_STATE_WAIT_SRI_SM;
    sms_arm_timer(s, g_rt->cfg.sms_sri_sm_timeout_ms);
    if (sms_send_map_begin(s->otid, MAP_OP_CODE_SEND_ROUTING_INFO_SM,
                           arg, (size_t)alen, NULL, 0, &called, &calling) < 0)
        sms_fail_outbound(s);
}

static void start_outbound_fwdsm(sms_session_t *s)
{
    int tlen = build_sms_deliver_tpdu(s->src_addr, s->data_coding, s->esm_class,
                                      s->user_data, s->user_data_len,
                                      s->tpdu, sizeof(s->tpdu));
    if (tlen < 0) {
        sms_fail_outbound(s);
        return;
    }
    s->tpdu_len = (uint16_t)tlen;

    uint8_t arg[320];
    int alen = map_encode_mt_fwd_sm_arg(s->imsi, g_rt->cfg.sms_local_smsc_gt,
                                        s->tpdu, s->tpdu_len,
                                        arg, sizeof(arg));
    if (alen < 0) { sms_fail_outbound(s); return; }

    ss7_sccp_addr_t called, calling;
    ss7_gt_from_digits(s->partner_vmsc_gt, SS7_SSN_VLR, &called);
    ss7_gt_from_digits(g_rt->cfg.sms_local_smsc_gt, SS7_SSN_MSC, &calling);

    uint32_t fwd_otid = sms_new_out_otid();
    s->state = SMS_STATE_WAIT_FWDSM;
    sms_arm_timer(s, g_rt->cfg.sms_fwdsm_timeout_ms);
    if (sms_send_map_begin(fwd_otid, MAP_OP_CODE_MT_FORWARD_SM,
                           arg, (size_t)alen, NULL, 0, &called, &calling) < 0) {
        sms_fail_outbound(s);
        return;
    }
    HASH_DEL(g_sessions, s);
    s->otid = fwd_otid;
    HASH_ADD(hh, g_sessions, otid, sizeof(s->otid), s);
}

static void on_smpp_disconnect(void)
{
    sms_session_t *s, *tmp;
    HASH_ITER(hh, g_sessions, s, tmp) {
        if (s->direction != SMS_DIR_OUTBOUND) continue;
        if (s->smpp_seq)
            smpp_server_send_submit_resp(s->smpp_seq, SMPP_ESME_RSUBMITFAIL);
        sms_sess_remove(s);
    }
}

static void on_smpp_submit(uint32_t seq,
                           const char *src, uint8_t src_ton, uint8_t src_npi,
                           const char *dst, uint8_t dst_ton, uint8_t dst_npi,
                           uint8_t data_coding, uint8_t esm_class,
                           const uint8_t *ud, uint8_t ud_len)
{
    (void)src_ton; (void)src_npi; (void)dst_ton; (void)dst_npi;
    int pidx = partner_for_msisdn(dst);
    if (pidx < 0) {
        smpp_server_send_submit_resp(seq, SMPP_ESME_RINVDSTADR);
        return;
    }
    sms_session_t *s = calloc(1, sizeof(*s));
    if (!s) {
        smpp_server_send_submit_resp(seq, SMPP_ESME_RSUBMITFAIL);
        return;
    }
    s->otid = sms_new_out_otid();
    s->direction = SMS_DIR_OUTBOUND;
    s->state = SMS_STATE_WAIT_SRI_SM;
    s->smpp_seq = seq;
    s->partner_idx = pidx;
    s->timer_fd = -1;
    snprintf(s->msisdn, sizeof(s->msisdn), "%s", dst);
    snprintf(s->src_addr, sizeof(s->src_addr), "%s", src ? src : "");
    s->data_coding = data_coding;
    s->esm_class = esm_class;
    /* ud_len is uint8_t (<=255) and user_data is 256 bytes, so it always fits. */
    memcpy(s->user_data, ud, ud_len);
    s->user_data_len = ud_len;
    HASH_ADD(hh, g_sessions, otid, sizeof(s->otid), s);

    LOGI("sms", "SMPP submit_sm seq=%u dst=%s partner=%s",
         seq, dst, g_rt->cfg.sms_partners[pidx].name);
    start_outbound_sri_sm(s);
}

static void handle_outbound_tcap(const tcap_msg_t *tmsg)
{
    if (!tmsg->have_dtid) return;
    sms_session_t *s = sms_sess_find(tmsg->dtid);
    if (!s || s->direction != SMS_DIR_OUTBOUND) return;

    for (size_t i = 0; i < tmsg->n_components; i++) {
        const tcap_component_t *c = &tmsg->components[i];
        if (c->kind == TCAP_CMP_KIND_ERR) {
            sms_fail_outbound(s);
            return;
        }
        if (c->kind != TCAP_CMP_KIND_RES) continue;

        if (s->state == SMS_STATE_WAIT_SRI_SM &&
            c->opcode == MAP_OP_CODE_SEND_ROUTING_INFO_SM) {
            uint8_t imsi_bcd[8];
            size_t ilen = 0;
            char vmsc[24];
            if (map_decode_sri_sm_res(c->parameters, c->parameters_len,
                                      imsi_bcd, &ilen, vmsc, sizeof(vmsc)) < 0) {
                sms_fail_outbound(s);
                return;
            }
            map_bcd_to_str(imsi_bcd, ilen, s->imsi, sizeof(s->imsi));
            snprintf(s->partner_vmsc_gt, sizeof(s->partner_vmsc_gt), "%s", vmsc);
            start_outbound_fwdsm(s);
            return;
        }
        if (s->state == SMS_STATE_WAIT_FWDSM &&
            c->opcode == MAP_OP_CODE_MT_FORWARD_SM) {
            smpp_server_send_submit_resp(s->smpp_seq, SMPP_ESME_ROK);
            sms_sess_remove(s);
            return;
        }
    }
}

/* ----- Outbound MO-SMS relay (our subscriber -> home SMSC) ------------- */

/* Osmocom GSUP SM-RP-DA/OA: [id-type][identity].
 * id-type: 1=IMSI, 2=MSISDN, 3=SMSC (libosmocore osmo_gsup_sms_sm_rp_oda_t).
 * identity for MSISDN/SMSC is GSM 04.11 style: optional length, TON/NPI, TBCD.
 * We rebuild a MAP AddressString (TON/NPI + TBCD), preserving the original
 * TON/NPI when present instead of always forcing 0x91. */
#define GSUP_SM_ODA_IMSI   1
#define GSUP_SM_ODA_MSISDN 2
#define GSUP_SM_ODA_SMSC   3

static int toa_looks_valid(uint8_t b)
{
    /* TS 23.040 / 24.008 type-of-address: ext=1, TON 0..7, NPI 0..15.
     * Require ext bit so we do not treat a TBCD digit-pair as TOA. */
    return (b & 0x80) != 0;
}

/* Parse GSUP address into MAP AddressString + digit string for GT/logging.
 * Returns 0 on success. */
static int gsup_sm_addr_parse(const uint8_t *v, size_t l,
                              uint8_t *type_out,
                              uint8_t *addr_out, size_t addr_cap, size_t *addr_len,
                              char *digits, size_t dig_cap)
{
    if (!v || l < 2 || !addr_out || addr_cap < 2 || !addr_len ||
        !digits || !dig_cap)
        return -1;
    digits[0] = '\0';
    *addr_len = 0;
    uint8_t type = v[0];
    if (type_out) *type_out = type;

    const uint8_t *id = v + 1;
    size_t idl = l - 1;
    if (idl == 0) return -1;

    /* Optional GSM 04.11 length byte (length of the rest of the IE). */
    if (idl >= 2 && id[0] == (uint8_t)(idl - 1)) {
        id++;
        idl--;
    }
    if (idl == 0) return -1;

    uint8_t ton = 0x91;
    const uint8_t *tbcd = id;
    size_t tbcd_len = idl;
    if (toa_looks_valid(id[0])) {
        ton = id[0];
        tbcd = id + 1;
        tbcd_len = idl - 1;
    }
    if (tbcd_len == 0 || tbcd_len + 1 > addr_cap) return -1;

    addr_out[0] = ton;
    memcpy(addr_out + 1, tbcd, tbcd_len);
    *addr_len = 1 + tbcd_len;
    map_bcd_to_str(tbcd, tbcd_len, digits, dig_cap);
    return digits[0] ? 0 : -1;
}

static void sms_mo_reply_err(int conn_id, const char *imsi, uint8_t mr,
                             uint8_t rp_cause)
{
    uint8_t gsup[128];
    int n = gsup_build_mo_fsm_err(imsi, mr, rp_cause, gsup, sizeof(gsup));
    if (n > 0)
        gsup_server_send(conn_id, gsup, (size_t)n);
}

/* Node GT for SRI-SM-Res: same as UL msc-Number (VLR GT partners already hit). */
static const char *sms_msc_gt(void)
{
    if (g_rt->cfg.map_local_gt[0])
        return g_rt->cfg.map_local_gt;
    if (g_rt->cfg.sms_local_msc_gt[0])
        return g_rt->cfg.sms_local_msc_gt;
    return "";
}

/* SCCP CgPA for outbound mo-ForwardSM: serving MSC GT (TS 23.040). */
static const char *sms_mo_cgpa_gt(void)
{
    if (g_rt->cfg.sms_local_msc_gt[0])
        return g_rt->cfg.sms_local_msc_gt;
    if (g_rt->cfg.map_local_gt[0])
        return g_rt->cfg.map_local_gt;
    return "";
}

/* Nature of number from a MAP AddressString / GSUP SM-RP-DA first octet.
 * A leading '0' is never part of an E.164 international number, so an
 * "international" claim over such digits is not believed. */
static int sms_addr_is_international(const uint8_t *addr, size_t alen,
                                     const char *digits)
{
    return alen >= 1 && (addr[0] & 0x70) == 0x10 &&
           digits && digits[0] && digits[0] != '0';
}

static int sms_rebuild_intl_addr(const char *digits, uint8_t *addr, size_t cap,
                                 size_t *alen)
{
    if (!digits || !digits[0] || !addr || cap < 2 || !alen)
        return -1;
    addr[0] = 0x91;
    int n = map_str_to_bcd(digits, addr + 1, cap - 1);
    if (n < 1)
        return -1;
    *alen = 1 + (size_t)n;
    return 0;
}

void sms_iwf_on_gsup_mo_req(int conn_id, const gsup_parsed_t *m)
{
    if (!g_rt || !m) return;
    uint8_t mr = m->have_sm_rp_mr ? m->sm_rp_mr : 0;

    char smsc[24], oa_dig[24];
    uint8_t da_type = 0, oa_type = 0;
    uint8_t da_addr[16], oa_addr[16];
    size_t da_alen = 0, oa_alen = 0;

    if (!m->sm_rp_ui_len) {
        LOGW("sms",
             "[%s] MO-FSM reject RP-96: missing SM-RP-UI ui_len=0 mr=%u",
             m->imsi, (unsigned)mr);
        sms_mo_reply_err(conn_id, m->imsi, mr, 96);
        return;
    }
    if (!m->sm_rp_da_len ||
        gsup_sm_addr_parse(m->sm_rp_da, m->sm_rp_da_len,
                           &da_type, da_addr, sizeof(da_addr), &da_alen,
                           smsc, sizeof(smsc)) < 0) {
        LOGW("sms",
             "[%s] MO-FSM reject RP-96: bad SM-RP-DA parse da_len=%u "
             "da_type=%u mr=%u",
             m->imsi, (unsigned)m->sm_rp_da_len, (unsigned)(m->sm_rp_da_len ? m->sm_rp_da[0] : 0),
             (unsigned)mr);
        sms_mo_reply_err(conn_id, m->imsi, mr, 96);
        return;
    }
    if (da_type != GSUP_SM_ODA_SMSC) {
        LOGW("sms",
             "[%s] MO-FSM reject RP-96: SM-RP-DA type=%u want SMSC(%u) "
             "digits=%s mr=%u",
             m->imsi, (unsigned)da_type, GSUP_SM_ODA_SMSC, smsc, (unsigned)mr);
        sms_mo_reply_err(conn_id, m->imsi, mr, 96);
        return;
    }
    if (!m->sm_rp_oa_len ||
        gsup_sm_addr_parse(m->sm_rp_oa, m->sm_rp_oa_len,
                           &oa_type, oa_addr, sizeof(oa_addr), &oa_alen,
                           oa_dig, sizeof(oa_dig)) < 0) {
        LOGW("sms",
             "[%s] MO-FSM reject RP-96: bad SM-RP-OA parse oa_len=%u "
             "oa_type=%u mr=%u",
             m->imsi, (unsigned)m->sm_rp_oa_len,
             (unsigned)(m->sm_rp_oa_len ? m->sm_rp_oa[0] : 0), (unsigned)mr);
        sms_mo_reply_err(conn_id, m->imsi, mr, 96);
        return;
    }
    if (oa_type != GSUP_SM_ODA_MSISDN) {
        LOGW("sms",
             "[%s] MO-FSM reject RP-96: SM-RP-OA type=%u want MSISDN(%u) "
             "digits=%s mr=%u",
             m->imsi, (unsigned)oa_type, GSUP_SM_ODA_MSISDN, oa_dig,
             (unsigned)mr);
        sms_mo_reply_err(conn_id, m->imsi, mr, 96);
        return;
    }

    /* The MS/MSC already states the nature of number. Only guess the format
     * when it is not international: normalising a GT that is already E.164
     * corrupts short international SMSC addresses (MCI's 9891100500 is ten
     * digits starting with '9' and would gain a second country code). */
    char smsc_raw[24];
    snprintf(smsc_raw, sizeof(smsc_raw), "%s", smsc);
    uint8_t da_ton = da_alen ? da_addr[0] : 0;
    int da_intl = sms_addr_is_international(da_addr, da_alen, smsc);
    if (!da_intl)
        map_normalize_msisdn_digits(smsc, smsc, sizeof(smsc));
    if (strlen(smsc) < 8) {
        LOGW("sms",
             "[%s] MO-FSM reject RP-96: SMSC GT too short raw=%s norm=%s "
             "ton=0x%02x mr=%u",
             m->imsi, smsc_raw, smsc, (unsigned)da_ton, (unsigned)mr);
        sms_mo_reply_err(conn_id, m->imsi, mr, 96);
        return;
    }
    if (!da_intl &&
        sms_rebuild_intl_addr(smsc, da_addr, sizeof(da_addr), &da_alen) < 0) {
        LOGW("sms", "[%s] MO-FSM reject RP-96: SMSC GT encode failed gt=%s mr=%u",
             m->imsi, smsc, (unsigned)mr);
        sms_mo_reply_err(conn_id, m->imsi, mr, 96);
        return;
    }
    if (strcmp(smsc_raw, smsc) != 0)
        LOGI("sms", "[%s] MO-FSM SMSC GT %s -> %s (ton=0x%02x)",
             m->imsi, smsc_raw, smsc, (unsigned)da_ton);

    uint8_t arg[400];
    int an = map_encode_mo_fwd_sm_arg(da_addr, da_alen, oa_addr, oa_alen,
                                      m->sm_rp_ui, m->sm_rp_ui_len,
                                      m->imsi, arg, sizeof(arg));
    if (an < 0) {
        LOGW("sms", "[%s] MO-FSM: MAP encode failed smsc=%s oa=%s",
             m->imsi, smsc, oa_dig);
        sms_mo_reply_err(conn_id, m->imsi, mr, 41 /* temporary failure */);
        return;
    }
    uint8_t dlg[128];
    int dn = map_encode_aarq(MAP_AC_SHORT_MSG_MO_RELAY_V3, dlg, sizeof(dlg));
    if (dn < 0) {
        sms_mo_reply_err(conn_id, m->imsi, mr, 41);
        return;
    }

    sms_session_t *s = calloc(1, sizeof(*s));
    if (!s) {
        sms_mo_reply_err(conn_id, m->imsi, mr, 41);
        return;
    }
    s->otid = sms_new_out_otid();
    s->direction = SMS_DIR_MO_OUT;
    s->state = SMS_STATE_WAIT_MO_FSM;
    s->timer_fd = -1;
    s->gsup_conn = conn_id;
    s->sm_rp_mr = mr;
    strncpy(s->imsi, m->imsi, sizeof(s->imsi) - 1);

    /* CdPA = SMSC GT from SM-RP-DA; CgPA = serving MSC GT (not VLR). */
    const char *cgpa = sms_mo_cgpa_gt();
    ss7_sccp_addr_t called, calling;
    ss7_gt_from_digits(smsc, SS7_SSN_MSC, &called);
    memset(&calling, 0, sizeof(calling));
    if (cgpa && cgpa[0])
        ss7_gt_from_digits(cgpa, SS7_SSN_MSC, &calling);
    calling.ssn = SS7_SSN_MSC;

    if (sms_send_map_begin(s->otid, MAP_OP_CODE_MT_FORWARD_SM /* mo-ForwardSM */,
                           arg, (size_t)an, dlg, (size_t)dn,
                           &called, calling.have_gt ? &calling : NULL) < 0) {
        free(s);
        sms_mo_reply_err(conn_id, m->imsi, mr, 41);
        return;
    }
    HASH_ADD(hh, g_sessions, otid, sizeof(s->otid), s);
    sms_arm_timer(s, g_rt->cfg.sms_fwdsm_timeout_ms);
    LOGI("sms",
         "[%s] RX GSUP MO-FSM mr=%u smsc=%s ton=0x%02x oa=%s ton=0x%02x "
         "ui_len=%u -> MAP mo-FwdSM-v3+imsi otid=0x%08x cgpa=%s",
         m->imsi, (unsigned)mr, smsc, (unsigned)da_addr[0],
         oa_dig, (unsigned)oa_addr[0],
         (unsigned)m->sm_rp_ui_len, s->otid, cgpa[0] ? cgpa : "-");
}

bool sms_iwf_on_mo_tcap(struct iwf_runtime *rt, const tcap_msg_t *tmsg)
{
    (void)rt;
    if (!g_rt || !tmsg->have_dtid) return false;
    sms_session_t *s = sms_sess_find(tmsg->dtid);
    if (!s || (s->direction != SMS_DIR_MO_OUT &&
               s->direction != SMS_DIR_ALERT_OUT))
        return false;
    bool alert = s->direction == SMS_DIR_ALERT_OUT;
    const char *what = alert ? "readyForSM" : "MO-FSM";

    uint8_t gsup[128];
    int n = -1;
    bool done = false;
    for (size_t i = 0; i < tmsg->n_components && !done; i++) {
        const tcap_component_t *c = &tmsg->components[i];
        if (c->kind == TCAP_CMP_KIND_RES) {
            LOGI("sms", "[%s] %s accepted mr=%u",
                 s->imsi, what, (unsigned)s->sm_rp_mr);
            n = alert
                ? gsup_build_ready_for_sm_res(s->imsi, s->sm_rp_mr,
                                              gsup, sizeof(gsup))
                : gsup_build_mo_fsm_res(s->imsi, s->sm_rp_mr,
                                        gsup, sizeof(gsup));
            done = true;
        } else if (c->kind == TCAP_CMP_KIND_ERR) {
            LOGI("sms", "[%s] %s rejected map_err=%d mr=%u",
                 s->imsi, what, c->error_code, (unsigned)s->sm_rp_mr);
            n = alert
                ? gsup_build_ready_for_sm_err(s->imsi, s->sm_rp_mr,
                                              41 /* temporary failure */,
                                              gsup, sizeof(gsup))
                : gsup_build_mo_fsm_err(s->imsi, s->sm_rp_mr, 41,
                                        gsup, sizeof(gsup));
            done = true;
        }
    }
    /* END without any component: dialogue closed without result. */
    if (!done && tmsg->type == TCAP_MSG_END) {
        LOGW("sms", "[%s] %s: END without result", s->imsi, what);
        n = alert
            ? gsup_build_ready_for_sm_err(s->imsi, s->sm_rp_mr, 41,
                                          gsup, sizeof(gsup))
            : gsup_build_mo_fsm_err(s->imsi, s->sm_rp_mr, 41,
                                    gsup, sizeof(gsup));
        done = true;
    }
    if (done) {
        if (n > 0)
            gsup_server_send(s->gsup_conn, gsup, (size_t)n);
        sms_sess_remove(s);
    }
    return true;
}

/* ----- readyForSM relay (MSC alert -> home HLR message-waiting) --------- */

static void sms_rfsm_reply_err(int conn_id, const char *imsi, uint8_t mr,
                               uint8_t rp_cause)
{
    uint8_t gsup[128];
    int n = gsup_build_ready_for_sm_err(imsi, mr, rp_cause,
                                        gsup, sizeof(gsup));
    if (n > 0)
        gsup_server_send(conn_id, gsup, (size_t)n);
}

void sms_iwf_on_gsup_ready_for_sm(int conn_id, const gsup_parsed_t *m)
{
    if (!g_rt || !m) return;
    uint8_t mr = m->have_sm_rp_mr ? m->sm_rp_mr : 0;

    gsup_route_t route;
    if (gsup_router_lookup(&g_rt->cfg, m->imsi, &route) < 0 ||
        route.kind == GSUP_ROUTE_REJECT) {
        LOGI("sms", "[%s] readyForSM: unroutable IMSI -> error", m->imsi);
        sms_rfsm_reply_err(conn_id, m->imsi, mr, 38 /* net out of order */);
        return;
    }
    if (!route.hlr_gt[0] && !route.e214_prefix[0]) {
        /* Partner reachable only over Diameter: there is no MAP readyForSM to
         * send. RP-SMMA is advisory, so acknowledge it rather than telling the
         * handset the network is out of order - cause 38 makes it repeat the
         * notification in a tight loop. Give the PLMN an mnc<NNN>_hlr_gt or
         * mnc<NNN>_e214_prefix in [roaming_hlr] to alert its HLR for real. */
        uint8_t gsup[128];
        int n = gsup_build_ready_for_sm_res(m->imsi, mr, gsup, sizeof(gsup));
        LOGI("sms",
             "[%s] readyForSM: no MAP HLR route for %u-%0*u -> ack locally",
             m->imsi, (unsigned)route.mcc, route.mnc_digits,
             (unsigned)route.mnc);
        if (n > 0)
            gsup_server_send(conn_id, gsup, (size_t)n);
        return;
    }

    /* GSUP alert reason 1 = ms-present, 2 = memory available;
     * MAP AlertReason  0 = ms-Present, 1 = memoryAvailable. */
    uint8_t reason = (m->have_sm_alert_reason &&
                      m->sm_alert_reason == GSUP_SM_ALERT_MS_PRESENT) ? 0 : 1;

    uint8_t arg[48];
    int an = map_encode_ready_for_sm_arg(m->imsi, reason, arg, sizeof(arg));
    uint8_t dlg[128];
    int dn = map_encode_aarq(MAP_AC_MWD_MNGT_V2, dlg, sizeof(dlg));
    if (an < 0 || dn < 0) {
        sms_rfsm_reply_err(conn_id, m->imsi, mr, 41);
        return;
    }

    sms_session_t *s = calloc(1, sizeof(*s));
    if (!s) {
        sms_rfsm_reply_err(conn_id, m->imsi, mr, 41);
        return;
    }
    s->otid = sms_new_out_otid();
    s->direction = SMS_DIR_ALERT_OUT;
    s->state = SMS_STATE_WAIT_RFSM;
    s->timer_fd = -1;
    s->gsup_conn = conn_id;
    s->sm_rp_mr = mr;
    strncpy(s->imsi, m->imsi, sizeof(s->imsi) - 1);

    /* CdPA: E.214 MGT (prefix + MSIN) or fixed HLR GT - same routing the
     * outbound UL/USSD use. CgPA: our MSC GT, SSN 8. */
    ss7_sccp_addr_t called, calling;
    if (route.e214_prefix[0]) {
        char mgt[40];
        size_t skip = 3 + (route.mnc_digits == 3 ? 3u : 2u);
        size_t il = strlen(route.imsi);
        snprintf(mgt, sizeof(mgt), "%s%s", route.e214_prefix,
                 il > skip ? route.imsi + skip : "");
        ss7_gt_from_digits(mgt, route.hlr_ssn ? route.hlr_ssn : SS7_SSN_HLR,
                           &called);
        called.gt_np_e214 = true;
    } else {
        ss7_gt_from_digits(route.hlr_gt,
                           route.hlr_ssn ? route.hlr_ssn : SS7_SSN_HLR,
                           &called);
    }
    memset(&calling, 0, sizeof(calling));
    const char *src_gt = route.src_gt[0] ? route.src_gt
                                         : g_rt->cfg.map_local_gt;
    if (src_gt && src_gt[0])
        ss7_gt_from_digits(src_gt, SS7_SSN_MSC, &calling);
    calling.ssn = SS7_SSN_MSC;

    if (sms_send_map_begin(s->otid, MAP_OP_CODE_READY_FOR_SM,
                           arg, (size_t)an, dlg, (size_t)dn,
                           &called, calling.have_gt ? &calling : NULL) < 0) {
        free(s);
        sms_rfsm_reply_err(conn_id, m->imsi, mr, 41);
        return;
    }
    HASH_ADD(hh, g_sessions, otid, sizeof(s->otid), s);
    sms_arm_timer(s, g_rt->cfg.sms_fwdsm_timeout_ms);
    LOGI("sms",
         "[%s] RX GSUP READY-FOR-SM mr=%u reason=%s -> MAP readyForSM "
         "otid=0x%08x cdpa=%s%s",
         m->imsi, (unsigned)mr, reason ? "memAvail" : "msPresent",
         s->otid, called.gt_digits, called.gt_np_e214 ? " (E.214)" : "");
}

static void on_hlr_sccp(struct iwf_runtime *rt,
                        const ss7_sccp_addr_t *calling,
                        const uint8_t *tcap, size_t len)
{
    if (!rt) return;
    const ss7_sccp_addr_t *cp = calling;

    tcap_msg_t tmsg;
    if (tcap_decode(tcap, len, &tmsg) < 0) return;

    /* SRI-SM is SMS-IWF only; everything else on HLR SSN goes to MAP-IWF
     * (SAI, purgeMS, UGL, …). Without this demux those ops were dropped
     * silently when CdPA SSN=6 (route-on-SSN after GTT). */
    if (tmsg.type == TCAP_MSG_BEGIN && tmsg.n_components > 0 &&
        tmsg.components[0].kind == TCAP_CMP_KIND_INVOKE &&
        tmsg.components[0].opcode == MAP_OP_CODE_SEND_ROUTING_INFO_SM) {
        handle_inbound_begin(cp, &tmsg, &tmsg.components[0]);
        return;
    }
    if ((tmsg.type == TCAP_MSG_END || tmsg.type == TCAP_MSG_CONTINUE) &&
        tmsg.have_dtid) {
        sms_session_t *s = sms_sess_find(tmsg.dtid);
        if (s && s->direction == SMS_DIR_OUTBOUND) {
            handle_outbound_tcap(&tmsg);
            return;
        }
    }

    map_iwf_on_sccp_unitdata(rt, cp, tcap, len);
}

void sms_iwf_on_smpp_srv_readable(void) { smpp_server_on_listen_readable(); }
void sms_iwf_on_smpp_conn_readable(void) { smpp_server_on_conn_readable(); }
void sms_iwf_on_gsup_readable(void)       { gsup_client_on_readable(); }
void sms_iwf_on_gsup_keepalive(void)    { gsup_client_on_keepalive(); }

void sms_iwf_on_timer(void)
{
    /* epoll data.u64 is the role tag; find which session timer fired. */
    sms_session_t *s, *tmp;
    HASH_ITER(hh, g_sessions, s, tmp) {
        if (s->timer_fd < 0)
            continue;
        uint64_t exp;
        ssize_t r = read(s->timer_fd, &exp, sizeof(exp));
        if (r != (ssize_t)sizeof(exp))
            continue;
        if (s->direction == SMS_DIR_MT_IN &&
            (s->state == SMS_STATE_WAIT_LU ||
             s->state == SMS_STATE_WAIT_LU_GRACE)) {
            /* Not a timeout: the parked SM is due (LU landed, LU took too
             * long, or the one retry is up). */
            LOGI("sms", "[%s] releasing parked MT-FSM state=%u retry=%u",
                 s->imsi, (unsigned)s->state, (unsigned)s->mt_retried);
            if (sms_mt_dispatch_gsup(s) < 0)
                sms_sess_remove(s);
            return;
        }
        LOGW("sms", "session timeout otid=0x%08x state=%u", s->otid, s->state);
        if (s->direction == SMS_DIR_INBOUND) {
            sms_fail_inbound(s);
        } else if (s->direction == SMS_DIR_MT_IN) {
            /* MSC never answered: paging failed.  absentSubscriber sets MNRF
             * at the home HLR so it re-delivers on our readyForSM relay. */
            sms_mt_send_end(s, 1, sms_mt_err_absent(s), NULL, 0);
            sms_sess_remove(s);
        } else if (s->direction == SMS_DIR_MO_OUT) {
            /* Home SMSC didn't answer: UE gets RP-ERROR and retries. */
            sms_mo_reply_err(s->gsup_conn, s->imsi, s->sm_rp_mr,
                             41 /* temporary failure */);
            sms_sess_remove(s);
        } else if (s->direction == SMS_DIR_ALERT_OUT) {
            /* Home HLR didn't answer the alert: harmless, SMSC retries
             * on its own timer anyway. */
            sms_rfsm_reply_err(s->gsup_conn, s->imsi, s->sm_rp_mr, 41);
            sms_sess_remove(s);
        } else {
            sms_fail_outbound(s);
        }
        return;
    }
}

bool sms_iwf_enabled(const struct iwf_runtime *rt)
{
    return rt && rt->cfg.sms_iwf_enabled && map_iwf_enabled(rt);
}

int sms_iwf_init(struct iwf_runtime *rt, int epfd)
{
    if (!rt || !rt->cfg.sms_iwf_enabled) return 0;
    if (!map_iwf_enabled(rt)) {
        LOGE("sms", "SMS-IWF requires [map_iwf].enabled = 1");
        return -1;
    }
    g_rt = rt;
    g_epfd = epfd;

    if (ss7_link_bind_hlr_ssn(rt, rt->cfg.sms_hlr_ssn) < 0)
        return -1;
    ss7_link_set_hlr_recv_cb(rt, on_hlr_sccp);

    gsup_client_set_cb(on_gsup_result);
    if (gsup_client_init(rt->cfg.gsup_remote_ip, rt->cfg.gsup_remote_port,
                         rt->cfg.gsup_client_name, epfd) < 0)
        return -1;

    smpp_server_set_submit_cb(on_smpp_submit);
    smpp_server_set_disconnect_cb(on_smpp_disconnect);
    if (smpp_server_init(rt->cfg.smpp_bind_ip, rt->cfg.smpp_port,
                         rt->cfg.smpp_system_id, rt->cfg.smpp_password,
                         epfd) < 0)
        return -1;

    LOGI("sms", "MAP SMS-IWF ready (HLR SSN %u, SMPP %s:%u, GSUP %s:%u)",
         (unsigned)rt->cfg.sms_hlr_ssn,
         rt->cfg.smpp_bind_ip, (unsigned)rt->cfg.smpp_port,
         rt->cfg.gsup_remote_ip, (unsigned)rt->cfg.gsup_remote_port);
    return 0;
}

void sms_iwf_shutdown(struct iwf_runtime *rt)
{
    (void)rt;
    sms_session_t *s, *tmp;
    HASH_ITER(hh, g_sessions, s, tmp)
        sms_sess_remove(s);
    smpp_server_shutdown();
    gsup_client_shutdown();
    g_rt = NULL;
    g_epfd = -1;
}
