/*
 * sms_iwf.c - MAP SMS interworking (inbound MT SRI-SM + outbound MO via SMPP).
 */

#include "sms_iwf.h"
#include "map_iwf.h"
#include "gsup_client.h"
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

#define SMS_STATE_WAIT_GSUP     1
#define SMS_STATE_WAIT_SRI_SM   2
#define SMS_STATE_WAIT_FWDSM    3

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
} sms_session_t;

static struct iwf_runtime *g_rt;
static sms_session_t *g_sessions;
static uint32_t g_out_otid = SMS_OTID_OUTBOUND_BIT;
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

static void on_gsup_result(uint32_t corr_id, int error, const char *imsi)
{
    sms_session_t *s = sms_sess_find(corr_id);
    if (!s || s->direction != SMS_DIR_INBOUND) return;
    if (error || !imsi || !imsi[0]) {
        sms_fail_inbound(s);
        return;
    }
    strncpy(s->imsi, imsi, sizeof(s->imsi) - 1);
    uint8_t params[64];
    int plen = map_encode_sri_sm_res(imsi, g_rt->cfg.sms_local_msc_gt,
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
    strncpy(s->msisdn, msisdn, sizeof(s->msisdn) - 1);
    HASH_ADD(hh, g_sessions, otid, sizeof(s->otid), s);
    sms_arm_timer(s, g_rt->cfg.sms_gsup_timeout_ms);

    LOGI("sms", "RX inbound SRI-SM msisdn=%s otid=0x%08x", msisdn, s->otid);
    if (gsup_client_send_sri_sm_req(msisdn, s->otid) < 0)
        sms_fail_inbound(s);
}

static int sms_send_map_begin(uint32_t otid, int opcode,
                              const uint8_t *params, size_t plen,
                              const ss7_sccp_addr_t *called,
                              const ss7_sccp_addr_t *calling)
{
    uint8_t cmp[256];
    size_t co = 0;
    if (tcap_enc_invoke(cmp, sizeof(cmp), &co, 1, opcode, params, plen) < 0)
        return -1;
    uint8_t out[512];
    int n = tcap_encode_message(TCAP_MSG_BEGIN, otid, true,
                                0, false, NULL, 0, cmp, co, out, sizeof(out));
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
                           arg, (size_t)alen, &called, &calling) < 0)
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
                           arg, (size_t)alen, &called, &calling) < 0) {
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
    strncpy(s->msisdn, dst, sizeof(s->msisdn) - 1);
    strncpy(s->src_addr, src ? src : "", sizeof(s->src_addr) - 1);
    s->data_coding = data_coding;
    s->esm_class = esm_class;
    if (ud_len > sizeof(s->user_data))
        ud_len = (uint8_t)sizeof(s->user_data);
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
            strncpy(s->partner_vmsc_gt, vmsc, sizeof(s->partner_vmsc_gt) - 1);
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

static void on_hlr_sccp(struct iwf_runtime *rt,
                        const ss7_sccp_addr_t *calling,
                        const uint8_t *tcap, size_t len)
{
    if (!rt) return;
    const ss7_sccp_addr_t *cp = calling;

    tcap_msg_t tmsg;
    if (tcap_decode(tcap, len, &tmsg) < 0) return;

    if (tmsg.type == TCAP_MSG_BEGIN && tmsg.n_components > 0 &&
        tmsg.components[0].kind == TCAP_CMP_KIND_INVOKE &&
        tmsg.components[0].opcode == MAP_OP_CODE_SEND_ROUTING_INFO_SM) {
        handle_inbound_begin(cp, &tmsg, &tmsg.components[0]);
        return;
    }
    if (tmsg.type == TCAP_MSG_END || tmsg.type == TCAP_MSG_CONTINUE)
        handle_outbound_tcap(&tmsg);
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
        LOGW("sms", "session timeout otid=0x%08x state=%u", s->otid, s->state);
        if (s->direction == SMS_DIR_INBOUND)
            sms_fail_inbound(s);
        else
            sms_fail_outbound(s);
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
