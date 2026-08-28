/*
 * isup_call.c — BICC/ISUP call state, IAM originate, circuit supervision.
 */

#include "isup_call.h"
#include "isup_codec.h"
#include "isup_cic.h"
#include "sip_iwf.h"
#include "ss7_link.h"
#include "config.h"
#include "runtime.h"
#include "logging.h"

#include <string.h>
#include <time.h>
#include <stdio.h>

#ifdef MAP_IWF_WITH_OSMO_SIGTRAN
#  include <osmocom/sigtran/protocol/mtp.h>
#else
#  define MTP_SI_ISUP  5
#  define MTP_SI_BICC 13
#endif

#define ISUP_CALL_MAX 128

typedef enum {
    IC_IDLE = 0,
    IC_IAM_SENT,
    IC_EARLY,
    IC_CONNECTED,
    IC_WAIT_RLC,
} ic_state_t;

typedef struct {
    int         used;
    uint32_t    sip_id;
    uint16_t    cic;
    ic_state_t  st;
    time_t      t0;
    int         rel_sent;
} isup_leg_t;

static isup_leg_t g_leg[ISUP_CALL_MAX];
static struct iwf_runtime *g_rt;

static isup_leg_t *leg_by_sip(uint32_t sip_id)
{
    for (int i = 0; i < ISUP_CALL_MAX; i++)
        if (g_leg[i].used && g_leg[i].sip_id == sip_id)
            return &g_leg[i];
    return NULL;
}

static isup_leg_t *leg_by_cic(uint16_t cic)
{
    for (int i = 0; i < ISUP_CALL_MAX; i++)
        if (g_leg[i].used && g_leg[i].cic == cic)
            return &g_leg[i];
    return NULL;
}

static isup_leg_t *leg_new(uint32_t sip_id, uint16_t cic)
{
    for (int i = 0; i < ISUP_CALL_MAX; i++) {
        if (g_leg[i].used) continue;
        memset(&g_leg[i], 0, sizeof(g_leg[i]));
        g_leg[i].used = 1;
        g_leg[i].sip_id = sip_id;
        g_leg[i].cic = cic;
        g_leg[i].st = IC_IAM_SENT;
        g_leg[i].t0 = time(NULL);
        return &g_leg[i];
    }
    return NULL;
}

static void leg_free(isup_leg_t *l)
{
    if (!l) return;
    isup_cic_release(l->cic);
    memset(l, 0, sizeof(*l));
}

static uint8_t tx_si(const iwf_config_t *cfg)
{
    if (cfg->bicc_si == IWF_BICC_SI_ISUP) return MTP_SI_ISUP;
    return MTP_SI_BICC;
}

static int tx_msu(struct iwf_runtime *rt, const uint8_t *msu, size_t len)
{
    if (!rt || !msu || !len) return -1;
    return ss7_link_send_mtp(rt, tx_si(&rt->cfg),
                             rt->cfg.bicc_opc, rt->cfg.bicc_dpc,
                             msu, len);
}

static void log_msg(const char *dir, uint32_t sip_id, uint16_t cic,
                    uint8_t type, uint32_t opc, uint32_t dpc, uint8_t cause)
{
    if (cause)
        LOGI("isup", "%s %s cic=%u id=%u opc=0x%x dpc=0x%x cause=%u",
             dir, isup_msg_name(type), (unsigned)cic, sip_id,
             (unsigned)opc, (unsigned)dpc, (unsigned)cause);
    else
        LOGI("isup", "%s %s cic=%u id=%u opc=0x%x dpc=0x%x",
             dir, isup_msg_name(type), (unsigned)cic, sip_id,
             (unsigned)opc, (unsigned)dpc);
}

int isup_call_init(struct iwf_runtime *rt)
{
    memset(g_leg, 0, sizeof(g_leg));
    g_rt = rt;
    return isup_cic_init(rt);
}

void isup_call_shutdown(void)
{
    isup_cic_shutdown();
    memset(g_leg, 0, sizeof(g_leg));
    g_rt = NULL;
}

int isup_call_reconfigure(struct iwf_runtime *rt)
{
    g_rt = rt;
    return isup_cic_reconfigure(rt);
}

int isup_call_south_is_bicc(const struct iwf_runtime *rt, const char *digits)
{
    if (!rt) return 0;
    const iwf_cs_route_t *r = iwf_cs_route_lookup(&rt->cfg, digits);
    if (r)
        return r->south == IWF_CS_SOUTH_BICC;
    return rt->cfg.roam_cs_route_mode == IWF_ROAM_CS_ROUTE_ISUP;
}

int isup_call_originate(struct iwf_runtime *rt, uint32_t sip_id,
                         const char *called, const char *calling,
                         int pres_restricted)
{
    if (!rt) return -1;
    if (!rt->cfg.bicc_dpc[0]) {
        LOGW("isup", "id=%u [bicc] dpc unset; cannot send IAM", sip_id);
        return -1;
    }
    int cic = isup_cic_alloc(sip_id);
    if (cic < 0) {
        LOGW("isup", "id=%u no CIC (cause 34)", sip_id);
        return -1;
    }
    isup_leg_t *l = leg_new(sip_id, (uint16_t)cic);
    if (!l) {
        isup_cic_release((uint16_t)cic);
        return -1;
    }

    isup_number_t cd, cg;
    isup_number_from_digits(&cd, called, ISUP_NAI_INTERNATIONAL, 0);
    isup_number_from_digits(&cg, calling, ISUP_NAI_INTERNATIONAL,
                            pres_restricted);

    char rtp_ip[64] = "";
    uint16_t rtp_port = 0;
    (void)isup_cic_rtp((uint16_t)cic, rtp_ip, sizeof(rtp_ip), &rtp_port);
    if (!rtp_ip[0] && rt->cfg.bicc_rtp_ip[0]) {
        snprintf(rtp_ip, sizeof(rtp_ip), "%s", rt->cfg.bicc_rtp_ip);
        rtp_port = rt->cfg.bicc_rtp_port_base;
    }

    uint8_t msu[ISUP_MSU_MAX];
    int n = isup_enc_iam(msu, sizeof(msu), (uint16_t)cic, &cd, &cg,
                         rtp_ip, rtp_port);
    if (n < 0) {
        LOGW("isup", "id=%u cic=%d IAM encode failed", sip_id, cic);
        leg_free(l);
        return -1;
    }
    if (tx_msu(rt, msu, (size_t)n) < 0) {
        LOGW("isup", "id=%u cic=%d IAM send failed", sip_id, cic);
        leg_free(l);
        return -1;
    }
    log_msg("TX", sip_id, (uint16_t)cic, ISUP_MT_IAM, 0, 0, 0);
    if (!rtp_ip[0])
        LOGW("isup", "id=%u cic=%d IAM without RTP map "
             "([bicc] cic_map / rtp_ip unset)", sip_id, cic);
    return 0;
}

void isup_call_release(uint32_t sip_id, uint8_t cause)
{
    isup_leg_t *l = leg_by_sip(sip_id);
    if (!l || !g_rt) return;
    if (l->rel_sent) return;
    uint8_t msu[32];
    int n = isup_enc_rel(msu, sizeof(msu), l->cic, cause ? cause : 16);
    if (n > 0) {
        tx_msu(g_rt, msu, (size_t)n);
        log_msg("TX", sip_id, l->cic, ISUP_MT_REL, 0, 0, cause);
    }
    l->rel_sent = 1;
    l->st = IC_WAIT_RLC;
    isup_cic_set_state(l->cic, CIC_WAIT_RLC);
}

void isup_call_detach(uint32_t sip_id)
{
    isup_leg_t *l = leg_by_sip(sip_id);
    if (l) leg_free(l);
}

static int reply_empty(struct iwf_runtime *rt, uint16_t cic, uint8_t type)
{
    uint8_t msu[8];
    int n = isup_enc_empty(msu, sizeof(msu), cic, type);
    if (n < 0) return -1;
    return tx_msu(rt, msu, (size_t)n);
}

static void on_acm(isup_leg_t *l)
{
    l->st = IC_EARLY;
    isup_cic_set_state(l->cic, CIC_OUTGOING);
    sip_iwf_on_isup_acm(l->sip_id);
}

static void on_anm(isup_leg_t *l)
{
    l->st = IC_CONNECTED;
    isup_cic_set_state(l->cic, CIC_CONNECTED);
    sip_iwf_on_isup_anm(l->sip_id);
}

static void on_rel_far(struct iwf_runtime *rt, isup_leg_t *l, uint8_t cause)
{
    uint8_t msu[8];
    int n = isup_enc_rlc(msu, sizeof(msu), l->cic);
    if (n > 0) tx_msu(rt, msu, (size_t)n);
    log_msg("TX", l->sip_id, l->cic, ISUP_MT_RLC, 0, 0, 0);
    int sip = isup_cause_to_sip(cause);
    uint32_t sid = l->sip_id;
    if (cause == 16 && l->st == IC_CONNECTED)
        sip = 200;
    leg_free(l);
    sip_iwf_on_isup_rel(sid, sip);
}

void isup_call_rx(struct iwf_runtime *rt, uint32_t opc, uint32_t dpc,
                   uint8_t si, const uint8_t *msu, size_t len)
{
    isup_msg_t m;
    if (isup_decode(msu, len, &m) < 0) {
        LOGW("isup", "RX decode fail len=%zu si=%u opc=0x%x",
             len, (unsigned)si, (unsigned)opc);
        return;
    }
    isup_leg_t *l = leg_by_cic(m.cic);
    uint32_t sid = l ? l->sip_id : isup_cic_sip_id(m.cic);
    log_msg("RX", sid, m.cic, m.type, opc, dpc,
            m.have_cause ? m.cause : 0);
    (void)dpc;

    switch (m.type) {
    case ISUP_MT_ACM:
    case ISUP_MT_CPG:
        if (l) on_acm(l);
        break;
    case ISUP_MT_ANM:
        if (l) on_anm(l);
        break;
    case ISUP_MT_REL:
        if (l)
            on_rel_far(rt, l, m.have_cause ? m.cause : 31);
        else {
            uint8_t rlc[8];
            int n = isup_enc_rlc(rlc, sizeof(rlc), m.cic);
            if (n > 0) tx_msu(rt, rlc, (size_t)n);
            isup_cic_reset(m.cic);
        }
        break;
    case ISUP_MT_RLC:
        if (l) {
            uint32_t id = l->sip_id;
            int wait = (l->st == IC_WAIT_RLC);
            leg_free(l);
            if (!wait)
                sip_iwf_on_isup_rel(id, 200);
        } else {
            isup_cic_reset(m.cic);
        }
        break;
    case ISUP_MT_BLO:
        isup_cic_block_remote(m.cic);
        reply_empty(rt, m.cic, ISUP_MT_BLA);
        log_msg("TX", 0, m.cic, ISUP_MT_BLA, 0, 0, 0);
        break;
    case ISUP_MT_UBL:
        isup_cic_unblock_remote(m.cic);
        reply_empty(rt, m.cic, ISUP_MT_UBA);
        log_msg("TX", 0, m.cic, ISUP_MT_UBA, 0, 0, 0);
        break;
    case ISUP_MT_BLA:
        isup_cic_block_local(m.cic);
        break;
    case ISUP_MT_UBA:
        isup_cic_unblock_local(m.cic);
        break;
    case ISUP_MT_RSC:
        if (l) {
            uint32_t id = l->sip_id;
            leg_free(l);
            sip_iwf_on_isup_rel(id, 503);
        }
        isup_cic_reset(m.cic);
        reply_empty(rt, m.cic, ISUP_MT_RLC);
        log_msg("TX", 0, m.cic, ISUP_MT_RLC, 0, 0, 0);
        break;
    case ISUP_MT_GRS: {
        uint8_t range = m.have_range ? m.range : 0;
        isup_cic_reset_range(m.cic, range);
        uint8_t gra[16];
        int n = isup_enc_gra(gra, sizeof(gra), m.cic, range);
        if (n > 0) tx_msu(rt, gra, (size_t)n);
        log_msg("TX", 0, m.cic, ISUP_MT_GRA, 0, 0, 0);
        break;
    }
    case ISUP_MT_CGB:
        isup_cic_block_remote(m.cic);
        reply_empty(rt, m.cic, ISUP_MT_CGBA);
        log_msg("TX", 0, m.cic, ISUP_MT_CGBA, 0, 0, 0);
        break;
    case ISUP_MT_CGU:
        isup_cic_unblock_remote(m.cic);
        reply_empty(rt, m.cic, ISUP_MT_CGUA);
        log_msg("TX", 0, m.cic, ISUP_MT_CGUA, 0, 0, 0);
        break;
    case ISUP_MT_IAM: {
        /* Dual seizure / unexpected incoming. GMSC originates only. */
        if (l && isup_cic_is_ours(m.cic)) {
            LOGW("isup", "dual seizure cic=%u — we are controlling, ignore IAM",
                 (unsigned)m.cic);
            break;
        }
        if (l) {
            LOGW("isup", "dual seizure cic=%u — yield, fail id=%u",
                 (unsigned)m.cic, l->sip_id);
            uint32_t id = l->sip_id;
            isup_call_release(id, 31);
            sip_iwf_on_isup_rel(id, 503);
        }
        uint8_t rel[32];
        int n = isup_enc_rel(rel, sizeof(rel), m.cic, 63);
        if (n > 0) {
            tx_msu(rt, rel, (size_t)n);
            log_msg("TX", 0, m.cic, ISUP_MT_REL, 0, 0, 63);
        }
        break;
    }
    case ISUP_MT_APM:
        if (m.have_ipbcp)
            LOGI("isup", "RX APM cic=%u rtp=%s:%u",
                 (unsigned)m.cic, m.ipbcp_ip, (unsigned)m.ipbcp_port);
        break;
    default:
        break;
    }
}

void isup_call_on_timer(struct iwf_runtime *rt)
{
    if (!rt) return;
    time_t now = time(NULL);
    int tmo = (rt->cfg.sip_invite_timeout_ms + 999) / 1000;
    if (tmo < 1) tmo = 8;
    for (int i = 0; i < ISUP_CALL_MAX; i++) {
        isup_leg_t *l = &g_leg[i];
        if (!l->used) continue;
        if (l->st == IC_WAIT_RLC && now - l->t0 >= 5) {
            LOGW("isup", "cic=%u id=%u RLC timeout — idle CIC",
                 (unsigned)l->cic, l->sip_id);
            leg_free(l);
            continue;
        }
        if (l->st == IC_IAM_SENT && now - l->t0 >= tmo) {
            LOGW("isup", "cic=%u id=%u IAM timeout — one REL, fail north",
                 (unsigned)l->cic, l->sip_id);
            uint32_t id = l->sip_id;
            isup_call_release(id, 18);
            sip_iwf_on_isup_rel(id, 480);
        }
    }
}
