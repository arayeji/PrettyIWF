/*
 * isup_cic.c — CIC pool and circuit state.
 */

#include "isup_cic.h"
#include "config.h"
#include "runtime.h"
#include "logging.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    uint16_t          cic;
    isup_cic_state_t  st;
    uint32_t          sip_id;
    char              rtp_ip[64];
    uint16_t          rtp_port;
    int               in_use_slot;
} cic_slot_t;

static cic_slot_t g_cic[IWF_CIC_MAX];
static int        g_n;
static uint16_t   g_first;
static uint16_t   g_last;
static int        g_even; /* 1 = originate even, 0 = odd */
static int        g_rr;

static cic_slot_t *find_cic(uint16_t cic)
{
    for (int i = 0; i < g_n; i++) {
        if (g_cic[i].in_use_slot && g_cic[i].cic == cic)
            return &g_cic[i];
    }
    return NULL;
}

static int parse_range(const char *s, uint16_t *lo, uint16_t *hi)
{
    if (!s || !s[0]) return -1;
    unsigned a = 0, b = 0;
    const char *p = s;
    while (*p >= '0' && *p <= '9')
        a = a * 10u + (unsigned)(*p++ - '0');
    if (*p == '-' || *p == ':') {
        p++;
        while (*p >= '0' && *p <= '9')
            b = b * 10u + (unsigned)(*p++ - '0');
    } else {
        b = a;
    }
    if (*p != '\0' || a == 0 || b == 0 || a > 4095 || b > 4095 || a > b)
        return -1;
    *lo = (uint16_t)a;
    *hi = (uint16_t)b;
    return 0;
}

static void apply_map(const iwf_config_t *cfg)
{
    for (int i = 0; i < cfg->bicc_n_cic_map; i++) {
        cic_slot_t *s = find_cic(cfg->bicc_cic_map[i].cic);
        if (!s) continue;
        snprintf(s->rtp_ip, sizeof(s->rtp_ip), "%s",
                 cfg->bicc_cic_map[i].ip);
        s->rtp_port = cfg->bicc_cic_map[i].port;
    }
    if (cfg->bicc_rtp_ip[0] && cfg->bicc_rtp_port_base) {
        uint16_t port = cfg->bicc_rtp_port_base;
        for (int i = 0; i < g_n; i++) {
            if (g_cic[i].rtp_ip[0]) continue;
            snprintf(g_cic[i].rtp_ip, sizeof(g_cic[i].rtp_ip), "%s",
                     cfg->bicc_rtp_ip);
            g_cic[i].rtp_port = port;
            if (port < 65534) port = (uint16_t)(port + 2);
        }
    }
}

int isup_cic_init(struct iwf_runtime *rt)
{
    memset(g_cic, 0, sizeof(g_cic));
    g_n = 0;
    g_rr = 0;
    g_first = 0;
    g_last = 0;
    if (!rt) return 0;
    const iwf_config_t *cfg = &rt->cfg;
    g_even = (cfg->bicc_cic_selection != IWF_CIC_SEL_ODD);
    if (!cfg->bicc_cic_range[0]) {
        LOGI("isup", "CIC pool empty ([bicc] cic_range unset)");
        return 0;
    }
    uint16_t lo = 0, hi = 0;
    if (parse_range(cfg->bicc_cic_range, &lo, &hi) < 0) {
        LOGW("isup", "[bicc] cic_range=%s invalid (use lo-hi)",
             cfg->bicc_cic_range);
        return -1;
    }
    if ((int)(hi - lo + 1) > IWF_CIC_MAX) {
        LOGW("isup", "cic_range %u-%u exceeds %d; truncating",
             (unsigned)lo, (unsigned)hi, IWF_CIC_MAX);
        hi = (uint16_t)(lo + IWF_CIC_MAX - 1);
    }
    g_first = lo;
    g_last = hi;
    for (uint16_t c = lo; c <= hi && g_n < IWF_CIC_MAX; c++) {
        g_cic[g_n].cic = c;
        g_cic[g_n].st = CIC_IDLE;
        g_cic[g_n].in_use_slot = 1;
        g_n++;
    }
    apply_map(cfg);
    LOGI("isup", "CIC pool %u-%u n=%d selection=%s",
         (unsigned)g_first, (unsigned)g_last, g_n,
         g_even ? "even" : "odd");
    return 0;
}

void isup_cic_shutdown(void)
{
    memset(g_cic, 0, sizeof(g_cic));
    g_n = 0;
}

int isup_cic_reconfigure(struct iwf_runtime *rt)
{
    int busy = 0;
    for (int i = 0; i < g_n; i++) {
        if (g_cic[i].st == CIC_OUTGOING || g_cic[i].st == CIC_INCOMING ||
            g_cic[i].st == CIC_CONNECTED || g_cic[i].st == CIC_WAIT_RLC)
            busy++;
    }
    if (busy) {
        LOGW("isup", "CIC reload skipped (%d busy circuits); restart to apply",
             busy);
        return 0;
    }
    return isup_cic_init(rt);
}

int isup_cic_in_range(uint16_t cic)
{
    return find_cic(cic) != NULL;
}

int isup_cic_is_ours(uint16_t cic)
{
    if (g_even) return (cic & 1) == 0;
    return (cic & 1) == 1;
}

int isup_cic_alloc(uint32_t sip_id)
{
    if (g_n <= 0) return -1;
    for (int k = 0; k < g_n; k++) {
        int i = (g_rr + k) % g_n;
        cic_slot_t *s = &g_cic[i];
        if (!s->in_use_slot) continue;
        if (s->st != CIC_IDLE) continue;
        if (!isup_cic_is_ours(s->cic)) continue;
        s->st = CIC_OUTGOING;
        s->sip_id = sip_id;
        g_rr = (i + 1) % g_n;
        return (int)s->cic;
    }
    LOGW("isup", "no idle CIC (selection=%s)", g_even ? "even" : "odd");
    return -1;
}

void isup_cic_set_state(uint16_t cic, isup_cic_state_t st)
{
    cic_slot_t *s = find_cic(cic);
    if (s) s->st = st;
}

isup_cic_state_t isup_cic_state(uint16_t cic)
{
    cic_slot_t *s = find_cic(cic);
    return s ? s->st : CIC_IDLE;
}

uint32_t isup_cic_sip_id(uint16_t cic)
{
    cic_slot_t *s = find_cic(cic);
    return s ? s->sip_id : 0;
}

void isup_cic_bind(uint16_t cic, uint32_t sip_id)
{
    cic_slot_t *s = find_cic(cic);
    if (s) s->sip_id = sip_id;
}

void isup_cic_release(uint16_t cic)
{
    cic_slot_t *s = find_cic(cic);
    if (!s) return;
    s->sip_id = 0;
    if (s->st == CIC_BLOCKED_LOC || s->st == CIC_BLOCKED_BOTH)
        s->st = CIC_BLOCKED_LOC;
    else if (s->st == CIC_BLOCKED_REM)
        s->st = CIC_BLOCKED_REM;
    else
        s->st = CIC_IDLE;
}

int isup_cic_rtp(uint16_t cic, char *ip, size_t ip_cap, uint16_t *port)
{
    cic_slot_t *s = find_cic(cic);
    if (!s || !s->rtp_ip[0]) return -1;
    if (ip && ip_cap) snprintf(ip, ip_cap, "%s", s->rtp_ip);
    if (port) *port = s->rtp_port;
    return 0;
}

void isup_cic_block_local(uint16_t cic)
{
    cic_slot_t *s = find_cic(cic);
    if (!s) return;
    if (s->st == CIC_BLOCKED_REM || s->st == CIC_BLOCKED_BOTH)
        s->st = CIC_BLOCKED_BOTH;
    else
        s->st = CIC_BLOCKED_LOC;
}

void isup_cic_unblock_local(uint16_t cic)
{
    cic_slot_t *s = find_cic(cic);
    if (!s) return;
    if (s->st == CIC_BLOCKED_BOTH) s->st = CIC_BLOCKED_REM;
    else if (s->st == CIC_BLOCKED_LOC) s->st = CIC_IDLE;
}

void isup_cic_block_remote(uint16_t cic)
{
    cic_slot_t *s = find_cic(cic);
    if (!s) return;
    if (s->st == CIC_BLOCKED_LOC || s->st == CIC_BLOCKED_BOTH)
        s->st = CIC_BLOCKED_BOTH;
    else
        s->st = CIC_BLOCKED_REM;
}

void isup_cic_unblock_remote(uint16_t cic)
{
    cic_slot_t *s = find_cic(cic);
    if (!s) return;
    if (s->st == CIC_BLOCKED_BOTH) s->st = CIC_BLOCKED_LOC;
    else if (s->st == CIC_BLOCKED_REM) s->st = CIC_IDLE;
}

void isup_cic_reset(uint16_t cic)
{
    cic_slot_t *s = find_cic(cic);
    if (!s) return;
    s->sip_id = 0;
    if (s->st == CIC_BLOCKED_LOC || s->st == CIC_BLOCKED_BOTH)
        s->st = CIC_BLOCKED_LOC;
    else
        s->st = CIC_IDLE;
}

void isup_cic_reset_range(uint16_t first, uint8_t range)
{
    uint16_t last = (uint16_t)(first + range);
    for (int i = 0; i < g_n; i++) {
        if (g_cic[i].cic >= first && g_cic[i].cic <= last)
            isup_cic_reset(g_cic[i].cic);
    }
}

uint16_t isup_cic_first(void) { return g_first; }
uint16_t isup_cic_last(void)  { return g_last; }
