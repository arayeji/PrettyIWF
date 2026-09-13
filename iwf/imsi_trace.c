/*
 * imsi_trace.c - runtime IMSI trace filters and PACKET logging.
 */

#include "imsi_trace.h"
#include "logging.h"
#ifdef GSUP_PROXY_ENABLED
#include "gsup_map_proxy.h"
#endif

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

static struct {
    pthread_mutex_t lock;
    int               initialized;
    int               count;
    char              imsi[IWF_IMSI_TRACE_MAX_FILTERS][IWF_IMSI_TRACE_LEN];
    bool              exact[IWF_IMSI_TRACE_MAX_FILTERS];
} g_filter;

static struct {
    uint8_t data[IWF_IMSI_TRACE_PACKET_MAX];
    size_t  dump_len;
    size_t  orig_len;
    char    proto[32];
    int     used;
} g_rx_bind;

#define TRACE_KIND_TCAP  1
#define TRACE_KIND_HBH   2
#define TRACE_CORR_MAX   256
#define TRACE_CORR_TTL   120
#define TRACE_HOLD_MAX   32

typedef struct {
    uint8_t kind;
    uint32_t id;
    char    imsi[IWF_IMSI_TRACE_LEN];
    time_t  ts;
} trace_corr_t;

typedef struct {
    int     used;
    uint32_t tid;
    char    proto[32];
    char    dir[8];
    uint8_t pdu[IWF_IMSI_TRACE_PACKET_MAX];
    uint16_t dump_len;
    uint16_t orig_len;
    time_t  ts;
} trace_hold_t;

static trace_corr_t g_corr[TRACE_CORR_MAX];
static trace_hold_t g_hold[TRACE_HOLD_MAX];

static uint32_t g_pkt_sec;
static uint32_t g_pkt_count;

static void filter_lock(void)
{
    if (!g_filter.initialized) {
        pthread_mutex_init(&g_filter.lock, NULL);
        g_filter.initialized = 1;
    }
    pthread_mutex_lock(&g_filter.lock);
}

static void filter_unlock(void)
{
    pthread_mutex_unlock(&g_filter.lock);
}

static bool digits_only(const char *s)
{
    if (!s || !s[0]) return false;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return false;
    }
    return true;
}

static bool trace_b64_encode(char *out, size_t out_cap,
                             const uint8_t *in, size_t in_len)
{
    static const char tab[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    size_t i;

    if (!out || out_cap < 4 || !in)
        return false;

    for (i = 0; i + 2 < in_len && o + 4 < out_cap; i += 3) {
        out[o++] = tab[(in[i] >> 2) & 0x3F];
        out[o++] = tab[((in[i] & 0x3) << 4) | ((in[i + 1] & 0xF0) >> 4)];
        out[o++] = tab[((in[i + 1] & 0xF) << 2) | ((in[i + 2] & 0xC0) >> 6)];
        out[o++] = tab[in[i + 2] & 0x3F];
    }
    if (i < in_len && o + 4 < out_cap) {
        out[o++] = tab[(in[i] >> 2) & 0x3F];
        if (i + 1 == in_len) {
            out[o++] = tab[((in[i] & 0x3) << 4)];
            out[o++] = '=';
        } else {
            out[o++] = tab[((in[i] & 0x3) << 4) | ((in[i + 1] & 0xF0) >> 4)];
            out[o++] = tab[((in[i + 1] & 0xF) << 2)];
            out[o++] = '=';
        }
    }
    out[o < out_cap ? o : out_cap - 1] = '\0';
    return o > 0;
}

static size_t admin_append_list(char *body, size_t cap, size_t off)
{
    int i;

    if (off >= cap)
        return off;

    off += (size_t)snprintf(body + off, cap - off, "\"trace_imsi\":[");
    for (i = 0; i < g_filter.count; i++) {
        if (i > 0 && off < cap)
            off += (size_t)snprintf(body + off, cap - off, ",");
        if (off < cap)
            off += (size_t)snprintf(body + off, cap - off, "\"%s\"",
                                    g_filter.imsi[i]);
    }
    if (off < cap)
        off += (size_t)snprintf(body + off, cap - off, "]");
    return off;
}

static size_t admin_fmt(char *body, size_t cap, bool ok, const char *detail)
{
    size_t off = 0;

    if (!body || cap == 0)
        return 0;

    off += (size_t)snprintf(body + off, cap - off,
                            "{\"ok\":%s,\"detail\":\"%s\",",
                            ok ? "true" : "false",
                            detail ? detail : "");
    off = admin_append_list(body, cap, off);
    if (off < cap)
        off += (size_t)snprintf(body + off, cap - off, "}\n");
    return off;
}

static void corr_expire(time_t now)
{
    int i;

    for (i = 0; i < TRACE_CORR_MAX; i++) {
        if (!g_corr[i].kind)
            continue;
        if (now - g_corr[i].ts > TRACE_CORR_TTL)
            g_corr[i].kind = 0;
    }
}

static void hold_expire(time_t now)
{
    int i;

    for (i = 0; i < TRACE_HOLD_MAX; i++) {
        if (!g_hold[i].used)
            continue;
        if (now - g_hold[i].ts > TRACE_CORR_TTL)
            g_hold[i].used = 0;
    }
}

static void corr_put(uint8_t kind, uint32_t id, const char *imsi)
{
    time_t now;
    int i, free_i = -1, oldest = 0;

    if (!id || !imsi || !imsi[0] || g_filter.count == 0)
        return;
    if (!iwf_imsi_trace_match(imsi))
        return;

    now = time(NULL);
    corr_expire(now);
    for (i = 0; i < TRACE_CORR_MAX; i++) {
        if (g_corr[i].kind == kind && g_corr[i].id == id) {
            snprintf(g_corr[i].imsi, sizeof(g_corr[i].imsi), "%s", imsi);
            g_corr[i].ts = now;
            return;
        }
        if (!g_corr[i].kind && free_i < 0)
            free_i = i;
        if (g_corr[i].kind && g_corr[i].ts < g_corr[oldest].ts)
            oldest = i;
    }
    if (free_i < 0)
        free_i = oldest;
    g_corr[free_i].kind = kind;
    g_corr[free_i].id = id;
    snprintf(g_corr[free_i].imsi, sizeof(g_corr[free_i].imsi), "%s", imsi);
    g_corr[free_i].ts = now;
}

static int corr_get(uint8_t kind, uint32_t id, char *imsi_out, size_t cap)
{
    int i;

    if (!id || !imsi_out || cap == 0)
        return -1;
    imsi_out[0] = '\0';
    corr_expire(time(NULL));
    for (i = 0; i < TRACE_CORR_MAX; i++) {
        if (g_corr[i].kind == kind && g_corr[i].id == id && g_corr[i].imsi[0]) {
            snprintf(imsi_out, cap, "%s", g_corr[i].imsi);
            return 0;
        }
    }
    return -1;
}

static void hold_put(uint32_t tid, const char *proto, const char *dir,
                      const void *data, size_t len)
{
    time_t now;
    int i, free_i = -1, oldest = 0;
    size_t dump_len;

    if (!tid || !data || !len || g_filter.count == 0)
        return;

    now = time(NULL);
    hold_expire(now);
    dump_len = len > IWF_IMSI_TRACE_PACKET_MAX ? IWF_IMSI_TRACE_PACKET_MAX : len;

    for (i = 0; i < TRACE_HOLD_MAX; i++) {
        if (g_hold[i].used && g_hold[i].tid == tid &&
            dir && strcmp(g_hold[i].dir, dir) == 0) {
            memcpy(g_hold[i].pdu, data, dump_len);
            g_hold[i].dump_len = (uint16_t)dump_len;
            g_hold[i].orig_len = (uint16_t)(len > 65535 ? 65535 : len);
            g_hold[i].ts = now;
            if (proto && proto[0])
                snprintf(g_hold[i].proto, sizeof(g_hold[i].proto), "%s", proto);
            return;
        }
        if (!g_hold[i].used && free_i < 0)
            free_i = i;
        if (g_hold[i].used && g_hold[i].ts < g_hold[oldest].ts)
            oldest = i;
    }
    if (free_i < 0)
        free_i = oldest;
    memset(&g_hold[free_i], 0, sizeof(g_hold[free_i]));
    g_hold[free_i].used = 1;
    g_hold[free_i].tid = tid;
    g_hold[free_i].dump_len = (uint16_t)dump_len;
    g_hold[free_i].orig_len = (uint16_t)(len > 65535 ? 65535 : len);
    g_hold[free_i].ts = now;
    memcpy(g_hold[free_i].pdu, data, dump_len);
    snprintf(g_hold[free_i].proto, sizeof(g_hold[free_i].proto), "%s",
             proto && proto[0] ? proto : "-");
    snprintf(g_hold[free_i].dir, sizeof(g_hold[free_i].dir), "%s",
             dir && dir[0] ? dir : "-");
}

static void bind_clear(void)
{
    g_rx_bind.used = 0;
    g_rx_bind.dump_len = 0;
    g_rx_bind.orig_len = 0;
    g_rx_bind.proto[0] = '\0';
}

void iwf_imsi_trace_init(void)
{
    filter_lock();
    g_filter.count = 0;
    memset(g_filter.imsi, 0, sizeof(g_filter.imsi));
    filter_unlock();
    bind_clear();
    memset(g_corr, 0, sizeof(g_corr));
    memset(g_hold, 0, sizeof(g_hold));
}

void iwf_imsi_trace_shutdown(void)
{
    iwf_imsi_trace_clear();
}

void iwf_imsi_trace_clear(void)
{
    filter_lock();
    g_filter.count = 0;
    memset(g_filter.imsi, 0, sizeof(g_filter.imsi));
    filter_unlock();
}

int iwf_imsi_trace_add(const char *imsi, bool exact)
{
    int i;

    if (!imsi || !imsi[0] || !digits_only(imsi))
        return -1;

    filter_lock();
    for (i = 0; i < g_filter.count; i++) {
        if (strcmp(g_filter.imsi[i], imsi) == 0) {
            g_filter.exact[i] = exact;
            filter_unlock();
            return 0;
        }
    }
    if (g_filter.count >= IWF_IMSI_TRACE_MAX_FILTERS) {
        filter_unlock();
        return -1;
    }
    snprintf(g_filter.imsi[g_filter.count], IWF_IMSI_TRACE_LEN, "%s", imsi);
    g_filter.exact[g_filter.count] = exact;
    g_filter.count++;
    filter_unlock();
    return 0;
}

int iwf_imsi_trace_replace(const char *imsi, bool exact)
{
    iwf_imsi_trace_clear();
    return iwf_imsi_trace_add(imsi, exact);
}

int iwf_imsi_trace_remove(const char *imsi)
{
    int i, j;

    if (!imsi || !imsi[0])
        return -1;

    filter_lock();
    for (i = 0; i < g_filter.count; i++) {
        if (strcmp(g_filter.imsi[i], imsi) != 0)
            continue;
        for (j = i + 1; j < g_filter.count; j++) {
            snprintf(g_filter.imsi[j - 1], IWF_IMSI_TRACE_LEN, "%s",
                     g_filter.imsi[j]);
            g_filter.exact[j - 1] = g_filter.exact[j];
        }
        g_filter.count--;
        g_filter.imsi[g_filter.count][0] = '\0';
        filter_unlock();
        return 0;
    }
    filter_unlock();
    return -1;
}

bool iwf_imsi_trace_match(const char *imsi)
{
    int i;
    bool matched = false;

    if (!imsi || !imsi[0])
        return false;

    if (g_filter.count == 0)
        return false;

    filter_lock();
    for (i = 0; i < g_filter.count; i++) {
        size_t n = strlen(g_filter.imsi[i]);
        if (n == 0)
            continue;
        if (g_filter.exact[i]) {
            if (strcmp(imsi, g_filter.imsi[i]) == 0) {
                matched = true;
                break;
            }
        } else if (strncmp(imsi, g_filter.imsi[i], n) == 0) {
            matched = true;
            break;
        }
    }
    filter_unlock();
    return matched;
}

int iwf_imsi_trace_count(void)
{
    int n;
    filter_lock();
    n = g_filter.count;
    filter_unlock();
    return n;
}

int iwf_imsi_trace_get(int index, char *buf, size_t buflen, bool *exact_out)
{
    if (!buf || buflen == 0)
        return -1;
    filter_lock();
    if (index < 0 || index >= g_filter.count) {
        filter_unlock();
        return -1;
    }
    snprintf(buf, buflen, "%s", g_filter.imsi[index]);
    if (exact_out)
        *exact_out = g_filter.exact[index];
    filter_unlock();
    return 0;
}

void iwf_imsi_trace_load_config(const char *csv)
{
    char *dup, *save, *tok;

    if (!csv || !csv[0])
        return;

    dup = strdup(csv);
    if (!dup)
        return;

    for (tok = strtok_r(dup, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        while (*tok == ' ' || *tok == '\t') tok++;
        if (*tok)
            iwf_imsi_trace_add(tok, false);
    }
    free(dup);
}

static bool match_exact_q(const iwf_imsi_trace_query_t *q)
{
    return q && q->match && strcasecmp(q->match, "exact") == 0;
}

int iwf_imsi_trace_admin(const iwf_imsi_trace_query_t *q,
                         char *body, size_t body_cap, size_t *body_len)
{
    const char *imsi = (q && q->imsi) ? q->imsi : NULL;
    bool exact = match_exact_q(q);
    char detail[256];
    int rv;

    if (!body || body_cap == 0 || !body_len)
        return 400;

    if (q && q->force) {
        iwf_imsi_trace_clear();
        *body_len = admin_fmt(body, body_cap, true,
                              "trace_imsi filters cleared");
        return 200;
    }

    if (imsi && strcmp(imsi, "list") == 0) {
        snprintf(detail, sizeof(detail), "listed %d prefix(es)",
                 iwf_imsi_trace_count());
        *body_len = admin_fmt(body, body_cap, true, detail);
        return 200;
    }

    if (!imsi || !imsi[0]) {
        snprintf(detail, sizeof(detail), "listed %d prefix(es)",
                 iwf_imsi_trace_count());
        *body_len = admin_fmt(body, body_cap, true, detail);
        return 200;
    }

    if (q->remove) {
        rv = iwf_imsi_trace_remove(imsi);
        if (rv != 0) {
            *body_len = admin_fmt(body, body_cap, false,
                                  "trace_imsi prefix not found");
            return 400;
        }
        snprintf(detail, sizeof(detail),
                 "trace_imsi removed %s (count=%d)", imsi,
                 iwf_imsi_trace_count());
        *body_len = admin_fmt(body, body_cap, true, detail);
        return 200;
    }

    if (q->replace) {
        rv = iwf_imsi_trace_replace(imsi, exact);
        if (rv != 0) {
            *body_len = admin_fmt(body, body_cap, false,
                                  "trace_imsi replace failed");
            return 500;
        }
        snprintf(detail, sizeof(detail),
                 "trace_imsi replaced with %s%s (count=%d)", imsi,
                 exact ? " [exact]" : "", iwf_imsi_trace_count());
        *body_len = admin_fmt(body, body_cap, true, detail);
        return 200;
    }

    rv = iwf_imsi_trace_add(imsi, exact);
    if (rv != 0) {
        *body_len = admin_fmt(body, body_cap, false, "trace_imsi list full");
        return 500;
    }
    snprintf(detail, sizeof(detail),
             "trace_imsi added %s%s (count=%d)", imsi,
             exact ? " [exact]" : "", iwf_imsi_trace_count());
    *body_len = admin_fmt(body, body_cap, true, detail);
    return 200;
}

void iwf_imsi_trace_packet(const char *imsi, const char *proto, const char *dir,
                           const void *data, size_t len)
{
    char b64[((IWF_IMSI_TRACE_PACKET_MAX + 2) / 3) * 4 + 1];
    size_t dump_len;
    int truncated = 0;
    uint32_t now_sec;

    if (g_filter.count == 0)
        return;
    if (!imsi || !imsi[0] || !data || !len)
        return;
    if (!iwf_imsi_trace_match(imsi))
        return;

    now_sec = (uint32_t)time(NULL);
    if (now_sec != g_pkt_sec) {
        g_pkt_sec = now_sec;
        g_pkt_count = 0;
    }
    g_pkt_count++;
    if (g_pkt_count > IWF_IMSI_TRACE_PACKET_PER_S)
        return;

    dump_len = len;
    if (dump_len > IWF_IMSI_TRACE_PACKET_MAX) {
        dump_len = IWF_IMSI_TRACE_PACKET_MAX;
        truncated = 1;
    }
    if (!trace_b64_encode(b64, sizeof(b64), (const uint8_t *)data, dump_len))
        return;

    iwf_log_imsi(IWF_LOG_INFO, imsi, "trace",
                 "PACKET: proto=%s dir=%s len=%zu%s b64=%s",
                 proto && proto[0] ? proto : "-",
                 dir && dir[0] ? dir : "-",
                 len,
                 truncated ? " trunc=1" : "",
                 b64);
}

void iwf_imsi_trace_bind_rx(const char *proto, const void *data, size_t len)
{
    bind_clear();

    if (g_filter.count == 0)
        return;
    if (!data || !len)
        return;

    g_rx_bind.orig_len = len;
    g_rx_bind.dump_len = len > IWF_IMSI_TRACE_PACKET_MAX
                         ? IWF_IMSI_TRACE_PACKET_MAX : len;
    memcpy(g_rx_bind.data, data, g_rx_bind.dump_len);
    g_rx_bind.used = 1;
    if (proto && proto[0])
        snprintf(g_rx_bind.proto, sizeof(g_rx_bind.proto), "%s", proto);
    else
        snprintf(g_rx_bind.proto, sizeof(g_rx_bind.proto), "-");
}

void iwf_imsi_trace_flush_rx(const char *imsi)
{
    if (!g_rx_bind.used || !g_rx_bind.dump_len)
        return;
    iwf_imsi_trace_packet(imsi, g_rx_bind.proto, "rx",
                          g_rx_bind.data, g_rx_bind.orig_len);
    bind_clear();
}

void iwf_imsi_trace_drop_rx(void)
{
    bind_clear();
}

void iwf_imsi_trace_remember_tcap(uint32_t tid, const char *imsi)
{
    corr_put(TRACE_KIND_TCAP, tid, imsi);
}

void iwf_imsi_trace_remember_diam_hbh(uint32_t hbh, const char *imsi)
{
    corr_put(TRACE_KIND_HBH, hbh, imsi);
}

int iwf_imsi_trace_imsi_for_tcap(uint32_t tid, char *imsi_out, size_t cap)
{
    return corr_get(TRACE_KIND_TCAP, tid, imsi_out, cap);
}

int iwf_imsi_trace_imsi_for_diam_hbh(uint32_t hbh, char *imsi_out, size_t cap)
{
    return corr_get(TRACE_KIND_HBH, hbh, imsi_out, cap);
}

void iwf_imsi_trace_park_rx(uint32_t tid)
{
    if (!g_rx_bind.used || !g_rx_bind.dump_len)
        return;
    hold_put(tid, g_rx_bind.proto, "rx", g_rx_bind.data, g_rx_bind.orig_len);
    bind_clear();
}

void iwf_imsi_trace_park_pdu(uint32_t tid, const char *proto, const char *dir,
                             const void *data, size_t len)
{
    hold_put(tid, proto, dir, data, len);
}

void iwf_imsi_trace_flush_parked(uint32_t tid, const char *imsi)
{
    int i;

    if (!tid || !imsi || !imsi[0])
        return;
    hold_expire(time(NULL));
    for (i = 0; i < TRACE_HOLD_MAX; i++) {
        if (!g_hold[i].used || g_hold[i].tid != tid)
            continue;
        iwf_imsi_trace_packet(imsi, g_hold[i].proto, g_hold[i].dir,
                              g_hold[i].pdu, g_hold[i].orig_len);
        g_hold[i].used = 0;
    }
    iwf_imsi_trace_remember_tcap(tid, imsi);
}

void iwf_imsi_trace_finish_rx(uint32_t dtid, bool have_dtid,
                               uint32_t otid, bool have_otid,
                               const char *imsi)
{
    char buf[IWF_IMSI_TRACE_LEN];
    const char *use = imsi;

    buf[0] = '\0';
    if ((!use || !use[0]) && have_dtid &&
        iwf_imsi_trace_imsi_for_tcap(dtid, buf, sizeof(buf)) == 0)
        use = buf;
    if ((!use || !use[0]) && have_otid &&
        iwf_imsi_trace_imsi_for_tcap(otid, buf, sizeof(buf)) == 0)
        use = buf;

    if (use && use[0]) {
        iwf_imsi_trace_flush_rx(use);
        if (have_dtid)
            iwf_imsi_trace_flush_parked(dtid, use);
        if (have_otid)
            iwf_imsi_trace_flush_parked(otid, use);
        iwf_imsi_trace_drop_rx();
        return;
    }

    if (have_dtid)
        iwf_imsi_trace_park_rx(dtid);
    else if (have_otid)
        iwf_imsi_trace_park_rx(otid);
    else
        iwf_imsi_trace_drop_rx();
}

int iwf_imsi_trace_imsi_for_msisdn(const char *msisdn,
                                    char *imsi_out, size_t cap)
{
    if (!imsi_out || cap == 0)
        return -1;
    imsi_out[0] = '\0';
#ifdef GSUP_PROXY_ENABLED
    if (gsup_map_proxy_imsi_for_msisdn(msisdn, imsi_out, cap) == 0 &&
        imsi_out[0])
        return 0;
#else
    (void)msisdn;
#endif
    return -1;
}

void iwf_imsi_trace_packet_msisdn(const char *msisdn, const char *proto,
                                  const char *dir, const void *data, size_t len)
{
    char imsi[IWF_IMSI_TRACE_LEN];

    if (iwf_imsi_trace_imsi_for_msisdn(msisdn, imsi, sizeof(imsi)) != 0)
        return;
    iwf_imsi_trace_packet(imsi, proto, dir, data, len);
}
