/*
 * imsi_trace.c - runtime IMSI trace filters and PACKET logging.
 */

#include "imsi_trace.h"
#include "logging.h"

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
    const uint8_t *data;
    size_t         len;
    char           proto[32];
} g_rx_bind;

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

void iwf_imsi_trace_init(void)
{
    filter_lock();
    g_filter.count = 0;
    memset(g_filter.imsi, 0, sizeof(g_filter.imsi));
    filter_unlock();
    g_rx_bind.data = NULL;
    g_rx_bind.len = 0;
    g_rx_bind.proto[0] = '\0';
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
    g_rx_bind.data = NULL;
    g_rx_bind.len = 0;
    g_rx_bind.proto[0] = '\0';

    if (g_filter.count == 0)
        return;
    if (!data || !len)
        return;

    g_rx_bind.data = (const uint8_t *)data;
    g_rx_bind.len = len;
    if (proto && proto[0])
        snprintf(g_rx_bind.proto, sizeof(g_rx_bind.proto), "%s", proto);
    else
        snprintf(g_rx_bind.proto, sizeof(g_rx_bind.proto), "-");
}

void iwf_imsi_trace_flush_rx(const char *imsi)
{
    if (!g_rx_bind.data || !g_rx_bind.len)
        return;
    iwf_imsi_trace_packet(imsi, g_rx_bind.proto, "rx",
                          g_rx_bind.data, g_rx_bind.len);
    g_rx_bind.data = NULL;
    g_rx_bind.len = 0;
    g_rx_bind.proto[0] = '\0';
}
