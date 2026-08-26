/*
 * msrn_pool.c - MSRN allocation / binding table for MAP ProvideRoamingNumber.
 */

#include "msrn_pool.h"
#include "logging.h"
#include "uthash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

typedef struct {
    char     name[MSRN_POOL_NAME_MAX];
    uint64_t start;
    uint64_t end;
    uint64_t next;          /* next candidate (wraps within [start,end]) */
    size_t   digit_width;   /* fixed width from start string */
} pool_rt_t;

typedef struct binding {
    msrn_binding_t      b;
    bool                in_use;
    UT_hash_handle      hh; /* keyed on b.msrn */
} binding_t;

static pool_rt_t   g_pools[MSRN_MAX_POOLS];
static int         g_n_pools;
static struct {
    char msc_gt[MSRN_DIGITS_MAX];
    char pool_name[MSRN_POOL_NAME_MAX];
} g_msc_map[MSRN_MAX_MSC_MAPS];
static int         g_n_msc_map;
static int         g_ttl_sec = 30;
static int         g_consume = 1;
static binding_t  *g_by_msrn;
static int         g_inited;

/* Minimal local helpers */
static int digits_only(const char *s)
{
    if (!s || !*s) return 0;
    for (; *s; s++) if (!isdigit((unsigned char)*s)) return 0;
    return 1;
}

static int parse_u64(const char *s, uint64_t *out)
{
    if (!digits_only(s)) return -1;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (!end || *end) return -1;
    *out = (uint64_t)v;
    return 0;
}

static void fmt_msrn(uint64_t n, size_t width, char *out, size_t cap)
{
    char tmp[32];
    snprintf(tmp, sizeof(tmp), "%llu", (unsigned long long)n);
    size_t len = strlen(tmp);
    if (width < len) width = len;
    if (width + 1 > cap) width = cap - 1;
    size_t pad = width > len ? width - len : 0;
    memset(out, '0', pad);
    memcpy(out + pad, tmp, len);
    out[pad + len] = '\0';
}

static binding_t *find_binding(const char *msrn)
{
    binding_t *b = NULL;
    if (!msrn || !msrn[0]) return NULL;
    HASH_FIND(hh, g_by_msrn, msrn, strlen(msrn), b);
    return b;
}

static int msrn_in_use(const char *msrn)
{
    binding_t *b = find_binding(msrn);
    return b && b->in_use;
}

static pool_rt_t *pool_by_name(const char *name)
{
    if (!name || !name[0]) return NULL;
    for (int i = 0; i < g_n_pools; i++) {
        if (!strcmp(g_pools[i].name, name))
            return &g_pools[i];
    }
    return NULL;
}

static pool_rt_t *select_pool(const char *msc_number)
{
    if (msc_number && msc_number[0]) {
        for (int i = 0; i < g_n_msc_map; i++) {
            if (!strcmp(g_msc_map[i].msc_gt, msc_number)) {
                pool_rt_t *p = pool_by_name(g_msc_map[i].pool_name);
                if (p) return p;
                LOGW("msrn", "msc_map %s -> pool %s missing",
                     msc_number, g_msc_map[i].pool_name);
                return NULL;
            }
        }
        if (g_n_msc_map > 0) {
            /* Strict: MSC maps configured but this MSC unknown. */
            return NULL;
        }
    }
    if (g_n_pools == 1)
        return &g_pools[0];
    if (g_n_pools > 1 && (!msc_number || !msc_number[0]))
        return &g_pools[0]; /* default first pool */
    return NULL;
}

int msrn_pool_init(const iwf_config_t *cfg)
{
    msrn_pool_shutdown();
    g_inited = 1;
    if (!cfg) return 0;

    g_ttl_sec = cfg->map_msrn_ttl_sec > 0 ? cfg->map_msrn_ttl_sec : 30;
    g_consume = cfg->map_msrn_consume_on_lookup ? 1 : 0;

    for (int i = 0; i < cfg->map_msrn_n_pools && g_n_pools < MSRN_MAX_POOLS; i++) {
        const char *s = cfg->map_msrn_pools[i].start;
        const char *e = cfg->map_msrn_pools[i].end;
        uint64_t vs, ve;
        if (parse_u64(s, &vs) < 0 || parse_u64(e, &ve) < 0 || ve < vs) {
            LOGW("msrn", "bad pool range %s-%s", s, e);
            continue;
        }
        pool_rt_t *p = &g_pools[g_n_pools++];
        memset(p, 0, sizeof(*p));
        snprintf(p->name, sizeof(p->name), "%s",
                 cfg->map_msrn_pools[i].name[0] ? cfg->map_msrn_pools[i].name
                                                 : "default");
        p->start = vs;
        p->end = ve;
        p->next = vs;
        p->digit_width = strlen(s);
        if (strlen(e) > p->digit_width)
            p->digit_width = strlen(e);
        LOGI("msrn", "pool %s range %s-%s width=%zu ttl=%ds",
             p->name, s, e, p->digit_width, g_ttl_sec);
    }

    for (int i = 0; i < cfg->map_msrn_n_msc_map && g_n_msc_map < MSRN_MAX_MSC_MAPS; i++) {
        snprintf(g_msc_map[g_n_msc_map].msc_gt,
                 sizeof(g_msc_map[g_n_msc_map].msc_gt),
                 "%s", cfg->map_msrn_msc_map[i].msc_gt);
        snprintf(g_msc_map[g_n_msc_map].pool_name,
                 sizeof(g_msc_map[g_n_msc_map].pool_name),
                 "%s", cfg->map_msrn_msc_map[i].pool_name);
        g_n_msc_map++;
        LOGI("msrn", "msc_map %s -> %s",
             g_msc_map[g_n_msc_map - 1].msc_gt,
             g_msc_map[g_n_msc_map - 1].pool_name);
    }
    return 0;
}

void msrn_pool_shutdown(void)
{
    binding_t *b, *tmp;
    HASH_ITER(hh, g_by_msrn, b, tmp) {
        HASH_DEL(g_by_msrn, b);
        free(b);
    }
    g_by_msrn = NULL;
    g_n_pools = 0;
    g_n_msc_map = 0;
    g_inited = 0;
    memset(g_pools, 0, sizeof(g_pools));
    memset(g_msc_map, 0, sizeof(g_msc_map));
}

void msrn_pool_set_ttl(int ttl_sec)
{
    if (ttl_sec > 0)
        g_ttl_sec = ttl_sec;
}

bool msrn_pool_configured(void)
{
    return g_inited && g_n_pools > 0;
}

bool msrn_pool_consume_on_lookup(void)
{
    return g_consume != 0;
}

int msrn_pool_alloc(const char *imsi,
                    const char *msisdn,
                    const char *msc_number,
                    uint32_t dialogue_id,
                    msrn_binding_t *out)
{
    if (!out || !imsi || !imsi[0]) return -1;
    if (!msrn_pool_configured()) return -1;

    pool_rt_t *p = select_pool(msc_number);
    if (!p) {
        LOGW("msrn",
             "[%s] alloc: no pool for msc=%s",
             imsi, msc_number && msc_number[0] ? msc_number : "(none)");
        return -1;
    }

    uint64_t span = p->end - p->start + 1;
    for (uint64_t tried = 0; tried < span; tried++) {
        uint64_t n = p->next;
        p->next = (n >= p->end) ? p->start : (n + 1);
        char digits[MSRN_DIGITS_MAX];
        fmt_msrn(n, p->digit_width, digits, sizeof(digits));
        if (msrn_in_use(digits))
            continue;

        binding_t *b = calloc(1, sizeof(*b));
        if (!b) return -1;
        time_t now = time(NULL);
        snprintf(b->b.msrn, sizeof(b->b.msrn), "%s", digits);
        snprintf(b->b.imsi, sizeof(b->b.imsi), "%s", imsi);
        if (msisdn && msisdn[0])
            snprintf(b->b.msisdn, sizeof(b->b.msisdn), "%s", msisdn);
        else
            snprintf(b->b.msisdn, sizeof(b->b.msisdn), "-");
        snprintf(b->b.pool_name, sizeof(b->b.pool_name), "%s", p->name);
        if (msc_number && msc_number[0])
            snprintf(b->b.msc_number, sizeof(b->b.msc_number), "%s", msc_number);
        b->b.dialogue_id = dialogue_id;
        b->b.allocated_at = now;
        b->b.expires_at = now + g_ttl_sec;
        b->in_use = true;
        HASH_ADD_KEYPTR(hh, g_by_msrn, b->b.msrn, strlen(b->b.msrn), b);
        *out = b->b;
        LOGI("msrn",
             "[%s] alloc msrn=%s pool=%s msc=%s tid=0x%08x ttl=%ds",
             imsi, digits, p->name,
             msc_number && msc_number[0] ? msc_number : "-",
             dialogue_id, g_ttl_sec);
        return 0;
    }
    LOGW("msrn", "[%s] pool %s exhausted", imsi, p->name);
    return -1;
}

int msrn_pool_lookup(const char *msrn_digits, bool consume, msrn_binding_t *out)
{
    if (!msrn_digits || !msrn_digits[0] || !out) return -1;
    binding_t *b = find_binding(msrn_digits);
    if (!b || !b->in_use) {
        LOGW("msrn", "lookup %s: not_found", msrn_digits);
        return -1;
    }
    time_t now = time(NULL);
    if (now > b->b.expires_at) {
        LOGW("msrn", "lookup %s: expired imsi=%s", msrn_digits, b->b.imsi);
        HASH_DEL(g_by_msrn, b);
        free(b);
        return -2;
    }
    *out = b->b;
    LOGI("msrn",
         "[%s] lookup msrn=%s msisdn=%s pool=%s consume=%d",
         b->b.imsi, msrn_digits, b->b.msisdn, b->b.pool_name, consume ? 1 : 0);
    if (consume) {
        HASH_DEL(g_by_msrn, b);
        free(b);
    }
    return 0;
}

void msrn_pool_release(const char *msrn_digits)
{
    binding_t *b = find_binding(msrn_digits);
    if (!b) return;
    LOGI("msrn", "[%s] release msrn=%s", b->b.imsi, msrn_digits);
    HASH_DEL(g_by_msrn, b);
    free(b);
}

void msrn_pool_sweep(time_t now)
{
    binding_t *b, *tmp;
    HASH_ITER(hh, g_by_msrn, b, tmp) {
        if (now > b->b.expires_at) {
            LOGW("msrn",
                 "[%s] ttl expiry msrn=%s tid=0x%08x",
                 b->b.imsi, b->b.msrn, b->b.dialogue_id);
            HASH_DEL(g_by_msrn, b);
            free(b);
        }
    }
}

int msrn_pool_show(char *buf, size_t cap)
{
    if (!buf || cap == 0) return 0;
    size_t o = 0;
    int n = snprintf(buf + o, cap - o, "msrn_pools=%d bindings=%u ttl=%d\n",
                     g_n_pools, (unsigned)HASH_COUNT(g_by_msrn), g_ttl_sec);
    if (n > 0) o += (size_t)n;
    binding_t *b, *tmp;
    time_t now = time(NULL);
    HASH_ITER(hh, g_by_msrn, b, tmp) {
        long left = (long)(b->b.expires_at - now);
        if (left < 0) left = 0;
        n = snprintf(buf + o, cap > o ? cap - o : 0,
                     "msrn=%s imsi=%s msisdn=%s pool=%s msc=%s tid=0x%08x ttl_left=%ld\n",
                     b->b.msrn, b->b.imsi, b->b.msisdn, b->b.pool_name,
                     b->b.msc_number[0] ? b->b.msc_number : "-",
                     b->b.dialogue_id, left);
        if (n < 0 || (size_t)n >= (cap > o ? cap - o : 0))
            break;
        o += (size_t)n;
    }
    if (o >= cap) o = cap - 1;
    buf[o] = '\0';
    return (int)o;
}
