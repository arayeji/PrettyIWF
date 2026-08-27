#include "pgw_dns.h"
#include "logging.h"
#include "uthash.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include <sys/socket.h>

#define PGW_DNS_ANSWER_MAX   4096
#define PGW_DNS_MAX_RR       16
#define PGW_DNS_MAX_DEPTH    3

typedef struct {
    uint16_t order;
    uint16_t pref;
    char     flags[8];
    char     service[128];
    char     replacement[NS_MAXDNAME];
} naptr_rr_t;

typedef struct pgw_dns_entry {
    char           name[NS_MAXDNAME];
    uint32_t       ipv4;                 /* host order; 0 = negative entry */
    char           host[NS_MAXDNAME];
    time_t         expires;
    UT_hash_handle hh;
} pgw_dns_entry_t;

static pgw_dns_entry_t *g_cache = NULL;
static int g_pos_ttl_s  = 300;
static int g_neg_ttl_s  = 30;
static int g_timeout_ms = 2000;

static struct __res_state g_res;
static int g_res_ready = 0;

/* ------------------------------------------------------------------ */
/* resolver state                                                      */
/* ------------------------------------------------------------------ */

static void res_apply_budget(void)
{
    /* retrans is seconds per try, retry is tries per server. The libc
     * defaults (5s x 2 x nservers) would block the epoll loop far too long
     * when a partner GpDNS is unreachable. */
    int secs = (g_timeout_ms + 999) / 1000;
    g_res.retrans = secs > 0 ? secs : 1;
    g_res.retry   = 1;
}

static int res_ready(void)
{
    if (g_res_ready)
        return 1;
    memset(&g_res, 0, sizeof(g_res));
    if (res_ninit(&g_res) != 0) {
        LOGE("pgw_dns", "res_ninit failed - PGW DNS discovery disabled");
        return 0;
    }
    res_apply_budget();
    g_res_ready = 1;
    return 1;
}

void pgw_dns_set_ttl(int pos_ttl_s, int neg_ttl_s)
{
    if (pos_ttl_s > 0) g_pos_ttl_s = pos_ttl_s;
    if (neg_ttl_s > 0) g_neg_ttl_s = neg_ttl_s;
}

void pgw_dns_set_timeout_ms(int timeout_ms)
{
    if (timeout_ms <= 0)
        return;
    g_timeout_ms = timeout_ms;
    if (g_res_ready)
        res_apply_budget();
}

/* ------------------------------------------------------------------ */
/* cache                                                               */
/* ------------------------------------------------------------------ */

static pgw_dns_entry_t *cache_find(const char *name, time_t now)
{
    pgw_dns_entry_t *e = NULL;
    HASH_FIND_STR(g_cache, name, e);
    if (!e)
        return NULL;
    if (e->expires <= now) {
        HASH_DEL(g_cache, e);
        free(e);
        return NULL;
    }
    return e;
}

static void cache_put(const char *name, uint32_t ipv4, const char *host,
                      time_t now)
{
    pgw_dns_entry_t *e = NULL;
    HASH_FIND_STR(g_cache, name, e);
    if (!e) {
        e = calloc(1, sizeof(*e));
        if (!e)
            return;
        strncpy(e->name, name, sizeof(e->name) - 1);
        HASH_ADD_STR(g_cache, name, e);
    }
    e->ipv4 = ipv4;
    e->host[0] = 0;
    if (host && host[0])
        strncpy(e->host, host, sizeof(e->host) - 1);
    e->expires = now + (ipv4 ? g_pos_ttl_s : g_neg_ttl_s);
}

void pgw_dns_cache_sweep(time_t now)
{
    pgw_dns_entry_t *e, *tmp;
    HASH_ITER(hh, g_cache, e, tmp) {
        if (e->expires <= now) {
            HASH_DEL(g_cache, e);
            free(e);
        }
    }
}

void pgw_dns_shutdown(void)
{
    pgw_dns_entry_t *e, *tmp;
    HASH_ITER(hh, g_cache, e, tmp) {
        HASH_DEL(g_cache, e);
        free(e);
    }
    if (g_res_ready) {
        res_nclose(&g_res);
        g_res_ready = 0;
    }
}

/* ------------------------------------------------------------------ */
/* NAPTR parsing                                                       */
/* ------------------------------------------------------------------ */

/* RFC 1035 <character-string>: one length octet then that many bytes. */
static int read_char_string(const unsigned char **p, const unsigned char *end,
                            char *out, size_t out_cap)
{
    if (*p >= end)
        return -1;
    size_t n = **p;
    (*p)++;
    if ((size_t)(end - *p) < n)
        return -1;
    size_t copy = n < out_cap - 1 ? n : out_cap - 1;
    memcpy(out, *p, copy);
    out[copy] = 0;
    *p += n;
    return 0;
}

/* The Service field must carry the PGW application tag plus an interface tag
 * we can actually anchor an S5/S8-C F-TEID on. Tags are colon-separated and
 * case-insensitive (TS 29.303 section 4.3.2). */
static int service_matches(const char *service, unsigned if_mask)
{
    if (!strcasestr(service, "x-3gpp-pgw"))
        return 0;
    if ((if_mask & PGW_DNS_IF_S8) && strcasestr(service, "x-s8-gtp")) return 1;
    if ((if_mask & PGW_DNS_IF_S5) && strcasestr(service, "x-s5-gtp")) return 1;
    if ((if_mask & PGW_DNS_IF_GN) && strcasestr(service, "x-gn"))     return 1;
    if ((if_mask & PGW_DNS_IF_GP) && strcasestr(service, "x-gp"))     return 1;
    return 0;
}

static int naptr_cmp(const void *a, const void *b)
{
    const naptr_rr_t *x = a, *y = b;
    if (x->order != y->order)
        return x->order < y->order ? -1 : 1;
    if (x->pref != y->pref)
        return x->pref < y->pref ? -1 : 1;
    return 0;
}

/* Query NAPTR at name, keep the RRs matching if_mask, sorted by (order,
 * preference). Returns the count, or -1 when the query itself failed
 * (NXDOMAIN / SERVFAIL / timeout). */
static int naptr_query(const char *name, unsigned if_mask,
                       naptr_rr_t *out, int out_max)
{
    unsigned char ans[PGW_DNS_ANSWER_MAX];
    int len = res_nquery(&g_res, name, ns_c_in, ns_t_naptr, ans, sizeof(ans));
    if (len < 0)
        return -1;

    ns_msg h;
    if (ns_initparse(ans, len, &h) < 0)
        return -1;

    int n_an = ns_msg_count(h, ns_s_an);
    int n = 0;
    for (int i = 0; i < n_an && n < out_max; i++) {
        ns_rr rr;
        if (ns_parserr(&h, ns_s_an, i, &rr) < 0)
            continue;
        if (ns_rr_type(rr) != ns_t_naptr)
            continue;

        const unsigned char *rd  = ns_rr_rdata(rr);
        const unsigned char *end = rd + ns_rr_rdlen(rr);
        if (end - rd < 4)
            continue;

        naptr_rr_t e;
        memset(&e, 0, sizeof(e));
        e.order = ns_get16(rd); rd += 2;
        e.pref  = ns_get16(rd); rd += 2;

        char regexp[256];
        if (read_char_string(&rd, end, e.flags, sizeof(e.flags)) != 0)
            continue;
        if (read_char_string(&rd, end, e.service, sizeof(e.service)) != 0)
            continue;
        if (read_char_string(&rd, end, regexp, sizeof(regexp)) != 0)
            continue;

        /* A non-empty Regexp with an empty Replacement is the ENUM-style
         * rewrite form; 3GPP never uses it for PGW discovery. */
        if (regexp[0])
            continue;

        if (ns_name_uncompress(ns_msg_base(h), ns_msg_end(h), rd,
                               e.replacement, sizeof(e.replacement)) < 0)
            continue;
        if (!e.replacement[0] || !strcmp(e.replacement, "."))
            continue;

        if (!service_matches(e.service, if_mask))
            continue;

        out[n++] = e;
    }

    if (n > 1)
        qsort(out, (size_t)n, sizeof(out[0]), naptr_cmp);
    return n;
}

/* ------------------------------------------------------------------ */
/* A / SRV                                                             */
/* ------------------------------------------------------------------ */

static uint32_t resolve_a(const char *host)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    struct addrinfo *res = NULL;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res)
        return 0;

    uint32_t ip = 0;
    for (struct addrinfo *p = res; p; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)p->ai_addr;
            ip = ntohl(sa->sin_addr.s_addr);
            break;
        }
    }
    freeaddrinfo(res);
    return ip;
}

/* SRV owner -> lowest-priority target -> A. Returns 0 when nothing resolves. */
static uint32_t resolve_srv(const char *owner, char *out_host, size_t host_cap)
{
    unsigned char ans[PGW_DNS_ANSWER_MAX];
    int len = res_nquery(&g_res, owner, ns_c_in, ns_t_srv, ans, sizeof(ans));
    if (len < 0)
        return 0;

    ns_msg h;
    if (ns_initparse(ans, len, &h) < 0)
        return 0;

    int n_an = ns_msg_count(h, ns_s_an);
    unsigned best_prio = 0xffffffffu;
    char best[NS_MAXDNAME];
    best[0] = 0;

    for (int i = 0; i < n_an; i++) {
        ns_rr rr;
        if (ns_parserr(&h, ns_s_an, i, &rr) < 0)
            continue;
        if (ns_rr_type(rr) != ns_t_srv)
            continue;
        if (ns_rr_rdlen(rr) < 7)
            continue;
        const unsigned char *rd = ns_rr_rdata(rr);
        unsigned prio = ns_get16(rd);
        char target[NS_MAXDNAME];
        if (ns_name_uncompress(ns_msg_base(h), ns_msg_end(h), rd + 6,
                               target, sizeof(target)) < 0)
            continue;
        if (prio < best_prio) {
            best_prio = prio;
            strncpy(best, target, sizeof(best) - 1);
            best[sizeof(best) - 1] = 0;
        }
    }

    if (!best[0])
        return 0;
    uint32_t ip = resolve_a(best);
    if (ip && out_host && host_cap) {
        strncpy(out_host, best, host_cap - 1);
        out_host[host_cap - 1] = 0;
    }
    return ip;
}

/* ------------------------------------------------------------------ */
/* discovery                                                           */
/* ------------------------------------------------------------------ */

static int resolve_recurse(const char *name, unsigned if_mask, int depth,
                           uint32_t *out_ipv4, char *out_host, size_t host_cap)
{
    if (depth > PGW_DNS_MAX_DEPTH)
        return 0;

    naptr_rr_t rrs[PGW_DNS_MAX_RR];
    int n = naptr_query(name, if_mask, rrs, PGW_DNS_MAX_RR);
    if (n <= 0)
        return 0;

    for (int i = 0; i < n; i++) {
        const naptr_rr_t *r = &rrs[i];
        uint32_t ip = 0;
        char host[NS_MAXDNAME];
        host[0] = 0;

        if (r->flags[0] == 'a' || r->flags[0] == 'A') {
            ip = resolve_a(r->replacement);
            if (ip) {
                strncpy(host, r->replacement, sizeof(host) - 1);
                host[sizeof(host) - 1] = 0;
            }
        } else if (r->flags[0] == 's' || r->flags[0] == 'S') {
            ip = resolve_srv(r->replacement, host, sizeof(host));
        } else if (r->flags[0] == 0) {
            /* Non-terminal: replacement is the owner of the next NAPTR. */
            if (resolve_recurse(r->replacement, if_mask, depth + 1,
                                &ip, host, sizeof(host)) != 1)
                ip = 0;
        } else {
            LOGD("pgw_dns", "%s: unsupported NAPTR flags %s - skipping",
                 name, r->flags);
            continue;
        }

        if (ip) {
            const char *shown = host[0] ? host : r->replacement;
            *out_ipv4 = ip;
            if (out_host && host_cap) {
                strncpy(out_host, shown, host_cap - 1);
                out_host[host_cap - 1] = 0;
            }
            LOGD("pgw_dns",
                 "%s -> NAPTR(order=%u pref=%u flags=%s svc=%s) -> %s = %u.%u.%u.%u",
                 name, (unsigned)r->order, (unsigned)r->pref,
                 r->flags, r->service, shown,
                 (ip >> 24) & 0xff, (ip >> 16) & 0xff,
                 (ip >> 8) & 0xff, ip & 0xff);
            return 1;
        }

        LOGD("pgw_dns", "%s: NAPTR replacement %s did not resolve - next RR",
             name, r->replacement);
    }
    return 0;
}

int pgw_dns_resolve_apn_fqdn(const char *apn_fqdn, unsigned if_mask,
                             uint32_t *out_ipv4,
                             char *out_host, size_t host_cap)
{
    if (!apn_fqdn || !apn_fqdn[0] || !out_ipv4)
        return 0;
    if (strlen(apn_fqdn) >= NS_MAXDNAME)
        return 0;
    if (out_host && host_cap)
        out_host[0] = 0;
    if (!if_mask)
        if_mask = PGW_DNS_IF_ANY;
    if (!res_ready())
        return 0;

    time_t now = time(NULL);

    pgw_dns_entry_t *c = cache_find(apn_fqdn, now);
    if (c) {
        if (!c->ipv4)
            return 0;                       /* cached negative */
        *out_ipv4 = c->ipv4;
        if (out_host && host_cap) {
            strncpy(out_host, c->host, host_cap - 1);
            out_host[host_cap - 1] = 0;
        }
        return 1;
    }

    uint32_t ip = 0;
    char host[NS_MAXDNAME];
    host[0] = 0;
    int ok = resolve_recurse(apn_fqdn, if_mask, 0, &ip, host, sizeof(host));

    if (ok && ip) {
        cache_put(apn_fqdn, ip, host, now);
        *out_ipv4 = ip;
        if (out_host && host_cap) {
            strncpy(out_host, host, host_cap - 1);
            out_host[host_cap - 1] = 0;
        }
        return 1;
    }

    cache_put(apn_fqdn, 0, NULL, now);
    return 0;
}
