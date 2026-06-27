#include "subscr_cache.h"
#include "logging.h"
#include "uthash.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>      /* strcasecmp */
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

#define SUBSCR_IMSI_MAX 20
#define SUBSCR_APN_MAX  64
#define SUBSCR_MAX_APN  8

typedef struct {
    char     apn[SUBSCR_APN_MAX];
    uint32_t pgw_ipv4;                  /* host order; 0 = FQDN-only/unresolved */
    char     pgw_fqdn[SUBSCR_FQDN_MAX];
    int      alloc_dynamic;
} subscr_apn_t;

typedef struct subscr_entry {
    char           imsi[SUBSCR_IMSI_MAX];
    subscr_apn_t   apns[SUBSCR_MAX_APN];
    uint8_t        n_apns;
    time_t         updated_at;
    UT_hash_handle hh;
} subscr_entry_t;

static subscr_entry_t *g_by_imsi = NULL;

void subscr_cache_init(void)
{
    g_by_imsi = NULL;
}

void subscr_cache_shutdown(void)
{
    subscr_entry_t *e, *tmp;
    HASH_ITER(hh, g_by_imsi, e, tmp) {
        HASH_DEL(g_by_imsi, e);
        free(e);
    }
}

static subscr_entry_t *find_imsi(const char *imsi)
{
    subscr_entry_t *e = NULL;
    HASH_FIND_STR(g_by_imsi, imsi, e);
    return e;
}

void subscr_cache_put_pgw(const char *imsi, const char *apn,
                          uint32_t pgw_ipv4, const char *pgw_fqdn,
                          int alloc_dynamic)
{
    if (!imsi || !*imsi || !apn || !*apn)
        return;
    if (!pgw_ipv4 && (!pgw_fqdn || !*pgw_fqdn))
        return;     /* nothing useful to remember */

    subscr_entry_t *e = find_imsi(imsi);
    if (!e) {
        e = calloc(1, sizeof(*e));
        if (!e)
            return;
        strncpy(e->imsi, imsi, sizeof(e->imsi) - 1);
        HASH_ADD_STR(g_by_imsi, imsi, e);
    }

    subscr_apn_t *a = NULL;
    for (uint8_t i = 0; i < e->n_apns; i++) {
        if (!strcasecmp(e->apns[i].apn, apn)) {
            a = &e->apns[i];
            break;
        }
    }
    if (!a) {
        if (e->n_apns >= SUBSCR_MAX_APN)
            a = &e->apns[0];            /* bound memory: recycle slot 0 */
        else
            a = &e->apns[e->n_apns++];
        memset(a, 0, sizeof(*a));
        strncpy(a->apn, apn, sizeof(a->apn) - 1);
    }

    a->pgw_ipv4      = pgw_ipv4;
    a->alloc_dynamic = alloc_dynamic;
    if (pgw_fqdn) {
        strncpy(a->pgw_fqdn, pgw_fqdn, sizeof(a->pgw_fqdn) - 1);
        a->pgw_fqdn[sizeof(a->pgw_fqdn) - 1] = '\0';
    } else {
        a->pgw_fqdn[0] = '\0';
    }
    e->updated_at = time(NULL);

    LOGI("subscr", "cache PGW imsi=%s apn=%s ipv4=%u.%u.%u.%u fqdn=%s alloc=%s",
         imsi, apn,
         (pgw_ipv4 >> 24) & 0xff, (pgw_ipv4 >> 16) & 0xff,
         (pgw_ipv4 >> 8) & 0xff, pgw_ipv4 & 0xff,
         a->pgw_fqdn[0] ? a->pgw_fqdn : "-",
         alloc_dynamic ? "dynamic" : "static");
}

uint32_t subscr_resolve_fqdn_ipv4(const char *fqdn)
{
    if (!fqdn || !*fqdn)
        return 0;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    struct addrinfo *res = NULL;
    if (getaddrinfo(fqdn, NULL, &hints, &res) != 0 || !res)
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

int subscr_cache_get_pgw(const char *imsi, const char *apn,
                         uint32_t *out_pgw_ipv4,
                         char *out_fqdn, size_t fqdn_cap,
                         int *out_alloc_dynamic)
{
    if (!imsi || !*imsi)
        return 0;

    subscr_entry_t *e = find_imsi(imsi);
    if (!e || e->n_apns == 0)
        return 0;

    subscr_apn_t *a = NULL;
    if (apn && *apn) {
        for (uint8_t i = 0; i < e->n_apns; i++) {
            if (!strcasecmp(e->apns[i].apn, apn)) {
                a = &e->apns[i];
                break;
            }
        }
    }
    /* Single-APN subscription: tolerate an APN mismatch (emulators often send
     * a generic APN in Create PDP that still maps to the one subscribed PDN). */
    if (!a && e->n_apns == 1)
        a = &e->apns[0];
    if (!a)
        return 0;

    uint32_t ip = a->pgw_ipv4;
    if (!ip && a->pgw_fqdn[0]) {
        ip = subscr_resolve_fqdn_ipv4(a->pgw_fqdn);
        if (ip)
            a->pgw_ipv4 = ip;           /* memoize the resolution */
    }

    if (out_fqdn && fqdn_cap) {
        strncpy(out_fqdn, a->pgw_fqdn, fqdn_cap - 1);
        out_fqdn[fqdn_cap - 1] = '\0';
    }
    if (out_alloc_dynamic)
        *out_alloc_dynamic = a->alloc_dynamic;

    if (!ip)
        return 0;
    if (out_pgw_ipv4)
        *out_pgw_ipv4 = ip;
    return 1;
}

void subscr_cache_sweep(time_t now, int ttl_s)
{
    subscr_entry_t *e, *tmp;
    HASH_ITER(hh, g_by_imsi, e, tmp) {
        if (now - e->updated_at > ttl_s) {
            HASH_DEL(g_by_imsi, e);
            free(e);
        }
    }
}
