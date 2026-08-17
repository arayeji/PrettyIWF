/*
 * subscr_cache.h - per-(IMSI, APN) subscription PGW cache.
 *
 * Bridges the GSUP/Diameter world (auth + Update Location) with the GTP
 * world (Create PDP -> Create Session). The home HSS may return the serving
 * PGW for a subscriber inside ULA Subscription-Data (MIP6-Agent-Info /
 * PDN-GW-Allocation-Type). That arrives long before osmo-sgsn issues the
 * Gn Create PDP Context, by which time the originating MAP/Diameter session
 * is gone. This cache remembers the PGW so translate.c can anchor the
 * S5/S8 session at the right PGW:
 *   - home-routed roamers  -> their home PGW (from the partner HSS),
 *   - local subscribers    -> the PGW their own HSS advertises (so no
 *                             static [smf] address is required).
 *
 * Always compiled. When the MAP/Diameter build is disabled the cache is
 * simply never populated and translate.c falls back to the [smf] config.
 */

#ifndef IWF_SUBSCR_CACHE_H
#define IWF_SUBSCR_CACHE_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

#define SUBSCR_FQDN_MAX 256

void subscr_cache_init(void);
void subscr_cache_shutdown(void);

/* Subscription PGW cache TTL (seconds). Default 300. Expired entries are
 * dropped on get and by the periodic sweep. */
void subscr_cache_set_ttl(int ttl_s);
int  subscr_cache_get_ttl(void);

/* Upsert the PGW selection for (imsi, apn) learned from HSS subscription
 * data. pgw_ipv4 is host byte order (0 when the HSS sent only an FQDN).
 * pgw_fqdn may be NULL/empty. alloc_dynamic: 1 = dynamic (DNS), 0 = static. */
void subscr_cache_put_pgw(const char *imsi, const char *apn,
                          uint32_t pgw_ipv4, const char *pgw_fqdn,
                          int alloc_dynamic);

/* Look up the PGW for (imsi, apn). On success returns 1 and sets
 * *out_pgw_ipv4 (host order, non-zero). When the stored entry holds only an
 * FQDN it is resolved to IPv4 here (best-effort) and memoized. Falls back to
 * the IMSI's sole APN entry when the exact APN is not found (common in
 * single-APN labs). out_fqdn / out_alloc_dynamic may be NULL. Returns 0 when
 * no usable PGW IPv4 is known. */
int  subscr_cache_get_pgw(const char *imsi, const char *apn,
                          uint32_t *out_pgw_ipv4,
                          char *out_fqdn, size_t fqdn_cap,
                          int *out_alloc_dynamic);

/* MIP path: return stored MIP-Home-Agent-Address IPv4 only (no DNS). */
int  subscr_cache_get_pgw_mip(const char *imsi, const char *apn,
                              uint32_t *out_pgw_ipv4);

/* DNS path: copy stored MIP-Home-Agent-Host FQDN (no resolve). Returns 1 if
 * a non-empty FQDN is present. */
int  subscr_cache_get_pgw_fqdn(const char *imsi, const char *apn,
                               char *out_fqdn, size_t fqdn_cap);

/* Evict entries not refreshed within ttl_s seconds. If ttl_s <= 0, uses the
 * TTL from subscr_cache_set_ttl(). */
void subscr_cache_sweep(time_t now, int ttl_s);

/* Best-effort synchronous resolution of an FQDN to a host-order IPv4 (0 on
 * failure). Shared so the PGW-selection path can resolve preconfigured PGW
 * FQDNs the same way as ULA-derived ones. */
uint32_t subscr_resolve_fqdn_ipv4(const char *fqdn);

#endif /* IWF_SUBSCR_CACHE_H */
