/*
 * pgw_dns.h - 3GPP PGW discovery by NAPTR (TS 23.003 §19.4.2 / TS 29.303).
 *
 * The APN-FQDN "<APN-NI>.apn.epc.mnc<MNC>.mcc<MCC>.3gppnetwork.org" is NOT
 * an A-record name. Per TS 29.303 §4.3.2 a GPRS/EPC node discovers the PGW
 * by querying NAPTR at that name, selecting an RR whose Service field
 * carries "x-3gpp-pgw" plus an interface tag ("x-s8-gtp", "x-s5-gtp", ...),
 * and only then resolving the NAPTR replacement host to A.
 *
 * Partner GpDNS servers publish exactly that and nothing else, so a plain
 * getaddrinfo() on the APN-FQDN returns NXDOMAIN and PGW selection fails.
 * (A local zone with a wildcard A record masks the problem for one partner
 * while every spec-compliant partner keeps failing.)
 *
 * Resolution is synchronous — it runs on the epoll loop — so results are
 * cached, negatives included, and the resolver retry/timeout is clamped.
 */

#ifndef IWF_PGW_DNS_H
#define IWF_PGW_DNS_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

/* Interface tags accepted in the NAPTR Service field, in addition to the
 * mandatory "x-3gpp-pgw" application tag. */
#define PGW_DNS_IF_S8   0x01
#define PGW_DNS_IF_S5   0x02
#define PGW_DNS_IF_GN   0x04
#define PGW_DNS_IF_GP   0x08
#define PGW_DNS_IF_ANY  (PGW_DNS_IF_S8 | PGW_DNS_IF_S5 | PGW_DNS_IF_GN | PGW_DNS_IF_GP)

/* Positive/negative cache TTLs (seconds). pos_ttl <= 0 keeps the current
 * value; neg_ttl <= 0 likewise. Defaults: 300 / 30. */
void pgw_dns_set_ttl(int pos_ttl_s, int neg_ttl_s);

/* Per-query resolver budget. Clamps res_state retrans/retry so a dead
 * partner GpDNS cannot stall the event loop for the libc default (~40s).
 * Default 2000 ms. */
void pgw_dns_set_timeout_ms(int timeout_ms);

/* Resolve an APN-FQDN to a PGW IPv4 (host byte order).
 *
 * NAPTR at apn_fqdn -> filter by "x-3gpp-pgw" + one of if_mask -> order by
 * (order, preference) -> follow flags:
 *   "a"  replacement is a host name          -> A
 *   "s"  replacement is an SRV owner name    -> SRV -> A
 *   ""   non-terminal, replacement is a new NAPTR owner (bounded recursion)
 *
 * Returns 1 and sets *out_ipv4 on success. out_host, when non-NULL, receives
 * the replacement host that produced the address (useful for logs).
 * Returns 0 when the name has no usable PGW record — the caller should treat
 * that as "reject", not as "try the next source".
 */
int pgw_dns_resolve_apn_fqdn(const char *apn_fqdn, unsigned if_mask,
                             uint32_t *out_ipv4,
                             char *out_host, size_t host_cap);

/* Drop expired cache entries. Called from the periodic sweep. */
void pgw_dns_cache_sweep(time_t now);

/* Free the cache and the resolver state. */
void pgw_dns_shutdown(void);

#endif /* IWF_PGW_DNS_H */
