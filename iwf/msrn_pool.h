/*
 * msrn_pool.h - Mobile Station Roaming Number pool for ProvideRoamingNumber.
 *
 * Owns MSRN ↔ IMSI bindings used when answering MAP PRN (opcode 4) and when
 * SIP ingress resolves an incoming call via cmd_sock msrn_lookup.
 */

#ifndef IWF_MSRN_POOL_H
#define IWF_MSRN_POOL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include "config.h"

#define MSRN_DIGITS_MAX     20
#define MSRN_IMSI_MAX       16
#define MSRN_MSISDN_MAX     24
#define MSRN_POOL_NAME_MAX  16
#define MSRN_MAX_POOLS      4
#define MSRN_MAX_MSC_MAPS   8

typedef struct {
    char     msrn[MSRN_DIGITS_MAX];
    char     imsi[MSRN_IMSI_MAX];
    char     msisdn[MSRN_MSISDN_MAX];   /* optional; "-" if unknown */
    char     pool_name[MSRN_POOL_NAME_MAX];
    char     msc_number[MSRN_DIGITS_MAX];
    uint32_t dialogue_id;
    time_t   allocated_at;
    time_t   expires_at;
} msrn_binding_t;

/* Load pools from config; safe to call with empty pools (feature off). */
int  msrn_pool_init(const iwf_config_t *cfg);
void msrn_pool_shutdown(void);

bool msrn_pool_configured(void);
bool msrn_pool_consume_on_lookup(void);

/* Allocate from pool selected by msc_number (via msrn_msc_map) or sole pool.
 * On success fills *out and returns 0. On failure returns -1 (exhausted /
 * no pool / unknown MSC when strict). */
int  msrn_pool_alloc(const char *imsi,
                     const char *msisdn,          /* may be NULL */
                     const char *msc_number,      /* may be NULL */
                     uint32_t dialogue_id,
                     msrn_binding_t *out);

/* Lookup by MSRN digits. consume=true releases binding after copy. */
int  msrn_pool_lookup(const char *msrn_digits, bool consume, msrn_binding_t *out);

void msrn_pool_release(const char *msrn_digits);
void msrn_pool_sweep(time_t now);

/* Append human-readable dump into buf; returns bytes written (excl NUL). */
int  msrn_pool_show(char *buf, size_t cap);

#endif /* IWF_MSRN_POOL_H */
