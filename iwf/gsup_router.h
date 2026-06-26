/*
 * gsup_router.h - IMSI-based GSUP routing table lookup.
 */

#ifndef IWF_GSUP_ROUTER_H
#define IWF_GSUP_ROUTER_H

#include <stdint.h>
#include <stdbool.h>

#include "config.h"

typedef enum {
    GSUP_ROUTE_REJECT   = 0,
    GSUP_ROUTE_LOCAL    = 1,   /* home PLMN: Diameter S6d (DRA→HSS), not PyHSS GSUP */
    GSUP_ROUTE_MAP_HLR  = 2,   /* outbound MAP toward foreign HLR GT */
    GSUP_ROUTE_DIAM_HSS = 3,   /* roaming partner: S6d via DRA (per-PLMN realm) */
} gsup_route_kind_t;

typedef struct {
    gsup_route_kind_t kind;
    char              imsi[16];
    uint16_t          mcc;
    uint16_t          mnc;
    char              hlr_gt[24];
    uint8_t           hlr_ssn;
    char              src_ip[64];
    char              src_gt[24];
    char              dest_realm[128];  /* DRA Destination-Realm (roam S6d) */
    char              dest_host[128];   /* optional Destination-Host          */
    int               route_idx;   /* index into cfg->gsup_roam_routes, or -1 */
} gsup_route_t;

int gsup_router_lookup(const iwf_config_t *cfg,
                       const char *imsi_digits,
                       gsup_route_t *out);

#endif /* IWF_GSUP_ROUTER_H */
