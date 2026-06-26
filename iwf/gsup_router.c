#include "gsup_router.h"
#include "config.h"
#include "map_codec.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int parse_plmn_from_imsi(const char *imsi, uint16_t *mcc, uint16_t *mnc)
{
    if (!imsi || strlen(imsi) < 5 || !mcc || !mnc)
        return -1;
    unsigned a = 0, b = 0, c = 0, d = 0, e = 0;
    if (sscanf(imsi, "%1u%1u%1u%1u%1u", &a, &b, &c, &d, &e) != 5)
        return -1;
    *mcc = (uint16_t)(a * 100u + b * 10u + c);
    /* Always return 2-digit MNC here. Callers that need to try 3-digit must
     * call parse_plmn_from_imsi_3digit() separately. This avoids misrouting
     * 2-digit MNC subscribers (e.g. HiWEB MNC=12) as 3-digit MNC=12x. */
    *mnc = (uint16_t)(d * 10u + e);
    return 0;
}

static int parse_mnc3_from_imsi(const char *imsi, uint16_t *mnc3)
{
    if (!imsi || strlen(imsi) < 6 || !mnc3)
        return -1;
    unsigned d = 0, e = 0;
    if (sscanf(imsi + 3, "%1u%1u", &d, &e) != 2)
        return -1;
    if (!isdigit((unsigned char)imsi[5]))
        return -1;
    unsigned f = (unsigned)(imsi[5] - '0');
    *mnc3 = (uint16_t)(d * 100u + e * 10u + f);
    return 0;
}

static void mnc_to_key(uint16_t mnc, char out[4])
{
    snprintf(out, 4, "%03u", (unsigned)mnc);
}

static int find_roam_route(const iwf_config_t *cfg, const char *mnc_key)
{
    for (int i = 0; i < cfg->gsup_n_roam_routes; i++) {
        if (!strcmp(cfg->gsup_roam_routes[i].mnc, mnc_key))
            return i;
    }
    return -1;
}

static void fill_diam_dest(gsup_route_t *out, const iwf_config_t *cfg, int idx)
{
    if (idx < 0 || idx >= cfg->gsup_n_roam_routes)
        return;
    const typeof(cfg->gsup_roam_routes[0]) *r = &cfg->gsup_roam_routes[idx];
    if (r->dest_realm[0])
        strncpy(out->dest_realm, r->dest_realm, sizeof(out->dest_realm) - 1);
    else if (r->use_diameter)
        (void)map_plmn_to_diam_realm(out->mcc, out->mnc,
                                     out->dest_realm, sizeof(out->dest_realm));
    if (r->dest_host[0])
        strncpy(out->dest_host, r->dest_host, sizeof(out->dest_host) - 1);
}

static void fill_route_meta(gsup_route_t *out, const iwf_config_t *cfg, int idx)
{
    out->route_idx = idx;
    if (idx < 0 || idx >= cfg->gsup_n_roam_routes)
        return;
    const typeof(cfg->gsup_roam_routes[0]) *r = &cfg->gsup_roam_routes[idx];
    if (r->hlr_gt[0])
        strncpy(out->hlr_gt, r->hlr_gt, sizeof(out->hlr_gt) - 1);
    out->hlr_ssn = r->hlr_ssn ? r->hlr_ssn : (uint8_t)6;
    if (r->src_ip[0])
        strncpy(out->src_ip, r->src_ip, sizeof(out->src_ip) - 1);
    if (r->src_gt[0])
        strncpy(out->src_gt, r->src_gt, sizeof(out->src_gt) - 1);
    else if (cfg->map_local_gt[0])
        strncpy(out->src_gt, cfg->map_local_gt, sizeof(out->src_gt) - 1);
    fill_diam_dest(out, cfg, idx);
}

static bool roam_route_is_diameter(const iwf_config_t *cfg, int idx)
{
    if (idx < 0 || idx >= cfg->gsup_n_roam_routes)
        return false;
    const typeof(cfg->gsup_roam_routes[0]) *r = &cfg->gsup_roam_routes[idx];
    return r->use_diameter || r->dest_realm[0] != '\0' || r->dest_host[0] != '\0';
}

int gsup_router_lookup(const iwf_config_t *cfg,
                       const char *imsi_digits,
                       gsup_route_t *out)
{
    if (!cfg || !imsi_digits || !out) return -1;
    memset(out, 0, sizeof(*out));
    strncpy(out->imsi, imsi_digits, sizeof(out->imsi) - 1);

    if (parse_plmn_from_imsi(imsi_digits, &out->mcc, &out->mnc) < 0)
        return -1;

    if (out->mcc != 432) {
        out->kind = GSUP_ROUTE_REJECT;
        return 0;
    }

    /* Try 2-digit MNC first, then 3-digit, to correctly handle operators like
     * HiWEB (MNC=012, 2-digit) whose IMSI digit[5] is the first MSIN digit. */
    char mnc_key[4];
    mnc_to_key(out->mnc, mnc_key);

    /* Check if the 2-digit key matches local or a roaming route.
     * If not, try the 3-digit interpretation. */
    bool matched_2digit = (!strcmp(mnc_key, cfg->gsup_local_mnc) ||
                           find_roam_route(cfg, mnc_key) >= 0);
    if (!matched_2digit) {
        uint16_t mnc3 = 0;
        if (parse_mnc3_from_imsi(imsi_digits, &mnc3) == 0) {
            char mnc_key3[4];
            mnc_to_key(mnc3, mnc_key3);
            if (!strcmp(mnc_key3, cfg->gsup_local_mnc) ||
                find_roam_route(cfg, mnc_key3) >= 0) {
                out->mnc = mnc3;
                mnc_to_key(mnc3, mnc_key);
            }
        }
    }

    if (!strcmp(mnc_key, cfg->gsup_local_mnc)) {
        out->kind = GSUP_ROUTE_LOCAL;
        fill_route_meta(out, cfg, find_roam_route(cfg, mnc_key));
        return 0;
    }

    int idx = find_roam_route(cfg, mnc_key);
    if (idx < 0) {
        out->kind = GSUP_ROUTE_REJECT;
        return 0;
    }
    if (cfg->gsup_roam_routes[idx].is_local) {
        out->kind = GSUP_ROUTE_LOCAL;
    } else if (roam_route_is_diameter(cfg, idx)) {
        out->kind = GSUP_ROUTE_DIAM_HSS;
    } else if (cfg->gsup_roam_routes[idx].hlr_gt[0]) {
        out->kind = GSUP_ROUTE_MAP_HLR;
    } else {
        out->kind = GSUP_ROUTE_REJECT;
        return 0;
    }
    fill_route_meta(out, cfg, idx);
    return 0;
}
