#include "config.h"
#include "logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>

#include "iwf.h"

static void defaults(iwf_config_t *c)
{
    memset(c, 0, sizeof(*c));
    strncpy(c->listen_ip, "0.0.0.0", sizeof(c->listen_ip) - 1);
    c->listen_port = 2123;
    c->local_ip[0] = '\0';
    strncpy(c->sgsn_ip, "0.0.0.0", sizeof(c->sgsn_ip) - 1);
    c->sgsn_port = GTP_PORT;
    strncpy(c->mme_ip, "0.0.0.0", sizeof(c->mme_ip) - 1);
    c->mme_port = GTP_PORT;
    strncpy(c->sgwc_ip, "127.0.0.1", sizeof(c->sgwc_ip) - 1);
    c->sgwc_port = 2123;
    strncpy(c->log_level, "error", sizeof(c->log_level) - 1);
    strncpy(c->log_file, "-", sizeof(c->log_file) - 1);
    c->trace_imsi[0] = '\0';
    c->metrics_enabled = 1;
    strncpy(c->metrics_listen_ip, "127.0.0.1", sizeof(c->metrics_listen_ip) - 1);
    c->metrics_listen_port = 9090;
    c->synthetic_uli_no_rai = 0;
    /* Default EUTRAN for out-of-the-box compatibility. UTRAN (1) is fully
     * supported by current Open5GS on both SGW-C and SMF (sgwc/gn-handler.c,
     * smf/gsm-sm.c, smf/s5c-build.c and smf/gx-path.c all switch on it), and
     * it is the truthful value for 3G subscribers - set [iwf] rat_type = utran
     * so the SGW-C and the PGW can tell them apart. Pair it with a real Gn ULI
     * IE from the SGSN; see gtpv2_enc_uli_from_v1_uli(). */
    c->rat_type = 6;
    /* Gn RAI is always LAC=0xfffe/RAC=0xff from OsmoSGSN — not a real cell.
     * Emit a fixed gateway TAI/ECGI for EUTRAN (MME-accepted roaming TAC). */
    c->uli_tac = 0xc350;
    c->uli_eci = 1;
    /* Prefer the HSS-advertised PGW (ULA MIP6-Agent-Info) over static [smf]. */
    c->pgw_from_subscription = 1;
    c->pgw_select[0] = IWF_PGW_SRC_MIP;
    c->pgw_select[1] = IWF_PGW_SRC_DNS;
    c->pgw_select[2] = IWF_PGW_SRC_STATIC;
    c->pgw_select[3] = IWF_PGW_SRC_SMF;
    c->pgw_n_select = 4;
    c->pgw_select_explicit = 0;
    c->pgw_cache_ttl_s = 300;
    c->pending_timeout_s = 15;
    c->pgw_dns_neg_ttl_s = 30;
    c->pgw_dns_timeout_ms = 2000;

    strncpy(c->map_cmd_sock_path, "/tmp/iwf_cmd.sock", sizeof(c->map_cmd_sock_path) - 1);
    c->map_cmd_sock_path[sizeof(c->map_cmd_sock_path) - 1] = '\0';

    /* MAP-IWF: disabled by default - existing GTP-only deployments need no changes. */
    c->map_iwf_enabled    = 0;
    c->map_local_ssn      = 149;
    c->map_sccp_ri        = IWF_SCCP_RI_GT;
    c->map_t_dialogue_ms  = 10000;
    c->map_isd_before_loc_up = 1;
    c->map_msrn_ttl_sec   = 30;
    c->map_msrn_consume_on_lookup = 1;
    c->map_msrn_n_pools   = 0;
    c->map_msrn_n_msc_map = 0;
    strncpy(c->stp_ip,   "127.0.0.1", sizeof(c->stp_ip)   - 1);
    c->stp_port           = 2905;
    c->stp_routing_context = 1u;
    c->stp_network_indicator = 0;   /* international; set reserved (3) for osmo-stp lab */
    c->diam_peer_port     = 3868;
    c->diam_watchdog_ms   = 30000;
    c->diam_request_timeout_ms = 10000;
    c->diam_vendor_id     = 10415;  /* 3GPP */
    strncpy(c->diam_product_name, "iwf",  sizeof(c->diam_product_name) - 1);

    c->gsup_server_enabled = 0;
    c->gsup_listen_port      = 4222;
    /* ITU-T E.212 test PLMN placeholders - a deployment must set
     * [gsup_server] local_mcc / local_mnc to its own values. */
    snprintf(c->gsup_local_mcc, sizeof(c->gsup_local_mcc), "001");
    snprintf(c->gsup_local_mnc, sizeof(c->gsup_local_mnc), "01");
    c->gsup_local_mcc_set = 0;
    c->gsup_timeout_ms       = 10000;
    c->gsup_cs_backend       = GSUP_BACKEND_DIAMETER;
    c->gsup_ps_backend       = GSUP_BACKEND_DIAMETER;

#ifdef SMS_IWF_ENABLED
    c->sms_iwf_enabled       = 0;
    c->sms_hlr_ssn           = 6;
    strncpy(c->sms_local_msc_gt,  "1234567890000", sizeof(c->sms_local_msc_gt) - 1);
    strncpy(c->sms_local_smsc_gt, "1234567890006", sizeof(c->sms_local_smsc_gt) - 1);
    c->sms_gsup_timeout_ms   = 3000;
    c->sms_sri_sm_timeout_ms = 5000;
    c->sms_fwdsm_timeout_ms  = 30000;
    strncpy(c->gsup_remote_ip, "127.0.0.1", sizeof(c->gsup_remote_ip) - 1);
    c->gsup_remote_port      = 4222;
    strncpy(c->gsup_client_name, "IWF-SMS", sizeof(c->gsup_client_name) - 1);
    strncpy(c->smpp_bind_ip, "127.0.0.1", sizeof(c->smpp_bind_ip) - 1);
    c->smpp_port             = 2777;
    strncpy(c->smpp_system_id, "iwf", sizeof(c->smpp_system_id) - 1);
    strncpy(c->smpp_password, "changeme", sizeof(c->smpp_password) - 1);
#endif
}

static int parse_gsup_backend(const char *val)
{
    if (!val || !*val) return GSUP_BACKEND_DIAMETER;
    if (!strcasecmp(val, "map") || !strcasecmp(val, "map-c") ||
        !strcasecmp(val, "ss7"))
        return GSUP_BACKEND_MAP;
    if (!strcasecmp(val, "diameter") || !strcasecmp(val, "s6d") ||
        !strcasecmp(val, "s6a"))
        return GSUP_BACKEND_DIAMETER;
    LOGW("config", "unknown gsup backend '%s' (use map|diameter)", val);
    return GSUP_BACKEND_DIAMETER;
}

static uint8_t parse_network_indicator(const char *val)
{
    if (!val || !*val)
        return 0;
    if (!strcasecmp(val, "international"))
        return 0;
    if (!strcasecmp(val, "spare"))
        return 1;
    if (!strcasecmp(val, "national"))
        return 2;
    if (!strcasecmp(val, "reserved"))
        return 3;
    long n = strtol(val, NULL, 0);
    if (n >= 0 && n <= 3)
        return (uint8_t)n;
    LOGW("config", "invalid network_indicator %s, using international (0)", val);
    return 0;
}

static uint8_t parse_rat_type(const char *val)
{
    if (!val || !*val) return 6;
    if (!strcasecmp(val, "utran"))  return 1;
    if (!strcasecmp(val, "geran"))  return 2;
    if (!strcasecmp(val, "wlan"))   return 3;
    if (!strcasecmp(val, "eutran")) return 6;
    long n = strtol(val, NULL, 0);
    if (n >= 1 && n <= 255) return (uint8_t)n;
    return 6;
}

static char *trim(char *s)
{
    while (*s && isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = '\0';
    return s;
}

static void strip_inline_comment(char *s)
{
    for (char *p = s; *p; p++) {
        if (*p == ';' || *p == '#') { *p = '\0'; return; }
    }
}

static void copy_str(char *dst, size_t dst_sz, const char *src)
{
    if (dst_sz == 0) return;
    size_t n = strlen(src);
    if (n >= dst_sz) n = dst_sz - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

#ifdef SMS_IWF_ENABLED
static void sms_partner_split_prefixes(iwf_config_t *out, int idx)
{
    char *raw = out->sms_partners[idx].prefixes_raw;
    out->sms_partners[idx].n_prefixes = 0;
    if (!raw[0]) return;
    char buf[256];
    copy_str(buf, sizeof(buf), raw);
    char *save = NULL;
    for (char *tok = strtok_r(buf, ",", &save); tok;
         tok = strtok_r(NULL, ",", &save)) {
        tok = trim(tok);
        if (!*tok) continue;
        int n = out->sms_partners[idx].n_prefixes;
        if (n >= SMS_MAX_PREFIXES) break;
        copy_str(out->sms_partners[idx].prefix[n],
                 sizeof(out->sms_partners[idx].prefix[n]), tok);
        out->sms_partners[idx].n_prefixes++;
    }
}

static int sms_partner_index(iwf_config_t *out, const char *section)
{
    if (strncmp(section, "partner.", 8) != 0) return -1;
    const char *name = section + 8;
    for (int i = 0; i < out->sms_n_partners; i++) {
        if (!strcmp(out->sms_partners[i].name, name))
            return i;
    }
    if (out->sms_n_partners >= SMS_MAX_PARTNERS) {
        LOGW("config", "too many [partner.*] sections (max %d)", SMS_MAX_PARTNERS);
        return -1;
    }
    int idx = out->sms_n_partners++;
    copy_str(out->sms_partners[idx].name,
             sizeof(out->sms_partners[idx].name), name);
    return idx;
}
#endif

static void gsup_listen_ip_add(iwf_config_t *out, const char *ip)
{
    if (!ip || !*ip) return;
    for (int i = 0; i < out->gsup_n_listen_ips; i++) {
        if (!strcmp(out->gsup_listen_ips[i], ip))
            return;
    }
    if (out->gsup_n_listen_ips >= GSUP_MAX_LISTEN_IPS) {
        LOGW("config", "too many GSUP listen IPs (max %d)", GSUP_MAX_LISTEN_IPS);
        return;
    }
    copy_str(out->gsup_listen_ips[out->gsup_n_listen_ips],
             sizeof(out->gsup_listen_ips[0]), ip);
    out->gsup_n_listen_ips++;
}

static void gsup_listen_ips_split(iwf_config_t *out, const char *csv)
{
    if (!csv || !*csv) return;
    char buf[512];
    copy_str(buf, sizeof(buf), csv);
    char *save = NULL;
    for (char *tok = strtok_r(buf, ",", &save); tok;
         tok = strtok_r(NULL, ",", &save)) {
        tok = trim(tok);
        if (*tok) gsup_listen_ip_add(out, tok);
    }
}

static void diam_peer_add(iwf_config_t *out, const char *ip, uint16_t port)
{
    if (!ip || !ip[0] || out->diam_n_peers >= DIAM_MAX_PEERS_CFG) return;
    int idx = out->diam_n_peers++;
    copy_str(out->diam_peers[idx].ip, sizeof(out->diam_peers[idx].ip), ip);
    out->diam_peers[idx].port = port ? port : 3868;
}

static void diam_peers_split(iwf_config_t *out, const char *csv)
{
    if (!csv || !*csv) return;
    char buf[512];
    copy_str(buf, sizeof(buf), csv);
    char *save = NULL;
    for (char *tok = strtok_r(buf, ",", &save); tok;
         tok = strtok_r(NULL, ",", &save)) {
        tok = trim(tok);
        if (!*tok) continue;
        char *colon = strchr(tok, ':');
        if (colon) {
            *colon = '\0';
            char *ip = trim(tok);
            char *port_s = trim(colon + 1);
            uint16_t port = (uint16_t)atoi(port_s);
            diam_peer_add(out, ip, port);
        } else {
            diam_peer_add(out, tok, out->diam_peer_port ? out->diam_peer_port : 3868);
        }
    }
}

static void diam_peers_finalize(iwf_config_t *out)
{
    if (out->diam_n_peers == 0 && out->diam_peer_ip[0]) {
        diam_peer_add(out, out->diam_peer_ip,
                      out->diam_peer_port ? out->diam_peer_port : 3868);
    }
}

static int gsup_roam_route_index(iwf_config_t *out, const char *mnc, int is_local)
{
    for (int i = 0; i < out->gsup_n_roam_routes; i++) {
        if (!strcmp(out->gsup_roam_routes[i].mnc, mnc))
            return i;
    }
    if (out->gsup_n_roam_routes >= GSUP_MAX_ROAM_ROUTES) {
        LOGW("config", "too many [roaming_hlr] routes (max %d)", GSUP_MAX_ROAM_ROUTES);
        return -1;
    }
    int idx = out->gsup_n_roam_routes++;
    memset(&out->gsup_roam_routes[idx], 0, sizeof(out->gsup_roam_routes[idx]));
    copy_str(out->gsup_roam_routes[idx].mnc,
             sizeof(out->gsup_roam_routes[idx].mnc), mnc);
    out->gsup_roam_routes[idx].hlr_ssn = 6; /* HLR SSN (TS 23.003) */
    out->gsup_roam_routes[idx].is_local = is_local;
    return idx;
}

/* Parse comma-separated PGW source order: mip,dns,static,smf.
 * Returns count written to out[] (0 on empty/invalid). Dedupes tokens. */
static int parse_pgw_select(const char *val, uint8_t out[IWF_PGW_SELECT_MAX])
{
    if (!val || !*val)
        return 0;
    char buf[128];
    copy_str(buf, sizeof(buf), val);
    int n = 0;
    int seen = 0;
    char *save = NULL;
    for (char *tok = strtok_r(buf, ", \t", &save); tok;
         tok = strtok_r(NULL, ", \t", &save)) {
        tok = trim(tok);
        if (!*tok) continue;
        uint8_t src = 0;
        if (!strcasecmp(tok, "mip") || !strcasecmp(tok, "subscription"))
            src = IWF_PGW_SRC_MIP;
        else if (!strcasecmp(tok, "dns") || !strcasecmp(tok, "apn") ||
                 !strcasecmp(tok, "fqdn"))
            src = IWF_PGW_SRC_DNS;
        else if (!strcasecmp(tok, "static") || !strcasecmp(tok, "pgw_ip"))
            src = IWF_PGW_SRC_STATIC;
        else if (!strcasecmp(tok, "smf") || !strcasecmp(tok, "config"))
            src = IWF_PGW_SRC_SMF;
        else {
            LOGW("config", "unknown pgw_select token '%s' "
                 "(expected mip,dns,static,smf)", tok);
            continue;
        }
        if (seen & (1 << src))
            continue;
        if (n >= IWF_PGW_SELECT_MAX)
            break;
        seen |= (1 << src);
        out[n++] = src;
    }
    return n;
}

/* Parse comma-separated IMSI prefixes (digits only) into home_imsi_prefix[]. */
static void home_imsi_prefix_add(iwf_config_t *out, const char *val)
{
    if (!out || !val)
        return;
    char buf[256];
    copy_str(buf, sizeof(buf), val);
    char *save = NULL;
    for (char *tok = strtok_r(buf, ", \t", &save); tok;
         tok = strtok_r(NULL, ", \t", &save)) {
        /* Keep digits only. */
        char pfx[IWF_HOME_IMSI_PREFIX_LEN];
        size_t n = 0;
        for (const char *p = tok; *p && n + 1 < sizeof(pfx); p++) {
            if (*p >= '0' && *p <= '9')
                pfx[n++] = *p;
        }
        pfx[n] = '\0';
        if (n < 5) {
            if (tok[0])
                LOGW("config", "home_imsi_prefix '%s' too short (need >=5 digits)",
                     tok);
            continue;
        }
        int dup = 0;
        for (int i = 0; i < out->n_home_imsi_prefix; i++) {
            if (!strcmp(out->home_imsi_prefix[i], pfx)) {
                dup = 1;
                break;
            }
        }
        if (dup)
            continue;
        if (out->n_home_imsi_prefix >= IWF_HOME_IMSI_PREFIX_MAX) {
            LOGW("config", "home_imsi_prefix full (max %d), ignoring %s",
                 IWF_HOME_IMSI_PREFIX_MAX, pfx);
            break;
        }
        copy_str(out->home_imsi_prefix[out->n_home_imsi_prefix],
                 sizeof(out->home_imsi_prefix[0]), pfx);
        out->n_home_imsi_prefix++;
    }
}
static void gsup_roam_key(iwf_config_t *out, const char *key, const char *val)
{
    if (strncmp(key, "mnc", 3) != 0) {
        LOGW("config", "unknown key [roaming_hlr].%s", key);
        return;
    }
    const char *p = key + 3;
    char mnc[4] = {0};
    int mi = 0;
    while (*p >= '0' && *p <= '9' && mi < 3)
        mnc[mi++] = *p++;
    if (mi != 3 || *p != '_') {
        LOGW("config", "bad [roaming_hlr] key (expected mncNNN_field): %s", key);
        return;
    }
    p++;
    int is_local = !strcmp(mnc, out->gsup_local_mnc);
    int idx = gsup_roam_route_index(out, mnc, is_local);
    if (idx < 0) return;
    if (!strcmp(p, "hlr_gt"))
        copy_str(out->gsup_roam_routes[idx].hlr_gt,
                 sizeof(out->gsup_roam_routes[idx].hlr_gt), val);
    else if (!strcmp(p, "ssn"))
        out->gsup_roam_routes[idx].hlr_ssn = (uint8_t)atoi(val);
    else if (!strcmp(p, "src_ip"))
        copy_str(out->gsup_roam_routes[idx].src_ip,
                 sizeof(out->gsup_roam_routes[idx].src_ip), val);
    else if (!strcmp(p, "src_gt"))
        copy_str(out->gsup_roam_routes[idx].src_gt,
                 sizeof(out->gsup_roam_routes[idx].src_gt), val);
    else if (!strcmp(p, "e214_prefix"))
        copy_str(out->gsup_roam_routes[idx].e214_prefix,
                 sizeof(out->gsup_roam_routes[idx].e214_prefix), val);
    else if (!strcmp(p, "dest_realm"))
        copy_str(out->gsup_roam_routes[idx].dest_realm,
                 sizeof(out->gsup_roam_routes[idx].dest_realm), val);
    else if (!strcmp(p, "dest_host"))
        copy_str(out->gsup_roam_routes[idx].dest_host,
                 sizeof(out->gsup_roam_routes[idx].dest_host), val);
    else if (!strcmp(p, "diameter"))
        out->gsup_roam_routes[idx].use_diameter = (atoi(val) != 0);
    else if (!strcmp(p, "pgw_ip"))
        copy_str(out->gsup_roam_routes[idx].pgw_ip,
                 sizeof(out->gsup_roam_routes[idx].pgw_ip), val);
    else if (!strcmp(p, "pgw_fqdn"))
        copy_str(out->gsup_roam_routes[idx].pgw_fqdn,
                 sizeof(out->gsup_roam_routes[idx].pgw_fqdn), val);
    else if (!strcmp(p, "pgw_select")) {
        int n = parse_pgw_select(val, out->gsup_roam_routes[idx].pgw_select);
        if (n > 0)
            out->gsup_roam_routes[idx].pgw_n_select = n;
    } else if (!strcmp(p, "apn") || !strcmp(p, "apn_acl")) {
        /* Comma-separated APN-NI allow-list for this PLMN. */
        char buf[512];
        copy_str(buf, sizeof(buf), val);
        char *save = NULL;
        for (char *tok = strtok_r(buf, ", \t", &save); tok;
             tok = strtok_r(NULL, ", \t", &save)) {
            iwf_apn_normalize(tok);
            if (!tok[0])
                continue;
            typeof(out->gsup_roam_routes[0]) *r = &out->gsup_roam_routes[idx];
            int dup = 0;
            for (int i = 0; i < r->n_apn_acl; i++) {
                if (!strcasecmp(r->apn_acl[i], tok)) {
                    dup = 1;
                    break;
                }
            }
            if (dup)
                continue;
            if (r->n_apn_acl >= IWF_APN_ACL_MAX) {
                LOGW("config",
                     "mnc%s_apn: ACL full (max %d), ignoring '%s'",
                     mnc, IWF_APN_ACL_MAX, tok);
                break;
            }
            copy_str(r->apn_acl[r->n_apn_acl],
                     sizeof(r->apn_acl[0]), tok);
            r->n_apn_acl++;
        }
    } else
        LOGW("config", "unknown key [roaming_hlr].%s", key);
}

int iwf_config_load(const char *path, iwf_config_t *out)
{
    defaults(out);

    if (!path || !*path) {
        LOGW("config", "no config path provided, using defaults");
        return 0;
    }

    FILE *fp = fopen(path, "r");
    if (!fp) {
        LOGE("config", "cannot open %s: %s", path, strerror(errno));
        return -1;
    }

    char  line[512];
    char  section[64] = "";
    int   lineno = 0;

    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        strip_inline_comment(line);
        char *p = trim(line);
        if (!*p) continue;

        if (*p == '[') {
            char *end = strchr(p, ']');
            if (!end) {
                LOGW("config", "%s:%d: malformed section", path, lineno);
                continue;
            }
            *end = '\0';
            copy_str(section, sizeof(section), p + 1);
            continue;
        }

        char *eq = strchr(p, '=');
        if (!eq) {
            LOGW("config", "%s:%d: no '=' in: %s", path, lineno, p);
            continue;
        }
        *eq = '\0';
        char *key = trim(p);
        char *val = trim(eq + 1);

        if (!strcmp(section, "iwf")) {
            if      (!strcmp(key, "listen_ip"))   copy_str(out->listen_ip, sizeof(out->listen_ip), val);
            else if (!strcmp(key, "listen_port")) out->listen_port = (uint16_t)atoi(val);
            else if (!strcmp(key, "local_ip"))    copy_str(out->local_ip, sizeof(out->local_ip), val);
            else if (!strcmp(key, "synthetic_uli_no_rai"))
                out->synthetic_uli_no_rai = (atoi(val) != 0);
            else if (!strcmp(key, "rat_type"))
                out->rat_type = parse_rat_type(val);
            else if (!strcmp(key, "uli_tac"))
                out->uli_tac = (uint16_t)strtoul(val, NULL, 0);
            else if (!strcmp(key, "uli_eci"))
                out->uli_eci = (uint32_t)strtoul(val, NULL, 0);
            else if (!strcmp(key, "home_imsi_prefix") ||
                       !strcmp(key, "local_imsi_prefix")) {
                home_imsi_prefix_add(out, val);
            } else if (!strcmp(key, "pgw_from_subscription"))
                out->pgw_from_subscription = (atoi(val) != 0);
            else if (!strcmp(key, "pgw_select")) {
                int n = parse_pgw_select(val, out->pgw_select);
                if (n > 0) {
                    out->pgw_n_select = n;
                    out->pgw_select_explicit = 1;
                }
            } else if (!strcmp(key, "pgw_cache_ttl_s")) {
                int ttl = atoi(val);
                out->pgw_cache_ttl_s = (ttl > 0) ? ttl : 300;
            } else if (!strcmp(key, "default_apn")) {
                LOGW("config",
                     "[iwf].default_apn ignored: the default APN is "
                     "subscription data and is taken from the S6a/S6d ULA");
            } else if (!strcmp(key, "pending_timeout_s")) {
                int t = atoi(val);
                out->pending_timeout_s = (t >= 0) ? t : 15;
            } else if (!strcmp(key, "pgw_dns_neg_ttl_s")) {
                int t = atoi(val);
                out->pgw_dns_neg_ttl_s = (t > 0) ? t : 30;
            } else if (!strcmp(key, "pgw_dns_timeout_ms")) {
                int t = atoi(val);
                out->pgw_dns_timeout_ms = (t > 0) ? t : 2000;
            } else LOGW("config", "unknown key [iwf].%s", key);
        } else if (!strcmp(section, "sgsn")) {
            if      (!strcmp(key, "ip"))   copy_str(out->sgsn_ip, sizeof(out->sgsn_ip), val);
            else if (!strcmp(key, "port")) out->sgsn_port = (uint16_t)atoi(val);
            else LOGW("config", "unknown key [sgsn].%s", key);
        } else if (!strcmp(section, "mme")) {
            if      (!strcmp(key, "ip"))   copy_str(out->mme_ip, sizeof(out->mme_ip), val);
            else if (!strcmp(key, "port")) out->mme_port = (uint16_t)atoi(val);
            else LOGW("config", "unknown key [mme].%s", key);
        } else if (!strcmp(section, "sgwc")) {
            if (!strcmp(key, "ip")) {
                copy_str(out->sgwc_ip, sizeof(out->sgwc_ip), val);
            } else if (!strcmp(key, "port")) {
                out->sgwc_port = (uint16_t)atoi(val);
            } else if (strncmp(key, "mnc", 3) == 0 &&
                       key[3] >= '0' && key[3] <= '9' &&
                       key[4] >= '0' && key[4] <= '9' &&
                       key[5] >= '0' && key[5] <= '9' &&
                       key[6] == '\0') {
                /* mncNNN = ip  or  mncNNN = ip:port */
                if (out->sgwc_n_by_mnc >= IWF_SGWC_MAX_BY_MNC) {
                    LOGW("config", "too many [sgwc] mncNNN entries (max %d)",
                         IWF_SGWC_MAX_BY_MNC);
                } else {
                    int i = out->sgwc_n_by_mnc++;
                    copy_str(out->sgwc_by_mnc[i].mnc,
                             sizeof(out->sgwc_by_mnc[i].mnc), key + 3);
                    char buf[80];
                    copy_str(buf, sizeof(buf), val);
                    char *colon = strchr(buf, ':');
                    if (colon) {
                        *colon = '\0';
                        out->sgwc_by_mnc[i].port = (uint16_t)atoi(colon + 1);
                    } else {
                        out->sgwc_by_mnc[i].port = 0;
                    }
                    copy_str(out->sgwc_by_mnc[i].ip,
                             sizeof(out->sgwc_by_mnc[i].ip), buf);
                }
            } else {
                LOGW("config", "unknown key [sgwc].%s", key);
            }
        } else if (!strcmp(section, "smf")) {
            if      (!strcmp(key, "ip"))   copy_str(out->smf_ip, sizeof(out->smf_ip), val);
            else if (!strcmp(key, "teid")) out->smf_teid = (uint32_t)strtoul(val, NULL, 0);
            else LOGW("config", "unknown key [smf].%s", key);
        } else if (!strcmp(section, "logging")) {
            if      (!strcmp(key, "level")) copy_str(out->log_level, sizeof(out->log_level), val);
            else if (!strcmp(key, "file"))  copy_str(out->log_file, sizeof(out->log_file), val);
            else if (!strcmp(key, "trace_imsi"))
                copy_str(out->trace_imsi, sizeof(out->trace_imsi), val);
            else LOGW("config", "unknown key [logging].%s", key);
        } else if (!strcmp(section, "metrics")) {
            if      (!strcmp(key, "enabled")) out->metrics_enabled = (atoi(val) != 0);
            else if (!strcmp(key, "listen_ip"))
                copy_str(out->metrics_listen_ip, sizeof(out->metrics_listen_ip), val);
            else if (!strcmp(key, "listen_port"))
                out->metrics_listen_port = (uint16_t)atoi(val);
            else LOGW("config", "unknown key [metrics].%s", key);
        } else if (!strcmp(section, "map_iwf")) {
            if      (!strcmp(key, "enabled"))        out->map_iwf_enabled  = (atoi(val) != 0);
            else if (!strcmp(key, "msisdn_map_file")) copy_str(out->map_msisdn_map_file, sizeof(out->map_msisdn_map_file), val);
            else if (!strcmp(key, "msisdn_db_uri"))  copy_str(out->map_msisdn_db_uri, sizeof(out->map_msisdn_db_uri), val);
            else if (!strcmp(key, "msisdn_db_name")) copy_str(out->map_msisdn_db_name, sizeof(out->map_msisdn_db_name), val);
            else if (!strcmp(key, "local_gt"))       copy_str(out->map_local_gt, sizeof(out->map_local_gt), val);
            else if (!strcmp(key, "local_pc"))       copy_str(out->map_local_pc, sizeof(out->map_local_pc), val);
            else if (!strcmp(key, "local_ssn"))      out->map_local_ssn    = (uint8_t)atoi(val);
            else if (!strcmp(key, "sccp_ri")) {
                /* gt = Route on GT when GT present (default); ssn = Route on SSN+PC. */
                if (!strcasecmp(val, "gt") || !strcmp(val, "0"))
                    out->map_sccp_ri = IWF_SCCP_RI_GT;
                else if (!strcasecmp(val, "ssn") || !strcasecmp(val, "ssn_pc") ||
                         !strcmp(val, "1"))
                    out->map_sccp_ri = IWF_SCCP_RI_SSN;
                else
                    LOGW("config", "bad [map_iwf].sccp_ri '%s' (want gt|ssn)", val);
            } else if (!strcmp(key, "t_dialogue_ms"))  out->map_t_dialogue_ms = atoi(val);
            else if (!strcmp(key, "isd_before_loc_up"))
                out->map_isd_before_loc_up = (atoi(val) != 0);
            else if (!strcmp(key, "cmd_sock"))
                copy_str(out->map_cmd_sock_path, sizeof(out->map_cmd_sock_path), val);
            else if (!strcmp(key, "msrn_ttl_sec")) {
                int ttl = atoi(val);
                out->map_msrn_ttl_sec = ttl > 0 ? ttl : 30;
            } else if (!strcmp(key, "msrn_consume_on_lookup")) {
                out->map_msrn_consume_on_lookup = (atoi(val) != 0);
            } else if (!strcmp(key, "msrn_pool")) {
                /* msrn_pool = start-end:name  e.g. 990000000000-990000009999:msc1 */
                if (out->map_msrn_n_pools >= IWF_MSRN_MAX_POOLS) {
                    LOGW("config", "too many msrn_pool lines (max %d)", IWF_MSRN_MAX_POOLS);
                } else {
                    char buf[96];
                    copy_str(buf, sizeof(buf), val);
                    char *dash = strchr(buf, '-');
                    char *colon = dash ? strrchr(dash + 1, ':') : NULL;
                    if (!dash || !colon || colon <= dash + 1) {
                        LOGW("config", "bad msrn_pool '%s' (want start-end:name)", val);
                    } else {
                        *dash = '\0';
                        *colon = '\0';
                        const char *start = buf;
                        const char *end = dash + 1;
                        const char *name = colon + 1;
                        int i = out->map_msrn_n_pools++;
                        copy_str(out->map_msrn_pools[i].start,
                                 sizeof(out->map_msrn_pools[i].start), start);
                        copy_str(out->map_msrn_pools[i].end,
                                 sizeof(out->map_msrn_pools[i].end), end);
                        copy_str(out->map_msrn_pools[i].name,
                                 sizeof(out->map_msrn_pools[i].name),
                                 name[0] ? name : "default");
                    }
                }
            } else if (!strcmp(key, "msrn_msc_map")) {
                /* msrn_msc_map = msc_gt:pool_name */
                if (out->map_msrn_n_msc_map >= IWF_MSRN_MAX_MSC_MAPS) {
                    LOGW("config", "too many msrn_msc_map lines (max %d)",
                         IWF_MSRN_MAX_MSC_MAPS);
                } else {
                    char buf[64];
                    copy_str(buf, sizeof(buf), val);
                    char *colon = strchr(buf, ':');
                    if (!colon || colon == buf || !colon[1]) {
                        LOGW("config", "bad msrn_msc_map '%s' (want msc:pool)", val);
                    } else {
                        *colon = '\0';
                        int i = out->map_msrn_n_msc_map++;
                        copy_str(out->map_msrn_msc_map[i].msc_gt,
                                 sizeof(out->map_msrn_msc_map[i].msc_gt), buf);
                        copy_str(out->map_msrn_msc_map[i].pool_name,
                                 sizeof(out->map_msrn_msc_map[i].pool_name),
                                 colon + 1);
                    }
                }
            } else LOGW("config", "unknown key [map_iwf].%s", key);
        } else if (!strcmp(section, "stp")) {
            if      (!strcmp(key, "local_ip"))   copy_str(out->stp_local_ip, sizeof(out->stp_local_ip), val);
            else if (!strcmp(key, "local_port")) out->stp_local_port = (uint16_t)atoi(val);
            else if (!strcmp(key, "ip"))         copy_str(out->stp_ip, sizeof(out->stp_ip), val);
            else if (!strcmp(key, "port"))       out->stp_port = (uint16_t)atoi(val);
            else if (!strcmp(key, "remote_pc"))  copy_str(out->stp_remote_pc, sizeof(out->stp_remote_pc), val);
            else if (!strcmp(key, "routing_context") || !strcmp(key, "rctx"))
                out->stp_routing_context = (uint32_t)strtoul(val, NULL, 0);
            else if (!strcmp(key, "network_indicator") || !strcmp(key, "ni"))
                out->stp_network_indicator = parse_network_indicator(val);
            else LOGW("config", "unknown key [stp].%s", key);
        } else if (!strcmp(section, "diameter_s6d")) {
            if      (!strcmp(key, "peer_ip"))       copy_str(out->diam_peer_ip, sizeof(out->diam_peer_ip), val);
            else if (!strcmp(key, "peer_port"))     out->diam_peer_port = (uint16_t)atoi(val);
            else if (!strcmp(key, "peers"))         diam_peers_split(out, val);
            else if (!strcmp(key, "local_ip"))      copy_str(out->diam_local_ip, sizeof(out->diam_local_ip), val);
            else if (!strcmp(key, "origin_host"))   copy_str(out->diam_origin_host, sizeof(out->diam_origin_host), val);
            else if (!strcmp(key, "origin_host_cs"))
                copy_str(out->diam_origin_host_cs, sizeof(out->diam_origin_host_cs), val);
            else if (!strcmp(key, "origin_realm"))  copy_str(out->diam_origin_realm, sizeof(out->diam_origin_realm), val);
            else if (!strcmp(key, "dest_host"))     copy_str(out->diam_dest_host, sizeof(out->diam_dest_host), val);
            else if (!strcmp(key, "dest_realm"))    copy_str(out->diam_dest_realm, sizeof(out->diam_dest_realm), val);
            else if (!strcmp(key, "product_name"))  copy_str(out->diam_product_name, sizeof(out->diam_product_name), val);
            else if (!strcmp(key, "vendor_id"))     out->diam_vendor_id = (uint32_t)strtoul(val, NULL, 0);
            else if (!strcmp(key, "watchdog_ms"))   out->diam_watchdog_ms = atoi(val);
            else if (!strcmp(key, "request_timeout_ms")) out->diam_request_timeout_ms = atoi(val);
            else LOGW("config", "unknown key [diameter_s6d].%s", key);
        } else if (!strcmp(section, "gsup_server")) {
            if      (!strcmp(key, "enabled"))        out->gsup_server_enabled = (atoi(val) != 0);
            else if (!strcmp(key, "listen_port"))    out->gsup_listen_port = (uint16_t)atoi(val);
            else if (!strcmp(key, "listen_ip"))      gsup_listen_ip_add(out, val);
            else if (!strcmp(key, "listen_ips"))     gsup_listen_ips_split(out, val);
            else if (!strcmp(key, "local_mcc")) {
                copy_str(out->gsup_local_mcc, sizeof(out->gsup_local_mcc), val);
                out->gsup_local_mcc_set = 1;
            }
            else if (!strcmp(key, "local_mnc"))      copy_str(out->gsup_local_mnc, sizeof(out->gsup_local_mnc), val);
            else if (!strcmp(key, "home_imsi_prefix") ||
                     !strcmp(key, "local_imsi_prefix"))
                home_imsi_prefix_add(out, val);
            else if (!strcmp(key, "timeout_ms"))     out->gsup_timeout_ms = atoi(val);
            else if (!strcmp(key, "cs_backend"))     out->gsup_cs_backend = parse_gsup_backend(val);
            else if (!strcmp(key, "ps_backend"))     out->gsup_ps_backend = parse_gsup_backend(val);
            else LOGW("config", "unknown key [gsup_server].%s", key);
        } else if (!strcmp(section, "roaming_hlr")) {
            gsup_roam_key(out, key, val);
#ifdef SMS_IWF_ENABLED
        } else if (!strcmp(section, "sms_iwf")) {
            if      (!strcmp(key, "enabled"))           out->sms_iwf_enabled = (atoi(val) != 0);
            else if (!strcmp(key, "hlr_ssn"))          out->sms_hlr_ssn = (uint8_t)atoi(val);
            else if (!strcmp(key, "local_msc_gt"))     copy_str(out->sms_local_msc_gt, sizeof(out->sms_local_msc_gt), val);
            else if (!strcmp(key, "local_smsc_gt"))    copy_str(out->sms_local_smsc_gt, sizeof(out->sms_local_smsc_gt), val);
            else if (!strcmp(key, "gsup_timeout_ms"))  out->sms_gsup_timeout_ms = atoi(val);
            else if (!strcmp(key, "sri_sm_timeout_ms")) out->sms_sri_sm_timeout_ms = atoi(val);
            else if (!strcmp(key, "fwdsm_timeout_ms")) out->sms_fwdsm_timeout_ms = atoi(val);
            else LOGW("config", "unknown key [sms_iwf].%s", key);
        } else if (!strcmp(section, "gsup_client")) {
            if      (!strcmp(key, "remote_ip"))    copy_str(out->gsup_remote_ip, sizeof(out->gsup_remote_ip), val);
            else if (!strcmp(key, "remote_port")) out->gsup_remote_port = (uint16_t)atoi(val);
            else if (!strcmp(key, "client_name")) copy_str(out->gsup_client_name, sizeof(out->gsup_client_name), val);
            else LOGW("config", "unknown key [gsup_client].%s", key);
        } else if (!strcmp(section, "smpp_server")) {
            if      (!strcmp(key, "bind_ip"))    copy_str(out->smpp_bind_ip, sizeof(out->smpp_bind_ip), val);
            else if (!strcmp(key, "port"))       out->smpp_port = (uint16_t)atoi(val);
            else if (!strcmp(key, "system_id"))  copy_str(out->smpp_system_id, sizeof(out->smpp_system_id), val);
            else if (!strcmp(key, "password"))  copy_str(out->smpp_password, sizeof(out->smpp_password), val);
            else LOGW("config", "unknown key [smpp_server].%s", key);
        } else {
            int pidx = sms_partner_index(out, section);
            if (pidx >= 0) {
                if      (!strcmp(key, "hlr_gt"))
                    copy_str(out->sms_partners[pidx].hlr_gt,
                             sizeof(out->sms_partners[pidx].hlr_gt), val);
                else if (!strcmp(key, "msisdn_prefixes"))
                    copy_str(out->sms_partners[pidx].prefixes_raw,
                             sizeof(out->sms_partners[pidx].prefixes_raw), val);
                else LOGW("config", "unknown key [%s].%s", section, key);
            } else
                LOGW("config", "%s:%d: key '%s' outside any known section", path, lineno, key);
        }
#else
        } else {
            LOGW("config", "%s:%d: key '%s' outside any known section", path, lineno, key);
        }
#endif
    }

    fclose(fp);

    diam_peers_finalize(out);

#ifdef SMS_IWF_ENABLED
    for (int i = 0; i < out->sms_n_partners; i++)
        sms_partner_split_prefixes(out, i);
#endif

    if (out->local_ip[0] == '\0' && strcmp(out->listen_ip, "0.0.0.0") != 0) {
        copy_str(out->local_ip, sizeof(out->local_ip), out->listen_ip);
    }

    /* The home PLMN is never compiled in. Without [gsup_server] local_mcc
     * the placeholder test MCC stays in force and gsup_router_lookup()
     * rejects every IMSI, so say so loudly rather than failing silently. */
    if (out->gsup_server_enabled && !out->gsup_local_mcc_set) {
        LOGE("config",
             "[gsup_server] local_mcc is not set - using placeholder %s; GSUP routing will reject every IMSI until you set your home MCC",
             out->gsup_local_mcc);
    }

    /* Legacy pgw_from_subscription=0 without explicit pgw_select: skip ULA MIP. */
    if (!out->pgw_select_explicit && !out->pgw_from_subscription) {
        out->pgw_select[0] = IWF_PGW_SRC_STATIC;
        out->pgw_select[1] = IWF_PGW_SRC_DNS;
        out->pgw_select[2] = IWF_PGW_SRC_SMF;
        out->pgw_n_select = 3;
    }
    if (out->pgw_n_select <= 0) {
        out->pgw_select[0] = IWF_PGW_SRC_MIP;
        out->pgw_select[1] = IWF_PGW_SRC_DNS;
        out->pgw_select[2] = IWF_PGW_SRC_STATIC;
        out->pgw_select[3] = IWF_PGW_SRC_SMF;
        out->pgw_n_select = 4;
    }
    if (out->pgw_cache_ttl_s <= 0)
        out->pgw_cache_ttl_s = 300;

    return 0;
}

static const char *pgw_src_name(uint8_t src)
{
    switch (src) {
    case IWF_PGW_SRC_MIP:    return "mip";
    case IWF_PGW_SRC_DNS:    return "dns";
    case IWF_PGW_SRC_STATIC: return "static";
    case IWF_PGW_SRC_SMF:    return "smf";
    default:                 return "?";
    }
}

void iwf_config_dump(const iwf_config_t *c)
{
    char sel[64];
    size_t off = 0;
    sel[0] = '\0';
    for (int i = 0; i < c->pgw_n_select && i < IWF_PGW_SELECT_MAX; i++) {
        int n = snprintf(sel + off, sizeof(sel) - off, "%s%s",
                         i ? "," : "", pgw_src_name(c->pgw_select[i]));
        if (n < 0 || (size_t)n >= sizeof(sel) - off)
            break;
        off += (size_t)n;
    }

    LOGI("config",
         "file=%s listen=%s:%u local_ip=%s rat_type=%u uli_tac=0x%04x uli_eci=0x%x "
         "synthetic_uli_no_rai=%d "
         "sgsn=%s:%u mme=%s:%u sgwc=%s:%u smf=%s teid=%u "
         "pgw_select=%s pgw_cache_ttl_s=%d log=%s/%s",
         c->cfg_path[0] ? c->cfg_path : "-",
         c->listen_ip, c->listen_port,
         c->local_ip[0] ? c->local_ip : "(unset)",
         (unsigned)c->rat_type, (unsigned)c->uli_tac, (unsigned)c->uli_eci,
         c->synthetic_uli_no_rai,
         c->sgsn_ip, (unsigned)c->sgsn_port,
         c->mme_ip, (unsigned)c->mme_port,
         c->sgwc_ip, c->sgwc_port,
         c->smf_ip[0] ? c->smf_ip : "(unset)", (unsigned)c->smf_teid,
         sel[0] ? sel : "-",
         c->pgw_cache_ttl_s,
         c->log_level, c->log_file);
    if (c->sgwc_n_by_mnc > 0) {
        for (int i = 0; i < c->sgwc_n_by_mnc; i++) {
            LOGI("config",
                 "sgwc mnc%s -> %s:%u",
                 c->sgwc_by_mnc[i].mnc,
                 c->sgwc_by_mnc[i].ip,
                 (unsigned)(c->sgwc_by_mnc[i].port
                            ? c->sgwc_by_mnc[i].port : c->sgwc_port));
        }
    }

    if (c->map_iwf_enabled) {
        LOGI("config",
             "map_iwf: local_gt=%s local_pc=%s ssn=%u sccp_ri=%s t_dialogue=%dms "
             "isd_before_loc_up=%d cmd_sock=%s",
             c->map_local_gt[0] ? c->map_local_gt : "(unset)",
             c->map_local_pc[0] ? c->map_local_pc : "(unset)",
             (unsigned)c->map_local_ssn,
             c->map_sccp_ri == IWF_SCCP_RI_SSN ? "ssn" : "gt",
             c->map_t_dialogue_ms,
             c->map_isd_before_loc_up,
             c->map_cmd_sock_path[0] ? c->map_cmd_sock_path : "(default)");
        if (c->map_msrn_n_pools > 0) {
            LOGI("config",
                 "map_iwf: msrn pools=%d msc_maps=%d ttl=%ds consume_on_lookup=%d",
                 c->map_msrn_n_pools, c->map_msrn_n_msc_map,
                 c->map_msrn_ttl_sec, c->map_msrn_consume_on_lookup);
        }
        {
            char lports[24];
            if (c->stp_local_port)
                snprintf(lports, sizeof(lports), "%u",
                         (unsigned)c->stp_local_port);
            else
                strcpy(lports, "ephemeral");
            LOGI("config", "map_iwf: stp M3UA bind %s:%s -> peer %s:%u remote_pc=%s rctx=%u ni=%u",
                 c->stp_local_ip[0] ? c->stp_local_ip : "(any)",
                 lports, c->stp_ip, c->stp_port,
                 c->stp_remote_pc[0] ? c->stp_remote_pc : "(unset)",
                 (unsigned)c->stp_routing_context,
                 (unsigned)c->stp_network_indicator);
        }
        LOGI("config", "map_iwf: diameter peers=%d local=%s origin=%s cs_origin=%s realm=%s "
                       "dest=%s/%s watchdog=%dms timeout=%dms",
             c->diam_n_peers,
             c->diam_local_ip[0] ? c->diam_local_ip
                                   : (c->local_ip[0] ? c->local_ip : "(any)"),
             c->diam_origin_host[0]  ? c->diam_origin_host  : "(unset)",
             c->diam_origin_host_cs[0] ? c->diam_origin_host_cs : "(same)",
             c->diam_origin_realm[0] ? c->diam_origin_realm : "(unset)",
             c->diam_dest_host[0]    ? c->diam_dest_host    : "(unset)",
             c->diam_dest_realm[0]   ? c->diam_dest_realm   : "(unset)",
             c->diam_watchdog_ms, c->diam_request_timeout_ms);
        for (int i = 0; i < c->diam_n_peers; i++)
            LOGI("config", "map_iwf: diameter peer[%d]=%s:%u",
                 i, c->diam_peers[i].ip, (unsigned)c->diam_peers[i].port);
    } else {
        LOGI("config", "map_iwf: disabled (set [map_iwf].enabled = 1 to bring it up)");
    }
    if (c->gsup_server_enabled) {
        LOGI("config", "gsup_server: listen_port=%u local_mnc=%s timeout=%dms "
                       "cs_backend=%s ps_backend=%s",
             (unsigned)c->gsup_listen_port,
             c->gsup_local_mnc[0] ? c->gsup_local_mnc : "(unset)",
             c->gsup_timeout_ms,
             c->gsup_cs_backend == GSUP_BACKEND_MAP ? "map" : "diameter",
             c->gsup_ps_backend == GSUP_BACKEND_MAP ? "map" : "diameter");
    }
    if (c->n_home_imsi_prefix > 0) {
        char list[256];
        size_t off = 0;
        list[0] = '\0';
        for (int i = 0; i < c->n_home_imsi_prefix; i++) {
            int n = snprintf(list + off, sizeof(list) - off, "%s%s",
                             i ? "," : "", c->home_imsi_prefix[i]);
            if (n < 0 || (size_t)n >= sizeof(list) - off)
                break;
            off += (size_t)n;
        }
        LOGI("config", "home_imsi_prefix=%s (bare APN); others get APN FQDN",
             list);
    }
    for (int i = 0; i < c->gsup_n_roam_routes; i++) {
        const typeof(c->gsup_roam_routes[0]) *r = &c->gsup_roam_routes[i];
        if (r->n_apn_acl <= 0)
            continue;
        char list[256];
        size_t off = 0;
        list[0] = '\0';
        for (int a = 0; a < r->n_apn_acl; a++) {
            int n = snprintf(list + off, sizeof(list) - off, "%s%s",
                             a ? "," : "", r->apn_acl[a]);
            if (n < 0 || (size_t)n >= sizeof(list) - off)
                break;
            off += (size_t)n;
        }
        LOGI("config", "roaming_hlr mnc%s apn_acl=%s", r->mnc, list);
    }
#ifdef SMS_IWF_ENABLED
    if (c->sms_iwf_enabled) {
        LOGI("config", "sms_iwf: msc_gt=%s smsc_gt=%s hlr_ssn=%u gsup_timeout=%dms",
             c->sms_local_msc_gt, c->sms_local_smsc_gt,
             (unsigned)c->sms_hlr_ssn, c->sms_gsup_timeout_ms);
        LOGI("config", "sms_iwf: gsup=%s:%u smpp=%s:%u partners=%d",
             c->gsup_remote_ip, (unsigned)c->gsup_remote_port,
             c->smpp_bind_ip, (unsigned)c->smpp_port, c->sms_n_partners);
    } else {
        LOGI("config", "sms_iwf: disabled (set [sms_iwf].enabled = 1; build SMS_IWF_ENABLED=1)");
    }
#endif
}

/* Find a [roaming_hlr] route by 3-digit MNC string key. */
static int roam_route_by_mnc_key(const iwf_config_t *cfg, const char *mnc_key)
{
    for (int i = 0; i < cfg->gsup_n_roam_routes; i++)
        if (!strcmp(cfg->gsup_roam_routes[i].mnc, mnc_key))
            return i;
    return -1;
}

int iwf_config_roam_pgw(const iwf_config_t *cfg, const char *imsi,
                        const char **out_ip, const char **out_fqdn)
{
    if (out_ip)   *out_ip   = NULL;
    if (out_fqdn) *out_fqdn = NULL;
    if (!cfg || !imsi || strlen(imsi) < 5)
        return 0;

    /* Match the IMSI PLMN against configured routes. Try the 2-digit MNC
     * first, then the 3-digit interpretation — same precedence as the GSUP
     * router so PS data and signalling agree on the partner. */
    char key[4];
    snprintf(key, sizeof(key), "%03u",
             (unsigned)((imsi[3] - '0') * 10 + (imsi[4] - '0')));
    int idx = roam_route_by_mnc_key(cfg, key);
    if (idx < 0 && strlen(imsi) >= 6 &&
        imsi[5] >= '0' && imsi[5] <= '9') {
        snprintf(key, sizeof(key), "%03u",
                 (unsigned)((imsi[3] - '0') * 100 + (imsi[4] - '0') * 10 +
                            (imsi[5] - '0')));
        idx = roam_route_by_mnc_key(cfg, key);
    }
    if (idx < 0)
        return 0;

    const char *ip   = cfg->gsup_roam_routes[idx].pgw_ip;
    const char *fqdn = cfg->gsup_roam_routes[idx].pgw_fqdn;
    if (!ip[0] && !fqdn[0])
        return 0;
    if (out_ip)   *out_ip   = ip;
    if (out_fqdn) *out_fqdn = fqdn;
    return 1;
}

/* Resolve [roaming_hlr] route index for an IMSI PLMN (2- then 3-digit MNC). */
static int roam_route_idx_for_imsi(const iwf_config_t *cfg, const char *imsi)
{
    if (!cfg || !imsi || strlen(imsi) < 5)
        return -1;
    char key[4];
    snprintf(key, sizeof(key), "%03u",
             (unsigned)((imsi[3] - '0') * 10 + (imsi[4] - '0')));
    int idx = roam_route_by_mnc_key(cfg, key);
    if (idx < 0 && strlen(imsi) >= 6 &&
        imsi[5] >= '0' && imsi[5] <= '9') {
        snprintf(key, sizeof(key), "%03u",
                 (unsigned)((imsi[3] - '0') * 100 + (imsi[4] - '0') * 10 +
                            (imsi[5] - '0')));
        idx = roam_route_by_mnc_key(cfg, key);
    }
    return idx;
}

int iwf_config_pgw_select(const iwf_config_t *cfg, const char *imsi,
                          uint8_t out[IWF_PGW_SELECT_MAX])
{
    if (!cfg || !out)
        return 0;
    int idx = roam_route_idx_for_imsi(cfg, imsi);
    if (idx >= 0 && cfg->gsup_roam_routes[idx].pgw_n_select > 0) {
        int n = cfg->gsup_roam_routes[idx].pgw_n_select;
        if (n > IWF_PGW_SELECT_MAX)
            n = IWF_PGW_SELECT_MAX;
        memcpy(out, cfg->gsup_roam_routes[idx].pgw_select, (size_t)n);
        return n;
    }
    int n = cfg->pgw_n_select;
    if (n <= 0) {
        out[0] = IWF_PGW_SRC_MIP;
        out[1] = IWF_PGW_SRC_DNS;
        out[2] = IWF_PGW_SRC_STATIC;
        out[3] = IWF_PGW_SRC_SMF;
        return 4;
    }
    if (n > IWF_PGW_SELECT_MAX)
        n = IWF_PGW_SELECT_MAX;
    memcpy(out, cfg->pgw_select, (size_t)n);
    return n;
}

static int sgwc_by_mnc_idx(const iwf_config_t *cfg, const char *mnc_key)
{
    for (int i = 0; i < cfg->sgwc_n_by_mnc; i++)
        if (!strcmp(cfg->sgwc_by_mnc[i].mnc, mnc_key))
            return i;
    return -1;
}

static int sgwc_idx_for_imsi(const iwf_config_t *cfg, const char *imsi)
{
    if (!cfg || !imsi || strlen(imsi) < 5)
        return -1;
    char key[4];
    snprintf(key, sizeof(key), "%03u",
             (unsigned)((imsi[3] - '0') * 10 + (imsi[4] - '0')));
    int idx = sgwc_by_mnc_idx(cfg, key);
    if (idx < 0 && strlen(imsi) >= 6 &&
        imsi[5] >= '0' && imsi[5] <= '9') {
        snprintf(key, sizeof(key), "%03u",
                 (unsigned)((imsi[3] - '0') * 100 + (imsi[4] - '0') * 10 +
                            (imsi[5] - '0')));
        idx = sgwc_by_mnc_idx(cfg, key);
    }
    return idx;
}

int iwf_config_sgwc_for_imsi(const iwf_config_t *cfg, const char *imsi,
                             char *ip_out, size_t ip_cap, uint16_t *port_out)
{
    if (!cfg || !ip_out || !ip_cap || !port_out)
        return -1;
    ip_out[0] = '\0';
    *port_out = cfg->sgwc_port ? cfg->sgwc_port : (uint16_t)2123;

    int idx = sgwc_idx_for_imsi(cfg, imsi);
    if (idx >= 0 && cfg->sgwc_by_mnc[idx].ip[0]) {
        copy_str(ip_out, ip_cap, cfg->sgwc_by_mnc[idx].ip);
        if (cfg->sgwc_by_mnc[idx].port)
            *port_out = cfg->sgwc_by_mnc[idx].port;
        return 0;
    }
    if (!cfg->sgwc_ip[0])
        return -1;
    copy_str(ip_out, ip_cap, cfg->sgwc_ip);
    return 0;
}

int iwf_config_visited_plmn(const iwf_config_t *cfg,
                            uint16_t *mcc, uint16_t *mnc)
{
    if (!cfg || !mcc || !mnc)
        return -1;
    if (!cfg->gsup_local_mnc[0])
        return -1;
    if (!cfg->gsup_local_mcc[0])
        return -1;
    *mcc = (uint16_t)atoi(cfg->gsup_local_mcc);
    *mnc = (uint16_t)atoi(cfg->gsup_local_mnc);
    return 0;
}

int iwf_config_imsi_is_home(const iwf_config_t *cfg, const char *imsi)
{
    if (!cfg || !imsi || strlen(imsi) < 5)
        return 0;

    /* Explicit home IMSI prefix list wins when configured. */
    if (cfg->n_home_imsi_prefix > 0) {
        for (int i = 0; i < cfg->n_home_imsi_prefix; i++) {
            size_t pl = strlen(cfg->home_imsi_prefix[i]);
            if (pl && strncmp(imsi, cfg->home_imsi_prefix[i], pl) == 0)
                return 1;
        }
        return 0;
    }

    /* Fallback: IMSI PLMN matches visited local_mcc/local_mnc. */
    uint16_t vmcc = 0, vmnc = 0;
    if (iwf_config_visited_plmn(cfg, &vmcc, &vmnc) < 0)
        return 0;
    unsigned a = 0, b = 0, c = 0, d = 0, e = 0;
    if (sscanf(imsi, "%1u%1u%1u%1u%1u", &a, &b, &c, &d, &e) != 5)
        return 0;
    uint16_t imsi_mcc = (uint16_t)(a * 100u + b * 10u + c);
    uint16_t imsi_mnc2 = (uint16_t)(d * 10u + e);
    if (imsi_mcc != vmcc)
        return 0;
    if (imsi_mnc2 == vmnc || imsi_mnc2 == (vmnc % 100))
        return 1;
    if (strlen(imsi) >= 6 && isdigit((unsigned char)imsi[5])) {
        uint16_t imsi_mnc3 = (uint16_t)(d * 100u + e * 10u +
                                        (unsigned)(imsi[5] - '0'));
        if (imsi_mnc3 == vmnc)
            return 1;
    }
    return 0;
}

int iwf_config_imsi_is_roamer(const iwf_config_t *cfg, const char *imsi)
{
    if (!cfg || !imsi || strlen(imsi) < 5)
        return 0;
    /* Need either an explicit prefix list or visited PLMN to classify. */
    if (cfg->n_home_imsi_prefix <= 0) {
        uint16_t dmcc = 0, dmnc = 0;
        if (iwf_config_visited_plmn(cfg, &dmcc, &dmnc) < 0)
            return 0;
    }
    return !iwf_config_imsi_is_home(cfg, imsi);
}

void iwf_apn_for_s4(const iwf_config_t *cfg, const char *imsi,
                    const char *src_apn, char *out, size_t out_cap)
{
    if (!out || !out_cap)
        return;
    out[0] = '\0';
    if (!src_apn || !src_apn[0])
        return;
    strncpy(out, src_apn, out_cap - 1);
    out[out_cap - 1] = '\0';
    iwf_apn_normalize(out);

    /* Home / local subscribers: SGW-C expects bare APN-NI (no OI). */
    if (!iwf_config_imsi_is_roamer(cfg, imsi)) {
        char *cut = strstr(out, ".mnc");
        if (!cut)
            cut = strstr(out, ".apn.epc.");
        if (!cut)
            cut = strstr(out, ".gprs");
        if (!cut)
            cut = strstr(out, ".3gppnetwork.org");
        if (cut)
            *cut = '\0';
        return;
    }

    /* Roamers: already an OI-bearing FQDN — keep as-is. */
    if (strstr(out, ".mnc") || strstr(out, ".gprs") ||
        strstr(out, ".3gppnetwork.org"))
        return;

    if (!imsi || strlen(imsi) < 5)
        return;

    unsigned a = 0, b = 0, c = 0, d = 0, e = 0;
    if (sscanf(imsi, "%1u%1u%1u%1u%1u", &a, &b, &c, &d, &e) != 5)
        return;
    uint16_t mcc = (uint16_t)(a * 100u + b * 10u + c);
    /* Prefer configured partner 3-digit MNC; else zero-pad IMSI 2-digit MNC
     * (00102 -> mnc002, 00103 -> mnc003 — matches MME / VPP NWI form). */
    uint16_t mnc = (uint16_t)(d * 10u + e);
    int ridx = roam_route_idx_for_imsi(cfg, imsi);
    if (ridx >= 0)
        mnc = (uint16_t)atoi(cfg->gsup_roam_routes[ridx].mnc);
    else {
        int sidx = sgwc_idx_for_imsi(cfg, imsi);
        if (sidx >= 0)
            mnc = (uint16_t)atoi(cfg->sgwc_by_mnc[sidx].mnc);
    }

    char oi[48];
    snprintf(oi, sizeof(oi), ".mnc%03u.mcc%03u.gprs",
             (unsigned)mnc, (unsigned)mcc);
    size_t al = strlen(out);
    size_t ol = strlen(oi);
    if (al + ol + 1 > out_cap)
        return;
    memcpy(out + al, oi, ol + 1);
}

/* Match request APN against an ACL entry (exact or NI prefix before '.'). */
static int apn_matches_acl_entry(const char *apn, const char *entry)
{
    if (!apn || !entry || !entry[0])
        return 0;
    if (!strcasecmp(apn, entry))
        return 1;
    size_t el = strlen(entry);
    if (strncasecmp(apn, entry, el) == 0 &&
        (apn[el] == '\0' || apn[el] == '.'))
        return 1;
    return 0;
}

int iwf_config_apn_allowed(const iwf_config_t *cfg, const char *imsi,
                           const char *apn)
{
    if (!cfg || !apn || !apn[0])
        return 1; /* empty handled elsewhere */
    int idx = roam_route_idx_for_imsi(cfg, imsi);
    if (idx < 0)
        return 1; /* no PLMN route → no ACL → allow all */
    const typeof(cfg->gsup_roam_routes[0]) *r = &cfg->gsup_roam_routes[idx];
    if (r->n_apn_acl <= 0)
        return 1;
    for (int i = 0; i < r->n_apn_acl; i++) {
        if (apn_matches_acl_entry(apn, r->apn_acl[i]))
            return 1;
    }
    return 0;
}

int iwf_config_apn_epc_fqdn(const iwf_config_t *cfg, const char *imsi,
                            const char *apn, char *out, size_t out_cap)
{
    if (!out || !out_cap || !imsi || strlen(imsi) < 5 || !apn || !apn[0])
        return -1;
    out[0] = '\0';

    /* APN-NI only (strip OI / epc suffix if present). */
    char ni[IWF_APN_ACL_NAME_MAX];
    copy_str(ni, sizeof(ni), apn);
    iwf_apn_normalize(ni);
    char *cut = strstr(ni, ".mnc");
    if (!cut)
        cut = strstr(ni, ".apn.epc.");
    if (!cut)
        cut = strstr(ni, ".gprs");
    if (cut)
        *cut = '\0';
    if (!ni[0])
        return -1;

    unsigned a = 0, b = 0, c = 0, d = 0, e = 0;
    if (sscanf(imsi, "%1u%1u%1u%1u%1u", &a, &b, &c, &d, &e) != 5)
        return -1;
    uint16_t mcc = (uint16_t)(a * 100u + b * 10u + c);
    uint16_t mnc = (uint16_t)(d * 10u + e);
    int ridx = roam_route_idx_for_imsi(cfg, imsi);
    if (ridx >= 0)
        mnc = (uint16_t)atoi(cfg->gsup_roam_routes[ridx].mnc);
    else if (strlen(imsi) >= 6 && imsi[5] >= '0' && imsi[5] <= '9')
        mnc = (uint16_t)(d * 100u + e * 10u + (unsigned)(imsi[5] - '0'));

    int n = snprintf(out, out_cap,
                     "%s.apn.epc.mnc%03u.mcc%03u.3gppnetwork.org",
                     ni, (unsigned)mnc, (unsigned)mcc);
    if (n < 0 || (size_t)n >= out_cap) {
        out[0] = '\0';
        return -1;
    }
    return 0;
}
