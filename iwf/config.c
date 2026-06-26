#include "config.h"
#include "logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    strncpy(c->log_level, "info", sizeof(c->log_level) - 1);
    strncpy(c->log_file, "-", sizeof(c->log_file) - 1);
    c->synthetic_uli_no_rai = 0;
    /* Open5GS SMF only accepts EUTRAN (6) and WLAN (3); UTRAN (1) is rejected
     * with "Unknown RAT Type" -> SGW-C surfaces it as GTP cause 70.
     * Default to EUTRAN so the IWF works against vanilla Open5GS out of the box. */
    c->rat_type = 6;

    strncpy(c->map_cmd_sock_path, "/tmp/iwf_cmd.sock", sizeof(c->map_cmd_sock_path) - 1);
    c->map_cmd_sock_path[sizeof(c->map_cmd_sock_path) - 1] = '\0';

    /* MAP-IWF: disabled by default - existing GTP-only deployments need no changes. */
    c->map_iwf_enabled    = 0;
    c->map_local_ssn      = 149;
    c->map_t_dialogue_ms  = 10000;
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
    strncpy(c->gsup_local_mnc, "012", sizeof(c->gsup_local_mnc) - 1);
    c->gsup_timeout_ms       = 10000;

#ifdef SMS_IWF_ENABLED
    c->sms_iwf_enabled       = 0;
    c->sms_hlr_ssn           = 6;
    strncpy(c->sms_local_msc_gt,  "1234567890000", sizeof(c->sms_local_msc_gt) - 1);
    strncpy(c->sms_local_smsc_gt, "1234567890006", sizeof(c->sms_local_smsc_gt) - 1);
    c->sms_gsup_timeout_ms   = 3000;
    c->sms_sri_sm_timeout_ms = 5000;
    c->sms_fwdsm_timeout_ms  = 10000;
    strncpy(c->gsup_remote_ip, "127.0.0.1", sizeof(c->gsup_remote_ip) - 1);
    c->gsup_remote_port      = 4222;
    strncpy(c->gsup_client_name, "IWF-SMS", sizeof(c->gsup_client_name) - 1);
    strncpy(c->smpp_bind_ip, "127.0.0.1", sizeof(c->smpp_bind_ip) - 1);
    c->smpp_port             = 2777;
    strncpy(c->smpp_system_id, "iwf", sizeof(c->smpp_system_id) - 1);
    strncpy(c->smpp_password, "changeme", sizeof(c->smpp_password) - 1);
#endif
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

/* Parse [roaming_hlr] keys: mnc035_hlr_gt, mnc035_ssn, mnc035_src_ip, ... */
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
    else if (!strcmp(p, "dest_realm"))
        copy_str(out->gsup_roam_routes[idx].dest_realm,
                 sizeof(out->gsup_roam_routes[idx].dest_realm), val);
    else if (!strcmp(p, "dest_host"))
        copy_str(out->gsup_roam_routes[idx].dest_host,
                 sizeof(out->gsup_roam_routes[idx].dest_host), val);
    else if (!strcmp(p, "diameter"))
        out->gsup_roam_routes[idx].use_diameter = (atoi(val) != 0);
    else
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
            else LOGW("config", "unknown key [iwf].%s", key);
        } else if (!strcmp(section, "sgsn")) {
            if      (!strcmp(key, "ip"))   copy_str(out->sgsn_ip, sizeof(out->sgsn_ip), val);
            else if (!strcmp(key, "port")) out->sgsn_port = (uint16_t)atoi(val);
            else LOGW("config", "unknown key [sgsn].%s", key);
        } else if (!strcmp(section, "mme")) {
            if      (!strcmp(key, "ip"))   copy_str(out->mme_ip, sizeof(out->mme_ip), val);
            else if (!strcmp(key, "port")) out->mme_port = (uint16_t)atoi(val);
            else LOGW("config", "unknown key [mme].%s", key);
        } else if (!strcmp(section, "sgwc")) {
            if      (!strcmp(key, "ip"))   copy_str(out->sgwc_ip, sizeof(out->sgwc_ip), val);
            else if (!strcmp(key, "port")) out->sgwc_port = (uint16_t)atoi(val);
            else LOGW("config", "unknown key [sgwc].%s", key);
        } else if (!strcmp(section, "smf")) {
            if      (!strcmp(key, "ip"))   copy_str(out->smf_ip, sizeof(out->smf_ip), val);
            else if (!strcmp(key, "teid")) out->smf_teid = (uint32_t)strtoul(val, NULL, 0);
            else LOGW("config", "unknown key [smf].%s", key);
        } else if (!strcmp(section, "logging")) {
            if      (!strcmp(key, "level")) copy_str(out->log_level, sizeof(out->log_level), val);
            else if (!strcmp(key, "file"))  copy_str(out->log_file, sizeof(out->log_file), val);
            else LOGW("config", "unknown key [logging].%s", key);
        } else if (!strcmp(section, "map_iwf")) {
            if      (!strcmp(key, "enabled"))        out->map_iwf_enabled  = (atoi(val) != 0);
            else if (!strcmp(key, "local_gt"))       copy_str(out->map_local_gt, sizeof(out->map_local_gt), val);
            else if (!strcmp(key, "local_pc"))       copy_str(out->map_local_pc, sizeof(out->map_local_pc), val);
            else if (!strcmp(key, "local_ssn"))      out->map_local_ssn    = (uint8_t)atoi(val);
            else if (!strcmp(key, "t_dialogue_ms"))  out->map_t_dialogue_ms = atoi(val);
            else if (!strcmp(key, "cmd_sock"))
                copy_str(out->map_cmd_sock_path, sizeof(out->map_cmd_sock_path), val);
            else LOGW("config", "unknown key [map_iwf].%s", key);
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
            else if (!strcmp(key, "local_mnc"))      copy_str(out->gsup_local_mnc, sizeof(out->gsup_local_mnc), val);
            else if (!strcmp(key, "timeout_ms"))     out->gsup_timeout_ms = atoi(val);
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
    return 0;
}

void iwf_config_dump(const iwf_config_t *c)
{
    LOGI("config",
         "file=%s listen=%s:%u local_ip=%s rat_type=%u synthetic_uli_no_rai=%d "
         "sgsn=%s:%u mme=%s:%u sgwc=%s:%u smf=%s teid=%u log=%s/%s",
         c->cfg_path[0] ? c->cfg_path : "-",
         c->listen_ip, c->listen_port,
         c->local_ip[0] ? c->local_ip : "(unset)",
         (unsigned)c->rat_type, c->synthetic_uli_no_rai,
         c->sgsn_ip, (unsigned)c->sgsn_port,
         c->mme_ip, (unsigned)c->mme_port,
         c->sgwc_ip, c->sgwc_port,
         c->smf_ip[0] ? c->smf_ip : "(unset)", (unsigned)c->smf_teid,
         c->log_level, c->log_file);

    if (c->map_iwf_enabled) {
        LOGI("config", "map_iwf: local_gt=%s local_pc=%s ssn=%u t_dialogue=%dms cmd_sock=%s",
             c->map_local_gt[0] ? c->map_local_gt : "(unset)",
             c->map_local_pc[0] ? c->map_local_pc : "(unset)",
             (unsigned)c->map_local_ssn, c->map_t_dialogue_ms,
             c->map_cmd_sock_path[0] ? c->map_cmd_sock_path : "(default)");
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
