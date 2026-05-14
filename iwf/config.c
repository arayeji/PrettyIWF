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
    c->diam_peer_port     = 3868;
    c->diam_watchdog_ms   = 30000;
    c->diam_request_timeout_ms = 10000;
    c->diam_vendor_id     = 10415;  /* 3GPP */
    strncpy(c->diam_product_name, "iwf",  sizeof(c->diam_product_name) - 1);
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
            else LOGW("config", "unknown key [stp].%s", key);
        } else if (!strcmp(section, "diameter_s6d")) {
            if      (!strcmp(key, "peer_ip"))       copy_str(out->diam_peer_ip, sizeof(out->diam_peer_ip), val);
            else if (!strcmp(key, "peer_port"))     out->diam_peer_port = (uint16_t)atoi(val);
            else if (!strcmp(key, "origin_host"))   copy_str(out->diam_origin_host, sizeof(out->diam_origin_host), val);
            else if (!strcmp(key, "origin_realm"))  copy_str(out->diam_origin_realm, sizeof(out->diam_origin_realm), val);
            else if (!strcmp(key, "dest_host"))     copy_str(out->diam_dest_host, sizeof(out->diam_dest_host), val);
            else if (!strcmp(key, "dest_realm"))    copy_str(out->diam_dest_realm, sizeof(out->diam_dest_realm), val);
            else if (!strcmp(key, "product_name"))  copy_str(out->diam_product_name, sizeof(out->diam_product_name), val);
            else if (!strcmp(key, "vendor_id"))     out->diam_vendor_id = (uint32_t)strtoul(val, NULL, 0);
            else if (!strcmp(key, "watchdog_ms"))   out->diam_watchdog_ms = atoi(val);
            else if (!strcmp(key, "request_timeout_ms")) out->diam_request_timeout_ms = atoi(val);
            else LOGW("config", "unknown key [diameter_s6d].%s", key);
        } else {
            LOGW("config", "%s:%d: key '%s' outside any known section", path, lineno, key);
        }
    }

    fclose(fp);

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
            LOGI("config", "map_iwf: stp M3UA bind %s:%s -> peer %s:%u remote_pc=%s rctx=%u",
                 c->stp_local_ip[0] ? c->stp_local_ip : "(any)",
                 lports, c->stp_ip, c->stp_port,
                 c->stp_remote_pc[0] ? c->stp_remote_pc : "(unset)",
                 (unsigned)c->stp_routing_context);
        }
        LOGI("config", "map_iwf: diameter peer=%s:%u origin=%s/%s dest=%s/%s "
                       "watchdog=%dms timeout=%dms",
             c->diam_peer_ip[0] ? c->diam_peer_ip : "(unset)",
             c->diam_peer_port,
             c->diam_origin_host[0]  ? c->diam_origin_host  : "(unset)",
             c->diam_origin_realm[0] ? c->diam_origin_realm : "(unset)",
             c->diam_dest_host[0]    ? c->diam_dest_host    : "(unset)",
             c->diam_dest_realm[0]   ? c->diam_dest_realm   : "(unset)",
             c->diam_watchdog_ms, c->diam_request_timeout_ms);
    } else {
        LOGI("config", "map_iwf: disabled (set [map_iwf].enabled = 1 to bring it up)");
    }
}
