#include "config.h"
#include "logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

static void defaults(iwf_config_t *c)
{
    memset(c, 0, sizeof(*c));
    strncpy(c->listen_ip, "0.0.0.0", sizeof(c->listen_ip) - 1);
    c->listen_port = 2123;
    c->local_ip[0] = '\0';
    strncpy(c->sgsn_ip, "0.0.0.0", sizeof(c->sgsn_ip) - 1);
    strncpy(c->sgwc_ip, "127.0.0.1", sizeof(c->sgwc_ip) - 1);
    c->sgwc_port = 2123;
    strncpy(c->log_level, "info", sizeof(c->log_level) - 1);
    strncpy(c->log_file, "-", sizeof(c->log_file) - 1);
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
            else LOGW("config", "unknown key [iwf].%s", key);
        } else if (!strcmp(section, "sgsn")) {
            if (!strcmp(key, "ip")) copy_str(out->sgsn_ip, sizeof(out->sgsn_ip), val);
            else LOGW("config", "unknown key [sgsn].%s", key);
        } else if (!strcmp(section, "sgwc")) {
            if      (!strcmp(key, "ip"))   copy_str(out->sgwc_ip, sizeof(out->sgwc_ip), val);
            else if (!strcmp(key, "port")) out->sgwc_port = (uint16_t)atoi(val);
            else LOGW("config", "unknown key [sgwc].%s", key);
        } else if (!strcmp(section, "logging")) {
            if      (!strcmp(key, "level")) copy_str(out->log_level, sizeof(out->log_level), val);
            else if (!strcmp(key, "file"))  copy_str(out->log_file, sizeof(out->log_file), val);
            else LOGW("config", "unknown key [logging].%s", key);
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
    LOGI("config", "listen=%s:%u local_ip=%s sgsn=%s sgwc=%s:%u log=%s/%s",
         c->listen_ip, c->listen_port,
         c->local_ip[0] ? c->local_ip : "(unset)",
         c->sgsn_ip, c->sgwc_ip, c->sgwc_port,
         c->log_level, c->log_file);
}
