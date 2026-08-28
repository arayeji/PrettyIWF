/*
 * config_reload.c - SIGHUP config reload (runtime tunables without restart).
 */

#include "config.h"
#include "runtime.h"
#include "logging.h"
#include "imsi_trace.h"
#include "msrn_pool.h"
#include "subscr_cache.h"
#include "pgw_dns.h"
#include "isup_call.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

static int streq(const char *a, const char *b)
{
    return strcmp(a ? a : "", b ? b : "") == 0;
}

static void rt_update_gtp_peer(struct sockaddr_in *dst, const char *ip,
                               uint16_t port)
{
    memset(dst, 0, sizeof(*dst));
    dst->sin_family = AF_INET;
    dst->sin_port   = htons(port);
    if (ip && ip[0] && strcmp(ip, "0.0.0.0") != 0)
        (void)inet_pton(AF_INET, ip, &dst->sin_addr);
}

static bool msrn_cfg_equal(const iwf_config_t *a, const iwf_config_t *b)
{
    if (a->map_msrn_n_pools != b->map_msrn_n_pools ||
        a->map_msrn_n_msc_map != b->map_msrn_n_msc_map ||
        a->map_msrn_consume_on_lookup != b->map_msrn_consume_on_lookup)
        return false;
    for (int i = 0; i < a->map_msrn_n_pools; i++) {
        if (!streq(a->map_msrn_pools[i].name, b->map_msrn_pools[i].name) ||
            !streq(a->map_msrn_pools[i].start, b->map_msrn_pools[i].start) ||
            !streq(a->map_msrn_pools[i].end, b->map_msrn_pools[i].end))
            return false;
    }
    for (int i = 0; i < a->map_msrn_n_msc_map; i++) {
        if (!streq(a->map_msrn_msc_map[i].msc_gt, b->map_msrn_msc_map[i].msc_gt) ||
            !streq(a->map_msrn_msc_map[i].pool_name,
                    b->map_msrn_msc_map[i].pool_name))
            return false;
    }
    return true;
}

/* Bind / socket-affecting options: updated in memory but not applied until
 * process restart. */
static void restart_reason_add(char *why, size_t cap, size_t *off,
                               const char *tag)
{
    if (!tag || !*tag || !why || !off || *off >= cap) return;
    int n = snprintf(why + *off, cap - *off, *off ? "; %s" : "%s", tag);
    if (n > 0) *off += (size_t)n;
}

static bool cfg_needs_restart(const iwf_config_t *old, const iwf_config_t *nc,
                              char *why, size_t cap)
{
    size_t off = 0;
    why[0] = '\0';

    if (!streq(old->listen_ip, nc->listen_ip) ||
        old->listen_port != nc->listen_port ||
        !streq(old->local_ip, nc->local_ip))
        restart_reason_add(why, cap, &off, "udp_listen");
    if (old->gsup_server_enabled != nc->gsup_server_enabled ||
        old->gsup_listen_port != nc->gsup_listen_port ||
        old->gsup_n_listen_ips != nc->gsup_n_listen_ips)
        restart_reason_add(why, cap, &off, "gsup_listen");
    else {
        for (int i = 0; i < old->gsup_n_listen_ips; i++) {
            if (!streq(old->gsup_listen_ips[i], nc->gsup_listen_ips[i]))
                restart_reason_add(why, cap, &off, "gsup_listen");
        }
    }
    if (!streq(old->stp_ip, nc->stp_ip) || old->stp_port != nc->stp_port ||
        !streq(old->stp_local_ip, nc->stp_local_ip) ||
        old->stp_local_port != nc->stp_local_port ||
        !streq(old->stp_remote_pc, nc->stp_remote_pc) ||
        old->stp_routing_context != nc->stp_routing_context ||
        old->stp_network_indicator != nc->stp_network_indicator)
        restart_reason_add(why, cap, &off, "stp");
    if (old->map_iwf_enabled != nc->map_iwf_enabled ||
        !streq(old->map_local_pc, nc->map_local_pc))
        restart_reason_add(why, cap, &off, "map_iwf");
    if (old->diam_n_peers != nc->diam_n_peers ||
        !streq(old->diam_local_ip, nc->diam_local_ip) ||
        !streq(old->diam_peer_ip, nc->diam_peer_ip) ||
        old->diam_peer_port != nc->diam_peer_port)
        restart_reason_add(why, cap, &off, "diameter_peers");
    else {
        for (int i = 0; i < old->diam_n_peers; i++) {
            if (!streq(old->diam_peers[i].ip, nc->diam_peers[i].ip) ||
                old->diam_peers[i].port != nc->diam_peers[i].port)
                restart_reason_add(why, cap, &off, "diameter_peers");
        }
    }
    if (old->metrics_enabled != nc->metrics_enabled ||
        !streq(old->metrics_listen_ip, nc->metrics_listen_ip) ||
        old->metrics_listen_port != nc->metrics_listen_port)
        restart_reason_add(why, cap, &off, "metrics_http");
#ifdef SMS_IWF_ENABLED
    if (old->sms_iwf_enabled != nc->sms_iwf_enabled ||
        !streq(old->smpp_bind_ip, nc->smpp_bind_ip) ||
        old->smpp_port != nc->smpp_port ||
        !streq(old->gsup_remote_ip, nc->gsup_remote_ip) ||
        old->gsup_remote_port != nc->gsup_remote_port)
        restart_reason_add(why, cap, &off, "sms_iwf");
#endif
    if (old->sip_iwf_enabled != nc->sip_iwf_enabled ||
        !streq(old->sip_listen_ip, nc->sip_listen_ip) ||
        old->sip_listen_port != nc->sip_listen_port ||
        old->sip_transport_udp != nc->sip_transport_udp ||
        old->sip_transport_tcp != nc->sip_transport_tcp)
        restart_reason_add(why, cap, &off, "sip_iwf");
    if (!streq(old->log_file, nc->log_file))
        restart_reason_add(why, cap, &off, "log_file");

    return why[0] != '\0';
}

static void log_timeout_delta(const char *name, int old_ms, int new_ms)
{
    if (old_ms != new_ms)
        LOGI("config", "reload: %s %d -> %d ms", name, old_ms, new_ms);
}

int iwf_config_reload(iwf_runtime_t *rt)
{
    if (!rt || !rt->cfg.cfg_path[0]) {
        LOGE("config", "reload: no config path");
        return -1;
    }

    iwf_config_t nc;
    if (iwf_config_load(rt->cfg.cfg_path, &nc) < 0) {
        LOGE("config", "reload failed reading %s", rt->cfg.cfg_path);
        return -1;
    }
    strncpy(nc.cfg_path, rt->cfg.cfg_path, sizeof(nc.cfg_path) - 1);
    nc.cfg_path[sizeof(nc.cfg_path) - 1] = '\0';

    const iwf_config_t *old = &rt->cfg;

    iwf_log_set_level(iwf_log_level_from_str(nc.log_level));
    subscr_cache_set_ttl(nc.pgw_cache_ttl_s);
    pgw_dns_set_ttl(nc.pgw_cache_ttl_s, nc.pgw_dns_neg_ttl_s);
    pgw_dns_set_timeout_ms(nc.pgw_dns_timeout_ms);
    iwf_imsi_trace_load_config(nc.trace_imsi);

    if (!msrn_cfg_equal(old, &nc)) {
        LOGI("config", "reload: MSRN pool layout changed -> reinitializing");
        if (msrn_pool_init(&nc) < 0)
            LOGW("config", "reload: msrn_pool_init failed");
    } else {
        msrn_pool_set_ttl(nc.map_msrn_ttl_sec);
    }

    rt_update_gtp_peer(&rt->sgwc_addr, nc.sgwc_ip, nc.sgwc_port);
    rt_update_gtp_peer(&rt->sgsn_gtp_addr, nc.sgsn_ip, nc.sgsn_port);
    rt_update_gtp_peer(&rt->mme_gtp_addr, nc.mme_ip, nc.mme_port);

    log_timeout_delta("gsup_timeout_ms", old->gsup_timeout_ms, nc.gsup_timeout_ms);
    log_timeout_delta("diam_request_timeout_ms", old->diam_request_timeout_ms,
                      nc.diam_request_timeout_ms);
    log_timeout_delta("map_t_dialogue_ms", old->map_t_dialogue_ms,
                      nc.map_t_dialogue_ms);
#ifdef SMS_IWF_ENABLED
    log_timeout_delta("sms_gsup_timeout_ms", old->sms_gsup_timeout_ms,
                      nc.sms_gsup_timeout_ms);
    log_timeout_delta("sms_sri_sm_timeout_ms", old->sms_sri_sm_timeout_ms,
                      nc.sms_sri_sm_timeout_ms);
    log_timeout_delta("sms_fwdsm_timeout_ms", old->sms_fwdsm_timeout_ms,
                      nc.sms_fwdsm_timeout_ms);
#endif

    char restart_why[256];
    bool need_restart = cfg_needs_restart(old, &nc, restart_why,
                                          sizeof(restart_why));

    rt->cfg = nc;
    (void)isup_call_reconfigure(rt);

    if (need_restart)
        LOGW("config",
             "reload complete (%s); restart required for: %s",
             rt->cfg.cfg_path, restart_why);
    else
        LOGI("config", "reload complete (%s)", rt->cfg.cfg_path);

    return 0;
}
