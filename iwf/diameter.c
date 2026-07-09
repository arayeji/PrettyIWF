/*
 * diameter.c - Diameter base (RFC 6733) + S6d (3GPP TS 29.272) client.
 *
 * Wire format (RFC 6733 §3):
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    Version    |                 Message Length                |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  CMD Flags    |                 Command Code                  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                     Application-ID                            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                  Hop-by-Hop Identifier                        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                  End-to-End Identifier                        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  AVPs ...                                                     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * AVPs are TLV-style with 32-bit alignment.  Vendor-Id (when V flag is set)
 * sits between the flags byte and the AVP data.
 *
 * Single peer
 * -----------
 * We open one TCP connection to PyHSS, run CER->CEA, then send S6d traffic
 * on the same connection.  No DNS, no SCTP multihoming, no failover (yet).
 * Reconnect with exponential backoff on socket close.
 */

#include "diameter.h"
#include "logging.h"
#include "runtime.h"
#include "map_session.h"
#include "map_iwf.h"
#include "map_iwf_priv.h"
#include "map_codec.h"
#include "gsup_proto.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>      /* strcasecmp */
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <poll.h>

/* ====================================================================== */
/* Wire helpers                                                           */
/* ====================================================================== */

static inline void put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)(v);
}
static inline uint32_t get_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}
static inline uint32_t get_be24(const uint8_t *p) {
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[2];
}
static inline void put_be24(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 16); p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)v;
}
static inline size_t pad4(size_t n) { return (n + 3) & ~(size_t)3; }

/* ====================================================================== */
/* AVP encode                                                             */
/* ====================================================================== */

/*  AVP header layout (RFC 6733 §4):
 *
 *   AVP Code (4)
 *   Flags (1) | AVP Length (3)
 *   [Vendor-Id (4)]    -- only if V flag is set
 *   Data ...
 *   Pad to 4-octet boundary.
 *
 * `flags` is the AVP flags byte; we set M (mandatory) by default.
 * `vendor_id` is non-zero only when the V flag is also set in `flags`.
 */
static int avp_put(uint8_t *buf, size_t cap, size_t *off,
                   uint32_t code, uint8_t flags, uint32_t vendor_id,
                   const void *data, size_t data_len)
{
    size_t hdr = 8 + ((flags & DIAM_AVP_FLAG_VENDOR) ? 4 : 0);
    size_t total = hdr + data_len;
    size_t pad   = pad4(total) - total;
    if (*off + pad4(total) > cap) return -1;

    uint8_t *p = buf + *off;
    put_be32(p, code);              p += 4;
    p[0] = flags;                   p += 1;
    put_be24(p, (uint32_t)total);   p += 3;
    if (flags & DIAM_AVP_FLAG_VENDOR) {
        put_be32(p, vendor_id);     p += 4;
    }
    if (data_len) { memcpy(p, data, data_len); p += data_len; }
    /* Pad bytes are zero per RFC 6733. */
    while (pad--) *p++ = 0;
    *off += pad4(total);
    return 0;
}

static int avp_put_u32(uint8_t *buf, size_t cap, size_t *off,
                       uint32_t code, uint8_t flags, uint32_t vendor_id,
                       uint32_t v)
{
    uint8_t be[4];
    put_be32(be, v);
    return avp_put(buf, cap, off, code, flags, vendor_id, be, 4);
}

static int avp_put_str(uint8_t *buf, size_t cap, size_t *off,
                       uint32_t code, uint8_t flags, uint32_t vendor_id,
                       const char *s)
{
    if (!s) return -1;
    return avp_put(buf, cap, off, code, flags, vendor_id, s, strlen(s));
}

/* Grouped AVP helper: build child AVPs at `child`, then wrap them with
 * `code` (vendor-specific if vendor_id != 0). */
static int avp_put_grouped(uint8_t *buf, size_t cap, size_t *off,
                           uint32_t code, uint8_t flags, uint32_t vendor_id,
                           const uint8_t *child, size_t child_len)
{
    return avp_put(buf, cap, off, code, flags, vendor_id, child, child_len);
}

/* ====================================================================== */
/* AVP decode                                                             */
/* ====================================================================== */

int diameter_avp_first(const uint8_t *buf, size_t len, diameter_avp_t *it)
{
    memset(it, 0, sizeof(*it));
    if (!buf || len < 8) return -1;
    it->code  = get_be32(buf);
    it->flags = buf[4];
    uint32_t total = get_be24(buf + 5);
    if (total > len || total < 8) return -1;
    size_t hdr = 8;
    if (it->flags & DIAM_AVP_FLAG_VENDOR) {
        if (total < 12) return -1;
        it->vendor_id = get_be32(buf + 8);
        hdr = 12;
    }
    it->data     = buf + hdr;
    it->data_len = total - hdr;
    return 0;
}

int diameter_avp_next(const uint8_t *buf, size_t len, diameter_avp_t *it)
{
    /* Compute the byte just after this AVP (including 4-byte pad). */
    if (!it->data) return -1;
    size_t hdr = 8 + ((it->flags & DIAM_AVP_FLAG_VENDOR) ? 4 : 0);
    size_t total = hdr + it->data_len;
    size_t consumed = pad4(total);
    size_t cur_off = (size_t)((it->data - buf) - hdr);
    size_t nxt = cur_off + consumed;
    if (nxt + 8 > len) return -1;
    return diameter_avp_first(buf + nxt, len - nxt, it);
}

int diameter_avp_find(const uint8_t *buf, size_t len,
                      uint32_t code, uint32_t vendor_id,
                      diameter_avp_t *out)
{
    diameter_avp_t it;
    if (diameter_avp_first(buf, len, &it) < 0) return -1;
    for (;;) {
        if (it.code == code && it.vendor_id == vendor_id) {
            *out = it;
            return 0;
        }
        if (diameter_avp_next(buf, len, &it) < 0) return -1;
    }
}

int diameter_avp_find_recursive(const uint8_t *buf, size_t len,
                                uint32_t code, uint32_t vendor_id,
                                diameter_avp_t *out)
{
    diameter_avp_t it;
    if (diameter_avp_first(buf, len, &it) < 0) return -1;
    for (;;) {
        if (it.code == code && it.vendor_id == vendor_id) {
            *out = it;
            return 0;
        }
        if (it.data_len >= 8 &&
            diameter_avp_find_recursive(it.data, it.data_len,
                                      code, vendor_id, out) == 0)
            return 0;
        if (diameter_avp_next(buf, len, &it) < 0) return -1;
    }
}

static bool diameter_avp_is_3gpp(const diameter_avp_t *a, uint32_t code)
{
    if (!a || a->code != code)
        return false;
    if (a->vendor_id == DIAMETER_VENDOR_3GPP)
        return true;
    return !(a->flags & DIAM_AVP_FLAG_VENDOR);
}

int diameter_avp_find_3gpp(const uint8_t *buf, size_t len,
                           uint32_t code, diameter_avp_t *out)
{
    diameter_avp_t it;
    if (diameter_avp_first(buf, len, &it) < 0) return -1;
    for (;;) {
        if (diameter_avp_is_3gpp(&it, code)) {
            *out = it;
            return 0;
        }
        if (diameter_avp_next(buf, len, &it) < 0) return -1;
    }
}

int diameter_avp_find_3gpp_recursive(const uint8_t *buf, size_t len,
                                     uint32_t code, diameter_avp_t *out)
{
    diameter_avp_t it;
    if (diameter_avp_first(buf, len, &it) < 0) return -1;
    for (;;) {
        if (diameter_avp_is_3gpp(&it, code)) {
            *out = it;
            return 0;
        }
        if (it.data_len >= 8 &&
            diameter_avp_find_3gpp_recursive(it.data, it.data_len, code, out) == 0)
            return 0;
        if (diameter_avp_next(buf, len, &it) < 0) return -1;
    }
}

int diameter_get_result_code(const uint8_t *body, size_t len, uint32_t *out_rc)
{
    diameter_avp_t a;
    if (diameter_avp_find(body, len, AVP_RESULT_CODE, 0, &a) == 0 &&
        a.data_len == 4) {
        *out_rc = get_be32(a.data);
        return 0;
    }
    /* Experimental-Result is a grouped AVP carrying Vendor-Id +
     * Experimental-Result-Code. We surface just the code. */
    if (diameter_avp_find(body, len, AVP_EXPERIMENTAL_RESULT, 0, &a) == 0) {
        diameter_avp_t inner;
        if (diameter_avp_find(a.data, a.data_len,
                              AVP_EXPERIMENTAL_RESULT_CODE, 0, &inner) == 0 &&
            inner.data_len == 4) {
            *out_rc = get_be32(inner.data);
            return 0;
        }
    }
    return -1;
}

int diameter_get_session_id(const uint8_t *body, size_t len,
                            char *out, size_t out_cap)
{
    diameter_avp_t a;
    if (diameter_avp_find(body, len, AVP_SESSION_ID, 0, &a) < 0) return -1;
    size_t n = a.data_len;
    if (n + 1 > out_cap) n = out_cap - 1;
    memcpy(out, a.data, n);
    out[n] = '\0';
    return 0;
}

int diameter_get_user_name(const uint8_t *body, size_t len,
                           char *out, size_t out_cap)
{
    diameter_avp_t a;
    if (diameter_avp_find(body, len, AVP_USER_NAME, 0, &a) < 0) return -1;
    if (a.data_len == 0 || a.data_len >= out_cap) return -1;
    memcpy(out, a.data, a.data_len);
    out[a.data_len] = '\0';
    return 0;
}

int diameter_get_os_avp(const uint8_t *body, size_t len,
                        uint32_t code, uint32_t vendor_id,
                        char *out, size_t out_cap)
{
    diameter_avp_t a;
    if (vendor_id) {
        if (diameter_avp_find(body, len, code, vendor_id, &a) < 0)
            return -1;
    } else if (diameter_avp_find(body, len, code, 0, &a) < 0) {
        return -1;
    }
    if (a.data_len == 0 || a.data_len >= out_cap) return -1;
    memcpy(out, a.data, a.data_len);
    out[a.data_len] = '\0';
    return 0;
}

int diameter_get_uint32_avp(const uint8_t *body, size_t len,
                            uint32_t code, uint32_t vendor_id,
                            uint32_t *out_val)
{
    diameter_avp_t a;
    if (diameter_avp_find(body, len, code, vendor_id, &a) < 0) return -1;
    if (a.data_len != 4) return -1;
    *out_val = get_be32(a.data);
    return 0;
}

/* ====================================================================== */
/* Connection management                                                  */
/* ====================================================================== */

static int set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int diameter_tx(diameter_peer_t *p, const uint8_t *buf, size_t len);

static diameter_pool_t *diam_pool(struct iwf_runtime *rt)
{
    return rt && rt->map ? &rt->map->diam : NULL;
}

static diameter_peer_t *diam_peer_at(diameter_pool_t *pool, int idx)
{
    if (!pool || idx < 0 || idx >= pool->n_peers) return NULL;
    return &pool->peer[idx];
}

static const char *sess_dest_realm(const map_session_t *s, const iwf_config_t *c)
{
    if (s && s->diam_dest_realm[0]) return s->diam_dest_realm;
    return c->diam_dest_realm;
}

static const char *sess_dest_host(const map_session_t *s, const iwf_config_t *c)
{
    /* A session-specific host (roaming route that pinned mncNNN_dest_host)
     * always wins. */
    if (s && s->diam_dest_host[0]) return s->diam_dest_host;
    /* Never inherit the global (home) Destination-Host for a session routed to
     * a different realm: a Destination-Host that lives in another realm makes
     * the DRA answer 3002 (UNABLE_TO_DELIVER). Only use the global host when the
     * effective Destination-Realm is the home realm; otherwise omit it and let
     * the DRA route by realm. */
    if (s && s->diam_dest_realm[0] && c->diam_dest_realm[0] &&
        strcasecmp(s->diam_dest_realm, c->diam_dest_realm) != 0)
        return NULL;
    return c->diam_dest_host;
}

static int diameter_pick_peer(diameter_pool_t *pool)
{
    if (!pool || pool->n_peers <= 0) return -1;
    int start = pool->rr_next % pool->n_peers;
    for (int i = 0; i < pool->n_peers; i++) {
        int idx = (start + i) % pool->n_peers;
        diameter_peer_t *p = &pool->peer[idx];
        if (p->state == DIAM_CONN_OPEN && p->fd >= 0)
            return idx;
    }
    return -1;
}

static int diameter_tx_pool(diameter_pool_t *pool, int prefer_idx,
                            const uint8_t *buf, size_t len)
{
    if (prefer_idx >= 0) {
        diameter_peer_t *p = diam_peer_at(pool, prefer_idx);
        if (p && p->state == DIAM_CONN_OPEN && p->fd >= 0)
            return diameter_tx(p, buf, len);
    }
    int idx = diameter_pick_peer(pool);
    if (idx < 0) return -1;
    return diameter_tx(&pool->peer[idx], buf, len);
}

static int build_header(uint8_t *buf, size_t cap,
                        uint8_t cmd_flags, uint32_t cmd_code, uint32_t app_id,
                        uint32_t hop_by_hop, uint32_t end_to_end)
{
    if (cap < 20) return -1;
    buf[0] = DIAMETER_VERSION;
    /* length filled in after AVPs */
    buf[1] = 0; buf[2] = 0; buf[3] = 0;
    buf[4] = cmd_flags;
    put_be24(buf + 5, cmd_code);
    put_be32(buf + 8,  app_id);
    put_be32(buf + 12, hop_by_hop);
    put_be32(buf + 16, end_to_end);
    return 20;
}

static void finalize_length(uint8_t *buf, size_t total)
{
    put_be24(buf + 1, (uint32_t)total);
}

static uint32_t next_hop_by_hop(diameter_pool_t *pool)
{
    return ++pool->hop_by_hop_seed;
}
static uint32_t next_end_to_end(diameter_pool_t *pool)
{
    return ++pool->end_to_end_seed;
}

/* Build the standard origin/realm/destination AVPs all S6d requests share. */
static const char *diam_origin_host_for_sess(const iwf_runtime_t *rt,
                                             const map_session_t *s)
{
    const iwf_config_t *c = &rt->cfg;
    if (s && s->gsup_cn_domain == GSUP_CN_DOMAIN_CS && c->diam_origin_host_cs[0])
        return c->diam_origin_host_cs;
    return c->diam_origin_host;
}

static int build_s6d_route_avps(struct iwf_runtime *rt,
                                uint8_t *avps, size_t cap, size_t *off,
                                const char *session_id,
                                const map_session_t *s)
{
    const iwf_config_t *c = &rt->cfg;
    const char *origin_host = diam_origin_host_for_sess(rt, s);
    if (avp_put_str(avps, cap, off, AVP_SESSION_ID,
                    DIAM_AVP_FLAG_MANDATORY, 0, session_id) < 0) return -1;
    if (avp_put_u32(avps, cap, off, AVP_AUTH_APPLICATION_ID,
                    DIAM_AVP_FLAG_MANDATORY, 0, DIAMETER_APP_S6D) < 0)
        return -1;

    if (avp_put_u32(avps, cap, off, AVP_AUTH_SESSION_STATE,
                    DIAM_AVP_FLAG_MANDATORY, 0, 1 /* NO_STATE_MAINTAINED */) < 0)
        return -1;
    if (avp_put_str(avps, cap, off, AVP_ORIGIN_HOST,
                    DIAM_AVP_FLAG_MANDATORY, 0, origin_host) < 0)
        return -1;
    if (avp_put_str(avps, cap, off, AVP_ORIGIN_REALM,
                    DIAM_AVP_FLAG_MANDATORY, 0, c->diam_origin_realm) < 0)
        return -1;
    {
        const char *dh = sess_dest_host(s, c);
        const char *dr = sess_dest_realm(s, c);
        if (dh && dh[0])
            if (avp_put_str(avps, cap, off, AVP_DESTINATION_HOST,
                            DIAM_AVP_FLAG_MANDATORY, 0, dh) < 0)
                return -1;
        if (!dr || !dr[0]) return -1;
        if (avp_put_str(avps, cap, off, AVP_DESTINATION_REALM,
                        DIAM_AVP_FLAG_MANDATORY, 0, dr) < 0)
            return -1;
    }
    return 0;
}

/* Build a unique textual Session-Id per RFC 6733 §8.8. Format:
 *   <DiameterIdentity>;<high32>;<low32>;<random>                          */
static void make_session_id(const char *origin_host, char *out, size_t cap)
{
    static uint32_t low = 0;
    if (low == 0) low = (uint32_t)time(NULL);
    low++;
    uint32_t high = (uint32_t)time(NULL);
    /* Bound origin_host to 80 chars so the full Session-Id fits in `cap`
     * even with extreme values for the three integer fields. */
    snprintf(out, cap, "%.80s;%u;%u;%08x",
             origin_host && origin_host[0] ? origin_host : "iwf",
             (unsigned)high, (unsigned)low,
             (unsigned)(rand() & 0xffffffff));
}

/* ====================================================================== */
/* CER / DWR                                                              */
/* ====================================================================== */

static int diameter_send_cer(struct iwf_runtime *rt, int peer_idx)
{
    diameter_pool_t *pool = diam_pool(rt);
    diameter_peer_t *d = diam_peer_at(pool, peer_idx);
    if (!d) return -1;
    const iwf_config_t *c = &rt->cfg;
    uint8_t pkt[1024];
    int hl = build_header(pkt, sizeof(pkt),
                          DIAM_HDR_FLAG_REQUEST, DIAMETER_CMD_CER,
                          DIAMETER_APP_BASE,
                          next_hop_by_hop(pool), next_end_to_end(pool));
    if (hl < 0) return -1;
    size_t off = (size_t)hl;

    avp_put_str(pkt, sizeof(pkt), &off, AVP_ORIGIN_HOST,
                DIAM_AVP_FLAG_MANDATORY, 0, c->diam_origin_host);
    avp_put_str(pkt, sizeof(pkt), &off, AVP_ORIGIN_REALM,
                DIAM_AVP_FLAG_MANDATORY, 0, c->diam_origin_realm);
    /* Host-IP-Address: prepend IANA address-family (1 = IPv4). */
    {
        uint8_t ipv4[6] = {0,1,0,0,0,0};
        struct sockaddr_in local;
        socklen_t sl = sizeof(local);
        if (getsockname(d->fd, (struct sockaddr*)&local, &sl) == 0) {
            memcpy(ipv4 + 2, &local.sin_addr.s_addr, 4);
        }
        avp_put(pkt, sizeof(pkt), &off, AVP_HOST_IP_ADDRESS,
                DIAM_AVP_FLAG_MANDATORY, 0, ipv4, 6);
    }
    avp_put_u32(pkt, sizeof(pkt), &off, AVP_VENDOR_ID,
                DIAM_AVP_FLAG_MANDATORY, 0, c->diam_vendor_id);
    avp_put_str(pkt, sizeof(pkt), &off, AVP_PRODUCT_NAME,
                0, 0, c->diam_product_name);
    avp_put_u32(pkt, sizeof(pkt), &off, AVP_ORIGIN_STATE_ID,
                DIAM_AVP_FLAG_MANDATORY, 0, pool->origin_state_id);

    /* Vendor-Specific-Application-Id grouped: advertise S6d. */
    {
        uint8_t vsai[32]; size_t vo = 0;
        avp_put_u32(vsai, sizeof(vsai), &vo, AVP_VENDOR_ID,
                    DIAM_AVP_FLAG_MANDATORY, 0, DIAMETER_VENDOR_3GPP);
        avp_put_u32(vsai, sizeof(vsai), &vo, AVP_AUTH_APPLICATION_ID,
                    DIAM_AVP_FLAG_MANDATORY, 0, DIAMETER_APP_S6D);
        avp_put_grouped(pkt, sizeof(pkt), &off, AVP_VENDOR_SPECIFIC_APP_ID,
                        DIAM_AVP_FLAG_MANDATORY, 0, vsai, vo);
    }
    avp_put_u32(pkt, sizeof(pkt), &off, AVP_SUPPORTED_VENDOR_ID,
                DIAM_AVP_FLAG_MANDATORY, 0, DIAMETER_VENDOR_3GPP);
    avp_put_u32(pkt, sizeof(pkt), &off, AVP_FIRMWARE_REVISION,
                0, 0, 1);

    finalize_length(pkt, off);
    LOGI("diameter", "TX CER peer[%d] origin=%s realm=%s -> %s:%u",
         peer_idx, c->diam_origin_host, c->diam_origin_realm,
         d->peer_ip, (unsigned)d->peer_port);
    return diameter_tx(d, pkt, off);
}

static int diameter_send_dwr(struct iwf_runtime *rt, int peer_idx)
{
    diameter_pool_t *pool = diam_pool(rt);
    diameter_peer_t *d = diam_peer_at(pool, peer_idx);
    if (!d || d->state != DIAM_CONN_OPEN) return -1;
    const iwf_config_t *c = &rt->cfg;
    uint8_t pkt[256];
    int hl = build_header(pkt, sizeof(pkt),
                          DIAM_HDR_FLAG_REQUEST, DIAMETER_CMD_DWR,
                          DIAMETER_APP_BASE,
                          next_hop_by_hop(pool), next_end_to_end(pool));
    size_t off = (size_t)hl;
    avp_put_str(pkt, sizeof(pkt), &off, AVP_ORIGIN_HOST,
                DIAM_AVP_FLAG_MANDATORY, 0, c->diam_origin_host);
    avp_put_str(pkt, sizeof(pkt), &off, AVP_ORIGIN_REALM,
                DIAM_AVP_FLAG_MANDATORY, 0, c->diam_origin_realm);
    avp_put_u32(pkt, sizeof(pkt), &off, AVP_ORIGIN_STATE_ID,
                DIAM_AVP_FLAG_MANDATORY, 0, pool->origin_state_id);
    finalize_length(pkt, off);
    d->last_dwr_at = time(NULL);
    return diameter_tx(d, pkt, off);
}

static int diameter_send_dpr(struct iwf_runtime *rt, int peer_idx)
{
    diameter_pool_t *pool = diam_pool(rt);
    diameter_peer_t *d = diam_peer_at(pool, peer_idx);
    if (!d || d->state != DIAM_CONN_OPEN) return -1;
    const iwf_config_t *c = &rt->cfg;
    uint8_t pkt[256];
    int hl = build_header(pkt, sizeof(pkt),
                          DIAM_HDR_FLAG_REQUEST, DIAMETER_CMD_DPR,
                          DIAMETER_APP_BASE,
                          next_hop_by_hop(pool), next_end_to_end(pool));
    size_t off = (size_t)hl;
    avp_put_str(pkt, sizeof(pkt), &off, AVP_ORIGIN_HOST,
                DIAM_AVP_FLAG_MANDATORY, 0, c->diam_origin_host);
    avp_put_str(pkt, sizeof(pkt), &off, AVP_ORIGIN_REALM,
                DIAM_AVP_FLAG_MANDATORY, 0, c->diam_origin_realm);
    avp_put_u32(pkt, sizeof(pkt), &off, AVP_DISCONNECT_CAUSE,
                DIAM_AVP_FLAG_MANDATORY, 0, 0 /* REBOOTING */);
    finalize_length(pkt, off);
    return diameter_tx(d, pkt, off);
}

static int send_dwa(struct iwf_runtime *rt, int peer_idx,
                    uint32_t hbh, uint32_t e2e)
{
    diameter_pool_t *pool = diam_pool(rt);
    diameter_peer_t *d = diam_peer_at(pool, peer_idx);
    if (!d) return -1;
    const iwf_config_t *c = &rt->cfg;
    uint8_t pkt[256];
    int hl = build_header(pkt, sizeof(pkt),
                          0 /* answer */, DIAMETER_CMD_DWR,
                          DIAMETER_APP_BASE, hbh, e2e);
    size_t off = (size_t)hl;
    avp_put_u32(pkt, sizeof(pkt), &off, AVP_RESULT_CODE,
                DIAM_AVP_FLAG_MANDATORY, 0, DIAM_RC_SUCCESS);
    avp_put_str(pkt, sizeof(pkt), &off, AVP_ORIGIN_HOST,
                DIAM_AVP_FLAG_MANDATORY, 0, c->diam_origin_host);
    avp_put_str(pkt, sizeof(pkt), &off, AVP_ORIGIN_REALM,
                DIAM_AVP_FLAG_MANDATORY, 0, c->diam_origin_realm);
    avp_put_u32(pkt, sizeof(pkt), &off, AVP_ORIGIN_STATE_ID,
                DIAM_AVP_FLAG_MANDATORY, 0, pool->origin_state_id);
    finalize_length(pkt, off);
    return diameter_tx(d, pkt, off);
}

static int diameter_ensure_session_peer(struct iwf_runtime *rt, map_session_t *s)
{
    diameter_pool_t *pool = diam_pool(rt);
    if (!pool || !s) return -1;
    if (s->diam_peer_idx >= 0 &&
        s->diam_peer_idx < pool->n_peers &&
        pool->peer[s->diam_peer_idx].state == DIAM_CONN_OPEN)
        return s->diam_peer_idx;
    int idx = diameter_pick_peer(pool);
    if (idx < 0) return -1;
    s->diam_peer_idx = idx;
    pool->rr_next = (idx + 1) % pool->n_peers;
    return idx;
}

static int diameter_tx_session(struct iwf_runtime *rt, map_session_t *s,
                               const uint8_t *pkt, size_t off)
{
    int idx = diameter_ensure_session_peer(rt, s);
    if (idx < 0) return -1;
    diameter_peer_t *p = diam_peer_at(diam_pool(rt), idx);
    int rc = diameter_tx(p, pkt, off);
    if (rc == 0) rt->map->stat_diam_tx++;
    return rc;
}

/* ====================================================================== */
/* S6d requests (one builder per command)                                 */
/* ====================================================================== */

static int build_s6d_request_header(struct iwf_runtime *rt, map_session_t *s,
                                    uint8_t *pkt, size_t cap,
                                    uint32_t cmd_code)
{
    diameter_pool_t *pool = diam_pool(rt);
    if (s->diameter_hop_by_hop == 0) s->diameter_hop_by_hop = next_hop_by_hop(pool);
    if (s->diameter_end_to_end == 0) s->diameter_end_to_end = next_end_to_end(pool);
    if (!s->diameter_session_id[0]) {
        make_session_id(rt->cfg.diam_origin_host,
                        s->diameter_session_id,
                        sizeof(s->diameter_session_id));
        map_sess_index_by_sid(s);
    }
    return build_header(pkt, cap,
                        DIAM_HDR_FLAG_REQUEST | DIAM_HDR_FLAG_PROXYABLE,
                        cmd_code, DIAMETER_APP_S6D,
                        s->diameter_hop_by_hop,
                        s->diameter_end_to_end);
}

static int diameter_body_valid(const uint8_t *body, size_t len)
{
    diameter_avp_t it;
    if (diameter_avp_first(body, len, &it) < 0)
        return -1;
    for (;;) {
        if (diameter_avp_next(body, len, &it) < 0)
            break;
    }
    return 0;
}

static int put_req_auth_info_group(uint8_t *pkt, size_t cap, size_t *off,
                                   uint32_t grouped_avp_code,
                                   uint8_t num_vectors,
                                   const uint8_t *resync_rand,
                                   const uint8_t *resync_auts)
{
    uint8_t inner[128];
    size_t io = 0;
    uint32_t nv = num_vectors > 0 ? num_vectors : 3;
    if (nv > 5) nv = 5;
    if (avp_put_u32(inner, sizeof(inner), &io, AVP_3GPP_NUM_REQ_VECTORS,
                    DIAM_AVP_FLAG_VENDOR | DIAM_AVP_FLAG_MANDATORY,
                    DIAMETER_VENDOR_3GPP, nv) < 0)
        return -1;
    if (avp_put_u32(inner, sizeof(inner), &io, AVP_3GPP_IMMEDIATE_RESPONSE_PREFERRED,
                    DIAM_AVP_FLAG_VENDOR | DIAM_AVP_FLAG_MANDATORY,
                    DIAMETER_VENDOR_3GPP, 1) < 0)
        return -1;
    if (resync_rand && resync_auts) {
        uint8_t rsi[16 + 14];
        memcpy(rsi, resync_rand, 16);
        memcpy(rsi + 16, resync_auts, 14);
        if (avp_put(inner, sizeof(inner), &io, AVP_3GPP_RE_SYNCHRONIZATION_INFO,
                    DIAM_AVP_FLAG_VENDOR | DIAM_AVP_FLAG_MANDATORY,
                    DIAMETER_VENDOR_3GPP, rsi, sizeof(rsi)) < 0)
            return -1;
    }
    return avp_put_grouped(pkt, cap, off, grouped_avp_code,
                           DIAM_AVP_FLAG_VENDOR | DIAM_AVP_FLAG_MANDATORY,
                           DIAMETER_VENDOR_3GPP, inner, io);
}

int diameter_send_air(struct iwf_runtime *rt, map_session_t *s)
{
    if (!diameter_is_open(rt)) {
        LOGW("diameter", "AIR not sent imsi=%s: peer not open", s->imsi_str);
        return -1;
    }
    uint8_t pkt[1024];
    int hl = build_s6d_request_header(rt, s, pkt, sizeof(pkt),
                                      DIAMETER_CMD_AIR);
    size_t off = (size_t)hl;

    if (build_s6d_route_avps(rt, pkt, sizeof(pkt), &off,
                             s->diameter_session_id, s) < 0) return -1;

    /* User-Name = IMSI (UTF-8 digits). */
    avp_put_str(pkt, sizeof(pkt), &off, AVP_USER_NAME,
                DIAM_AVP_FLAG_MANDATORY, 0, s->imsi_str);

    /* Visited-PLMN-Id (3 BCD bytes), V+M — required by Open5GS HSS for Milenage. */
    if (s->have_visited_plmn) {
        avp_put(pkt, sizeof(pkt), &off, AVP_3GPP_VISITED_PLMN_ID,
                DIAM_AVP_FLAG_VENDOR | DIAM_AVP_FLAG_MANDATORY,
                DIAMETER_VENDOR_3GPP, s->visited_plmn_bcd, 3);
    } else {
        LOGW("diameter", "AIR imsi=%s: no Visited-PLMN-Id (set [gsup_server] local_mnc)",
             s->imsi_str);
    }

    /* osmo-sgsn 3G: Requested-UTRAN-GERAN-Authentication-Info (1409) only.
     * Do not use 1408 here — HSS returns E-UTRAN/KASME without CK/IK. */
    {
        uint8_t nv = s->gsup_num_vectors > 0 ? s->gsup_num_vectors : 1;
        const uint8_t *rr = s->have_resync ? s->resync_rand : NULL;
        const uint8_t *ra = s->have_resync ? s->resync_auts : NULL;
        if (put_req_auth_info_group(pkt, sizeof(pkt), &off,
                                    AVP_3GPP_REQ_UTRAN_GERAN_AUTH_INFO,
                                    nv, rr, ra) < 0)
            return -1;
    }

    /* RAT-Type = UTRAN (1000) for osmo-sgsn 3G; GPRS (1001) yields HSS rc=5014. */
    avp_put_u32(pkt, sizeof(pkt), &off, AVP_3GPP_RAT_TYPE,
                DIAM_AVP_FLAG_VENDOR | DIAM_AVP_FLAG_MANDATORY,
                DIAMETER_VENDOR_3GPP, DIAM_RAT_TYPE_UTRAN);

    finalize_length(pkt, off);
    if (diameter_body_valid(pkt + (size_t)hl, off - (size_t)hl) < 0) {
        LOGE("diameter", "AIR imsi=%s: encoded AVP layout invalid", s->imsi_str);
        return -1;
    }
    LOGI("diameter", "TX AIR imsi=%s sid=%s len=%zu auth=UTRAN/1409%s",
         s->imsi_str, s->diameter_session_id, off,
         s->have_resync ? " resync=1" : "");
    return diameter_tx_session(rt, s, pkt, off);
}

int diameter_send_ulr(struct iwf_runtime *rt, map_session_t *s)
{
    if (!diameter_is_open(rt)) return -1;
    uint8_t pkt[1024];
    int hl = build_s6d_request_header(rt, s, pkt, sizeof(pkt),
                                      DIAMETER_CMD_ULR);
    size_t off = (size_t)hl;

    if (build_s6d_route_avps(rt, pkt, sizeof(pkt), &off,
                             s->diameter_session_id, s) < 0) return -1;

    avp_put_str(pkt, sizeof(pkt), &off, AVP_USER_NAME,
                DIAM_AVP_FLAG_MANDATORY, 0, s->imsi_str);
    if (s->have_visited_plmn) {
        avp_put(pkt, sizeof(pkt), &off, AVP_3GPP_VISITED_PLMN_ID,
                DIAM_AVP_FLAG_VENDOR | DIAM_AVP_FLAG_MANDATORY,
                DIAMETER_VENDOR_3GPP, s->visited_plmn_bcd, 3);
    }

    /* TS 29.272 §7.3.7 ULR-Flags:
     *  CS (GSUP CN=CS): S6d-style — bit1 clear, no GPRS-Sub-Req → MSISDN ULA.
     *  PS (SGSN):       S6d/SGSN — bit1 clear, GPRS-Sub-Req set → PDP/APN ULA.
     *  Do not set S6a/MME indicator (bit1) for Osmocom interworking. */
    uint32_t ulr_flags = 0;
    uint32_t rat_type  = DIAM_RAT_TYPE_UTRAN;
    if (s->gsup_cn_domain == GSUP_CN_DOMAIN_CS) {
        ulr_flags = 0;
    } else {
        ulr_flags = ULR_FLAG_GPRS_SUBSCRIPTION_REQ;
    }
    avp_put_u32(pkt, sizeof(pkt), &off, AVP_3GPP_ULR_FLAGS,
                DIAM_AVP_FLAG_VENDOR | DIAM_AVP_FLAG_MANDATORY,
                DIAMETER_VENDOR_3GPP, ulr_flags);

    avp_put_u32(pkt, sizeof(pkt), &off, AVP_3GPP_RAT_TYPE,
                DIAM_AVP_FLAG_VENDOR | DIAM_AVP_FLAG_MANDATORY,
                DIAMETER_VENDOR_3GPP, rat_type);

    /* CS ULR: SGSN-Number carries the osmo-msc VLR GT (TBCD). Pretty5GS HSS
     * detects CS attach from this AVP and stores vlr_number / vlr_host. */
    if (s->gsup_cn_domain == GSUP_CN_DOMAIN_CS) {
        const char *vlr_gt = rt->cfg.map_local_gt;
        uint8_t sn_bcd[8];
        int snl = -1;

        if (vlr_gt[0])
            snl = map_str_to_bcd(vlr_gt, sn_bcd, sizeof(sn_bcd));
        if (snl > 0) {
            if (avp_put(pkt, sizeof(pkt), &off, AVP_3GPP_SGSN_NUMBER,
                        DIAM_AVP_FLAG_VENDOR | DIAM_AVP_FLAG_MANDATORY,
                        DIAMETER_VENDOR_3GPP, sn_bcd, (size_t)snl) < 0)
                return -1;
        } else {
            LOGW("diameter", "CS ULR imsi=%s: no SGSN-Number (set [map_iwf] local_gt "
                 "to osmo-msc VLR GT)", s->imsi_str);
        }
    }

    finalize_length(pkt, off);
    if (s->gsup_cn_domain == GSUP_CN_DOMAIN_CS) {
        LOGI("diameter", "TX ULR imsi=%s cn=CS/S6d flags=0x%x origin=%s vlr_gt=%s sid=%s len=%zu",
             s->imsi_str, (unsigned)ulr_flags, diam_origin_host_for_sess(rt, s),
             rt->cfg.map_local_gt[0] ? rt->cfg.map_local_gt : "(unset)",
             s->diameter_session_id, off);
    } else {
        LOGI("diameter", "TX ULR imsi=%s cn=PS/S6d flags=0x%x rat=%u origin=%s sid=%s len=%zu",
             s->imsi_str, (unsigned)ulr_flags, (unsigned)rat_type,
             diam_origin_host_for_sess(rt, s), s->diameter_session_id, off);
    }
    return diameter_tx_session(rt, s, pkt, off);
}

int diameter_send_clr(struct iwf_runtime *rt, map_session_t *s)
{
    if (!diameter_is_open(rt)) return -1;
    uint8_t pkt[512];
    int hl = build_s6d_request_header(rt, s, pkt, sizeof(pkt),
                                      DIAMETER_CMD_CLR);
    size_t off = (size_t)hl;

    if (build_s6d_route_avps(rt, pkt, sizeof(pkt), &off,
                             s->diameter_session_id, s) < 0) return -1;

    avp_put_str(pkt, sizeof(pkt), &off, AVP_USER_NAME,
                DIAM_AVP_FLAG_MANDATORY, 0, s->imsi_str);
    avp_put_u32(pkt, sizeof(pkt), &off, AVP_3GPP_CANCELLATION_TYPE,
                DIAM_AVP_FLAG_VENDOR | DIAM_AVP_FLAG_MANDATORY,
                DIAMETER_VENDOR_3GPP, 0 /* MME_UPDATE_PROCEDURE */);

    finalize_length(pkt, off);
    LOGI("diameter", "TX CLR imsi=%s sid=%s", s->imsi_str, s->diameter_session_id);
    return diameter_tx_session(rt, s, pkt, off);
}

int diameter_send_cla_answer(struct iwf_runtime *rt,
                             uint32_t hop_by_hop, uint32_t end_to_end,
                             const char *session_id, uint32_t result_code,
                             int peer_idx)
{
    if (!diameter_is_open(rt)) return -1;
    diameter_pool_t *pool = diam_pool(rt);
    const iwf_config_t *c = &rt->cfg;
    uint8_t pkt[512];
    int hl = build_header(pkt, sizeof(pkt),
                          0 /* answer */, DIAMETER_CMD_CLR,
                          DIAMETER_APP_S6D,
                          hop_by_hop, end_to_end);
    if (hl < 0) return -1;
    size_t off = (size_t)hl;

    if (session_id && session_id[0]) {
        if (avp_put_str(pkt, sizeof(pkt), &off, AVP_SESSION_ID,
                        DIAM_AVP_FLAG_MANDATORY, 0, session_id) < 0)
            return -1;
    }
    if (avp_put_u32(pkt, sizeof(pkt), &off, AVP_RESULT_CODE,
                    DIAM_AVP_FLAG_MANDATORY, 0, result_code) < 0)
        return -1;
    if (avp_put_str(pkt, sizeof(pkt), &off, AVP_ORIGIN_HOST,
                    DIAM_AVP_FLAG_MANDATORY, 0, c->diam_origin_host) < 0)
        return -1;
    if (avp_put_str(pkt, sizeof(pkt), &off, AVP_ORIGIN_REALM,
                    DIAM_AVP_FLAG_MANDATORY, 0, c->diam_origin_realm) < 0)
        return -1;
    if (avp_put_u32(pkt, sizeof(pkt), &off, AVP_AUTH_SESSION_STATE,
                    DIAM_AVP_FLAG_MANDATORY, 0, 1) < 0)
        return -1;

    finalize_length(pkt, off);
    LOGI("diameter", "TX CLA rc=%u sid=%s peer=%d",
         (unsigned)result_code, session_id ? session_id : "", peer_idx);
    int rc = diameter_tx_pool(pool, peer_idx, pkt, off);
    if (rc == 0) rt->map->stat_diam_tx++;
    return rc;
}

int diameter_send_ida_answer(struct iwf_runtime *rt,
                             uint32_t hop_by_hop, uint32_t end_to_end,
                             const char *session_id, uint32_t result_code,
                             const char *origin_host, int peer_idx)
{
    if (!diameter_is_open(rt)) return -1;
    diameter_pool_t *pool = diam_pool(rt);
    const iwf_config_t *c = &rt->cfg;
    const char *oh = (origin_host && origin_host[0]) ? origin_host
                                                     : c->diam_origin_host;
    uint8_t pkt[512];
    int hl = build_header(pkt, sizeof(pkt),
                          0 /* answer */, DIAMETER_CMD_IDR,
                          DIAMETER_APP_S6D,
                          hop_by_hop, end_to_end);
    if (hl < 0) return -1;
    size_t off = (size_t)hl;

    if (session_id && session_id[0]) {
        if (avp_put_str(pkt, sizeof(pkt), &off, AVP_SESSION_ID,
                        DIAM_AVP_FLAG_MANDATORY, 0, session_id) < 0)
            return -1;
    }
    if (avp_put_u32(pkt, sizeof(pkt), &off, AVP_RESULT_CODE,
                    DIAM_AVP_FLAG_MANDATORY, 0, result_code) < 0)
        return -1;
    if (avp_put_str(pkt, sizeof(pkt), &off, AVP_ORIGIN_HOST,
                    DIAM_AVP_FLAG_MANDATORY, 0, oh) < 0)
        return -1;
    if (avp_put_str(pkt, sizeof(pkt), &off, AVP_ORIGIN_REALM,
                    DIAM_AVP_FLAG_MANDATORY, 0, c->diam_origin_realm) < 0)
        return -1;
    if (avp_put_u32(pkt, sizeof(pkt), &off, AVP_AUTH_SESSION_STATE,
                    DIAM_AVP_FLAG_MANDATORY, 0, 1) < 0)
        return -1;

    finalize_length(pkt, off);
    LOGI("diameter", "TX IDA rc=%u sid=%s origin=%s peer=%d",
         (unsigned)result_code, session_id ? session_id : "", oh, peer_idx);
    int rc = diameter_tx_pool(pool, peer_idx, pkt, off);
    if (rc == 0) rt->map->stat_diam_tx++;
    return rc;
}

int diameter_send_nor(struct iwf_runtime *rt,
                      const char *imsi, const char *origin_host,
                      uint32_t ue_reachability)
{
    if (!diameter_is_open(rt) || !imsi || !imsi[0]) return -1;
    diameter_pool_t *pool = diam_pool(rt);
    const iwf_config_t *c = &rt->cfg;
    const char *oh = (origin_host && origin_host[0]) ? origin_host
                                                     : c->diam_origin_host;
    char sid[128];
    uint8_t pkt[512];
    size_t off;

    make_session_id(oh, sid, sizeof(sid));

    int hl = build_header(pkt, sizeof(pkt),
                          DIAM_HDR_FLAG_REQUEST | DIAM_HDR_FLAG_PROXYABLE,
                          DIAMETER_CMD_NOR, DIAMETER_APP_S6D,
                          next_hop_by_hop(pool), next_end_to_end(pool));
    if (hl < 0) return -1;
    off = (size_t)hl;

    if (avp_put_str(pkt, sizeof(pkt), &off, AVP_SESSION_ID,
                    DIAM_AVP_FLAG_MANDATORY, 0, sid) < 0)
        return -1;
    if (avp_put_u32(pkt, sizeof(pkt), &off, AVP_AUTH_APPLICATION_ID,
                    DIAM_AVP_FLAG_MANDATORY, 0, DIAMETER_APP_S6D) < 0)
        return -1;
    if (avp_put_u32(pkt, sizeof(pkt), &off, AVP_AUTH_SESSION_STATE,
                    DIAM_AVP_FLAG_MANDATORY, 0, 1) < 0)
        return -1;
    if (avp_put_str(pkt, sizeof(pkt), &off, AVP_ORIGIN_HOST,
                    DIAM_AVP_FLAG_MANDATORY, 0, oh) < 0)
        return -1;
    if (avp_put_str(pkt, sizeof(pkt), &off, AVP_ORIGIN_REALM,
                    DIAM_AVP_FLAG_MANDATORY, 0, c->diam_origin_realm) < 0)
        return -1;
    if (c->diam_dest_host[0]) {
        if (avp_put_str(pkt, sizeof(pkt), &off, AVP_DESTINATION_HOST,
                        DIAM_AVP_FLAG_MANDATORY, 0, c->diam_dest_host) < 0)
            return -1;
    }
    if (avp_put_str(pkt, sizeof(pkt), &off, AVP_DESTINATION_REALM,
                    DIAM_AVP_FLAG_MANDATORY, 0, c->diam_dest_realm) < 0)
        return -1;
    if (avp_put_str(pkt, sizeof(pkt), &off, AVP_USER_NAME,
                    DIAM_AVP_FLAG_MANDATORY, 0, imsi) < 0)
        return -1;
    if (avp_put_u32(pkt, sizeof(pkt), &off, AVP_3GPP_NOR_FLAGS,
                    DIAM_AVP_FLAG_VENDOR | DIAM_AVP_FLAG_MANDATORY,
                    DIAMETER_VENDOR_3GPP, NOR_FLAG_UE_REACHABILITY) < 0)
        return -1;
    if (avp_put_u32(pkt, sizeof(pkt), &off, AVP_3GPP_UE_REACHABILITY,
                    DIAM_AVP_FLAG_VENDOR | DIAM_AVP_FLAG_MANDATORY,
                    DIAMETER_VENDOR_3GPP, ue_reachability) < 0)
        return -1;

    finalize_length(pkt, off);
    LOGI("diameter", "TX NOR imsi=%s reach=%u origin=%s sid=%s",
         imsi, (unsigned)ue_reachability, oh, sid);
    int idx = diameter_pick_peer(pool);
    if (idx < 0) return -1;
    pool->rr_next = (idx + 1) % pool->n_peers;
    int rc = diameter_tx(&pool->peer[idx], pkt, off);
    if (rc == 0) rt->map->stat_diam_tx++;
    return rc;
}

int diameter_send_pur(struct iwf_runtime *rt, map_session_t *s)
{
    if (!diameter_is_open(rt)) return -1;
    uint8_t pkt[512];
    int hl = build_s6d_request_header(rt, s, pkt, sizeof(pkt),
                                      DIAMETER_CMD_PUR);
    size_t off = (size_t)hl;

    if (build_s6d_route_avps(rt, pkt, sizeof(pkt), &off,
                             s->diameter_session_id, s) < 0) return -1;

    avp_put_str(pkt, sizeof(pkt), &off, AVP_USER_NAME,
                DIAM_AVP_FLAG_MANDATORY, 0, s->imsi_str);
    avp_put_u32(pkt, sizeof(pkt), &off, AVP_3GPP_PUR_FLAGS,
                DIAM_AVP_FLAG_VENDOR,
                DIAMETER_VENDOR_3GPP, 0);

    finalize_length(pkt, off);
    LOGI("diameter", "TX PUR imsi=%s sid=%s", s->imsi_str, s->diameter_session_id);
    return diameter_tx_session(rt, s, pkt, off);
}

/* ====================================================================== */
/* TX / RX plumbing                                                       */
/* ====================================================================== */

static int diameter_tx(diameter_peer_t *p, const uint8_t *buf, size_t len)
{
    if (!p || p->fd < 0) return -1;
    if (p->tx_used + len > sizeof(p->tx)) {
        LOGE("diameter", "tx buffer overflow (used=%zu add=%zu)", p->tx_used, len);
        return -1;
    }
    size_t off = 0;
    if (p->tx_used == 0) {
        ssize_t r = send(p->fd, buf, len, MSG_NOSIGNAL);
        if (r > 0) off = (size_t)r;
        else if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGE("diameter", "send: %s", strerror(errno));
            close(p->fd); p->fd = -1; p->state = DIAM_CONN_CLOSED;
            return -1;
        }
    }
    if (off < len) {
        memcpy(p->tx + p->tx_used, buf + off, len - off);
        p->tx_used += (len - off);
    }
    return 0;
}

static void try_flush_tx(diameter_peer_t *p)
{
    if (!p || p->fd < 0 || p->tx_used == 0) return;
    ssize_t r = send(p->fd, p->tx, p->tx_used, MSG_NOSIGNAL);
    if (r > 0) {
        if ((size_t)r < p->tx_used)
            memmove(p->tx, p->tx + r, p->tx_used - r);
        p->tx_used -= (size_t)r;
    } else if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        LOGE("diameter", "flush send: %s", strerror(errno));
        close(p->fd); p->fd = -1; p->state = DIAM_CONN_CLOSED;
    }
}

static void diameter_epoll_attach(struct iwf_runtime *rt, int peer_idx, int fd)
{
    if (fd < 0 || rt->map->epoll_fd < 0) return;
    struct epoll_event ev = {
        .events   = EPOLLIN | EPOLLRDHUP,
        .data.u64 = MAP_EPOLL_ROLE_DIAMETER_PEER(peer_idx),
    };
    if (epoll_ctl(rt->map->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0)
        LOGW("diameter", "epoll_ctl ADD fd=%d peer=%d: %s",
             fd, peer_idx, strerror(errno));
}

static int diameter_wait_connected(int fd)
{
    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    if (poll(&pfd, 1, 10000) <= 0)
        return -1;
    int so_err = 0;
    socklen_t el = sizeof(so_err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &el) < 0 || so_err != 0) {
        if (so_err)
            LOGE("diameter", "connect: %s", strerror(so_err));
        return -1;
    }
    return 0;
}

static void schedule_reconnect_peer(diameter_peer_t *p)
{
    if (!p) return;
    if (p->reconnect_backoff_s == 0) p->reconnect_backoff_s = 1;
    else if (p->reconnect_backoff_s < 60) p->reconnect_backoff_s *= 2;
    p->reconnect_not_before = time(NULL) + (time_t)p->reconnect_backoff_s;
    LOGW("diameter", "peer[%s:%u] reconnect in %us",
         p->peer_ip, (unsigned)p->peer_port, p->reconnect_backoff_s);
}

static const char *diam_bind_ip(const iwf_config_t *c)
{
    if (c->diam_local_ip[0]) return c->diam_local_ip;
    if (c->local_ip[0])      return c->local_ip;
    return NULL;
}

static int bind_local_ip(int fd, const char *ip)
{
    if (!ip || !ip[0]) return 0;
    struct sockaddr_in la;
    memset(&la, 0, sizeof(la));
    la.sin_family = AF_INET;
    la.sin_port   = 0;
    if (inet_pton(AF_INET, ip, &la.sin_addr) != 1) {
        LOGE("diameter", "bad local bind ip %s", ip);
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&la, sizeof(la)) < 0) {
        LOGE("diameter", "bind %s: %s", ip, strerror(errno));
        return -1;
    }
    return 0;
}

static void drop_peer(struct iwf_runtime *rt, int peer_idx)
{
    diameter_pool_t *pool = diam_pool(rt);
    diameter_peer_t *p = diam_peer_at(pool, peer_idx);
    if (!p) return;
    if (p->fd >= 0) {
        if (rt->map->epoll_fd >= 0)
            epoll_ctl(rt->map->epoll_fd, EPOLL_CTL_DEL, p->fd, NULL);
        close(p->fd);
        p->fd = -1;
    }
    p->state = DIAM_CONN_CLOSED;
    p->rx_used = 0;
    p->tx_used = 0;
}

static int connect_peer(struct iwf_runtime *rt, int peer_idx)
{
    diameter_pool_t *pool = diam_pool(rt);
    diameter_peer_t *p = diam_peer_at(pool, peer_idx);
    const iwf_config_t *c = &rt->cfg;
    if (!p || peer_idx < 0 || peer_idx >= c->diam_n_peers) return -1;

    drop_peer(rt, peer_idx);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { LOGE("diameter", "socket: %s", strerror(errno)); return -1; }
    set_nonblock(fd);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    const char *bind_ip = diam_bind_ip(c);
    if (bind_local_ip(fd, bind_ip) < 0) {
        close(fd);
        return -1;
    }

    memset(&p->peer, 0, sizeof(p->peer));
    p->peer.sin_family = AF_INET;
    p->peer.sin_port   = htons(p->peer_port ? p->peer_port : DIAMETER_PORT_DEFAULT);
    if (inet_pton(AF_INET, p->peer_ip, &p->peer.sin_addr) != 1) {
        LOGE("diameter", "bad diameter peer ip %s", p->peer_ip);
        close(fd); return -1;
    }

    int rc = connect(fd, (struct sockaddr*)&p->peer, sizeof(p->peer));
    if (rc < 0) {
        if (errno == EINPROGRESS) {
            if (diameter_wait_connected(fd) < 0) {
                LOGE("diameter", "TCP connect to %s:%u failed (local=%s)",
                     p->peer_ip, (unsigned)p->peer_port,
                     bind_ip ? bind_ip : "any");
                close(fd);
                return -1;
            }
        } else {
            LOGE("diameter", "connect %s:%u: %s",
                 p->peer_ip, p->peer_port, strerror(errno));
            close(fd);
            return -1;
        }
    }
    p->fd = fd;
    p->state = DIAM_CONN_CER_SENT;
    p->cer_sent_at = time(NULL);
    LOGI("diameter", "TCP connected peer[%d] %s:%u (local=%s)",
         peer_idx, p->peer_ip, (unsigned)p->peer_port,
         bind_ip ? bind_ip : "any");
    diameter_epoll_attach(rt, peer_idx, fd);
    if (diameter_send_cer(rt, peer_idx) < 0) {
        LOGE("diameter", "CER send failed peer[%d]", peer_idx);
        drop_peer(rt, peer_idx);
        return -1;
    }
    return 0;
}

static void on_cea(struct iwf_runtime *rt, int peer_idx,
                   const uint8_t *body, size_t len)
{
    diameter_pool_t *pool = diam_pool(rt);
    diameter_peer_t *p = diam_peer_at(pool, peer_idx);
    uint32_t rc = 0;
    if (diameter_get_result_code(body, len, &rc) == 0 && rc == DIAM_RC_SUCCESS) {
        if (p) {
            p->state = DIAM_CONN_OPEN;
            p->reconnect_backoff_s = 0;
            p->reconnect_not_before = 0;
        }
        LOGI("diameter", "peer[%d] up: CEA rc=2001 %s:%u",
             peer_idx, p ? p->peer_ip : "?", p ? (unsigned)p->peer_port : 0);
    } else {
        LOGE("diameter", "peer[%d] CEA rejected rc=%u", peer_idx, (unsigned)rc);
        drop_peer(rt, peer_idx);
        if (p) schedule_reconnect_peer(p);
    }
}

static void on_answer(struct iwf_runtime *rt, uint32_t cmd_code,
                      const uint8_t *body, size_t len)
{
    char sid[DIAMETER_SESSION_ID_MAX];
    sid[0] = '\0';
    diameter_get_session_id(body, len, sid, sizeof(sid));
    map_session_t *s = map_sess_find_by_diameter_sid(sid);
    if (!s) {
        LOGW("diameter", "answer cmd=%u sid=%s -> no session", (unsigned)cmd_code, sid);
        return;
    }
    uint32_t rc = 0;
    diameter_get_result_code(body, len, &rc);
    s->diameter_result_code = rc;
    LOGI("diameter", "RX answer cmd=%u imsi=%s sid=%s rc=%u",
         (unsigned)cmd_code, s->imsi_str, sid, (unsigned)rc);

    if (rc != DIAM_RC_SUCCESS && rc != DIAM_RC_LIMITED_SUCCESS) {
        map_iwf_diameter_error(rt, s, rc);
        return;
    }
    switch (cmd_code) {
    case DIAMETER_CMD_AIR: map_iwf_on_aia(rt, s, body, len); break;
    case DIAMETER_CMD_ULR: map_iwf_on_ula(rt, s, body, len); break;
    case DIAMETER_CMD_CLR: map_iwf_on_cla(rt, s, body, len); break;
    case DIAMETER_CMD_PUR: map_iwf_on_pua(rt, s, body, len); break;
    default:
        LOGW("diameter", "unexpected answer cmd=%u for imsi=%s",
             (unsigned)cmd_code, s->imsi_str);
        break;
    }
}

static void dispatch_message(struct iwf_runtime *rt, int peer_idx,
                             const uint8_t *pkt, size_t len)
{
    if (len < 20) return;
    uint8_t  flags    = pkt[4];
    uint32_t cmd_code = get_be24(pkt + 5);
    uint32_t app_id   = get_be32(pkt + 8);
    uint32_t hbh      = get_be32(pkt + 12);
    uint32_t e2e      = get_be32(pkt + 16);
    const uint8_t *body = pkt + 20;
    size_t   body_len   = len - 20;

    diameter_peer_t *p = diam_peer_at(diam_pool(rt), peer_idx);
    if (p) p->last_rx_at = time(NULL);
    rt->map->stat_diam_rx++;

    bool is_req = (flags & DIAM_HDR_FLAG_REQUEST) != 0;
    if (is_req) {
        if (cmd_code == DIAMETER_CMD_DWR) {
            send_dwa(rt, peer_idx, hbh, e2e);
            return;
        }
        if (cmd_code == DIAMETER_CMD_DPR) {
            LOGI("diameter", "RX DPR peer[%d]; closing", peer_idx);
            drop_peer(rt, peer_idx);
            if (p) schedule_reconnect_peer(p);
            return;
        }
        if (cmd_code == DIAMETER_CMD_CLR && app_id == DIAMETER_APP_S6D) {
            map_iwf_on_clr(rt, body, body_len, hbh, e2e, peer_idx);
            return;
        }
        if (cmd_code == DIAMETER_CMD_IDR && app_id == DIAMETER_APP_S6D) {
            map_iwf_on_idr(rt, body, body_len, hbh, e2e, peer_idx);
            return;
        }
        LOGW("diameter", "unexpected request cmd=%u app=%u peer[%d]",
             (unsigned)cmd_code, (unsigned)app_id, peer_idx);
        return;
    }

    if (cmd_code == DIAMETER_CMD_CER) {
        on_cea(rt, peer_idx, body, body_len);
        return;
    }
    if (cmd_code == DIAMETER_CMD_DWR) {
        LOGD("diameter", "RX DWA peer[%d]", peer_idx);
        return;
    }
    if (cmd_code == DIAMETER_CMD_DPR) {
        LOGI("diameter", "RX DPA peer[%d]", peer_idx);
        return;
    }
    on_answer(rt, cmd_code, body, body_len);
}

void diameter_on_readable(struct iwf_runtime *rt, int peer_idx)
{
    diameter_peer_t *p = diam_peer_at(diam_pool(rt), peer_idx);
    if (!p || p->fd < 0) return;

    for (;;) {
        if (p->rx_used >= sizeof(p->rx)) {
            LOGE("diameter", "rx buffer full peer[%d]; reset", peer_idx);
            drop_peer(rt, peer_idx);
            schedule_reconnect_peer(p);
            return;
        }
        ssize_t r = recv(p->fd, p->rx + p->rx_used, sizeof(p->rx) - p->rx_used, 0);
        if (r > 0) {
            p->rx_used += (size_t)r;
        } else if (r == 0) {
            LOGW("diameter", "peer[%d] closed TCP", peer_idx);
            drop_peer(rt, peer_idx);
            schedule_reconnect_peer(p);
            return;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EINTR) continue;
            LOGE("diameter", "recv peer[%d]: %s", peer_idx, strerror(errno));
            drop_peer(rt, peer_idx);
            schedule_reconnect_peer(p);
            return;
        }
    }

    size_t consumed = 0;
    while (p->rx_used - consumed >= 20) {
        const uint8_t *pkt = p->rx + consumed;
        if (pkt[0] != DIAMETER_VERSION) {
            LOGE("diameter", "bad version peer[%d]; reset", peer_idx);
            drop_peer(rt, peer_idx);
            schedule_reconnect_peer(p);
            return;
        }
        uint32_t mlen = get_be24(pkt + 1);
        if (mlen < 20 || mlen > sizeof(p->rx)) {
            LOGE("diameter", "bad msg length %u peer[%d]", (unsigned)mlen, peer_idx);
            drop_peer(rt, peer_idx);
            schedule_reconnect_peer(p);
            return;
        }
        if (p->rx_used - consumed < mlen) break;
        dispatch_message(rt, peer_idx, pkt, mlen);
        consumed += mlen;
    }
    if (consumed) {
        if (consumed < p->rx_used)
            memmove(p->rx, p->rx + consumed, p->rx_used - consumed);
        p->rx_used -= consumed;
    }

    try_flush_tx(p);
}

int diameter_init(struct iwf_runtime *rt)
{
    diameter_pool_t *pool = diam_pool(rt);
    const iwf_config_t *c = &rt->cfg;
    memset(pool, 0, sizeof(*pool));
    pool->watchdog_timerfd = -1;
    pool->origin_state_id = (uint32_t)time(NULL);
    pool->hop_by_hop_seed = (uint32_t)rand();
    pool->end_to_end_seed = (uint32_t)rand();

    if (c->diam_n_peers <= 0 ||
        !c->diam_origin_host[0] || !c->diam_origin_realm[0] ||
        !c->diam_dest_realm[0]) {
        LOGE("diameter", "missing [diameter_s6d]: peers, origin_host, "
                         "origin_realm, dest_realm");
        return -1;
    }

    pool->n_peers = c->diam_n_peers;
    for (int i = 0; i < pool->n_peers; i++) {
        diameter_peer_t *p = &pool->peer[i];
        p->fd = -1;
        p->state = DIAM_CONN_CLOSED;
        strncpy(p->peer_ip, c->diam_peers[i].ip, sizeof(p->peer_ip) - 1);
        p->peer_ip[sizeof(p->peer_ip) - 1] = '\0';
        p->peer_port = c->diam_peers[i].port ? c->diam_peers[i].port : 3868;
    }

    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (tfd < 0) { LOGE("diameter", "timerfd: %s", strerror(errno)); return -1; }
    int ms = c->diam_watchdog_ms > 0 ? c->diam_watchdog_ms : 30000;
    struct itimerspec its = {
        .it_interval = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L },
        .it_value    = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L },
    };
    timerfd_settime(tfd, 0, &its, NULL);
    pool->watchdog_timerfd = tfd;

    for (int i = 0; i < pool->n_peers; i++) {
        if (connect_peer(rt, i) < 0)
            schedule_reconnect_peer(&pool->peer[i]);
    }
    return 0;
}

void diameter_on_dwa_tick(struct iwf_runtime *rt)
{
    diameter_pool_t *pool = diam_pool(rt);
    if (!pool || pool->watchdog_timerfd < 0) return;
    uint64_t exp;
    ssize_t r = read(pool->watchdog_timerfd, &exp, sizeof(exp));
    (void)r;

    time_t now = time(NULL);
    for (int i = 0; i < pool->n_peers; i++) {
        diameter_peer_t *p = &pool->peer[i];
        if (p->state == DIAM_CONN_CER_SENT && p->cer_sent_at > 0 &&
            now - p->cer_sent_at >= 10) {
            LOGW("diameter", "CEA timeout peer[%d] %s:%u",
                 i, p->peer_ip, (unsigned)p->peer_port);
            drop_peer(rt, i);
            schedule_reconnect_peer(p);
            continue;
        }
        if (p->state == DIAM_CONN_OPEN)
            diameter_send_dwr(rt, i);
        else if (p->state == DIAM_CONN_CLOSED &&
                 p->reconnect_not_before > 0 && now >= p->reconnect_not_before) {
            LOGI("diameter", "reconnect peer[%d] %s:%u", i, p->peer_ip,
                 (unsigned)p->peer_port);
            if (connect_peer(rt, i) < 0)
                schedule_reconnect_peer(p);
        }
    }
}

void diameter_shutdown(struct iwf_runtime *rt)
{
    if (!rt->map) return;
    diameter_pool_t *pool = diam_pool(rt);
    for (int i = 0; i < pool->n_peers; i++) {
        diameter_peer_t *p = &pool->peer[i];
        if (p->state == DIAM_CONN_OPEN)
            diameter_send_dpr(rt, i);
        try_flush_tx(p);
        if (p->fd >= 0) close(p->fd);
        p->fd = -1;
        p->state = DIAM_CONN_CLOSED;
    }
    if (pool->watchdog_timerfd >= 0) close(pool->watchdog_timerfd);
    pool->watchdog_timerfd = -1;
}

int diameter_get_fd(const struct iwf_runtime *rt)
{
    if (!rt || !rt->map) return -1;
    const diameter_pool_t *pool = &rt->map->diam;
    for (int i = 0; i < pool->n_peers; i++)
        if (pool->peer[i].fd >= 0)
            return pool->peer[i].fd;
    return -1;
}

int diameter_get_dwa_timer_fd(const struct iwf_runtime *rt)
{
    return rt->map ? rt->map->diam.watchdog_timerfd : -1;
}

bool diameter_is_open(const struct iwf_runtime *rt)
{
    if (!rt || !rt->map) return false;
    const diameter_pool_t *pool = &rt->map->diam;
    for (int i = 0; i < pool->n_peers; i++)
        if (pool->peer[i].state == DIAM_CONN_OPEN && pool->peer[i].fd >= 0)
            return true;
    return false;
}
