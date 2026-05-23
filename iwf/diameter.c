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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
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

/* ====================================================================== */
/* Connection management                                                  */
/* ====================================================================== */

static int set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int diameter_tx(diameter_state_t *d, const uint8_t *buf, size_t len);

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

static uint32_t next_hop_by_hop(diameter_state_t *d)
{
    return ++d->hop_by_hop_seed;
}
static uint32_t next_end_to_end(diameter_state_t *d)
{
    return ++d->end_to_end_seed;
}

/* Build the standard origin/realm/destination AVPs all S6d requests share. */
static int build_s6d_route_avps(struct iwf_runtime *rt,
                                uint8_t *avps, size_t cap, size_t *off,
                                const char *session_id)
{
    const iwf_config_t *c = &rt->cfg;
    if (avp_put_str(avps, cap, off, AVP_SESSION_ID,
                    DIAM_AVP_FLAG_MANDATORY, 0, session_id) < 0) return -1;

    /* Vendor-Specific-Application-Id (grouped) - identifies S6d. */
    uint8_t vsai[32]; size_t vo = 0;
    avp_put_u32(vsai, sizeof(vsai), &vo, AVP_VENDOR_ID,
                DIAM_AVP_FLAG_MANDATORY, 0, DIAMETER_VENDOR_3GPP);
    avp_put_u32(vsai, sizeof(vsai), &vo, AVP_AUTH_APPLICATION_ID,
                DIAM_AVP_FLAG_MANDATORY, 0, DIAMETER_APP_S6D);
    if (avp_put_grouped(avps, cap, off, AVP_VENDOR_SPECIFIC_APP_ID,
                        DIAM_AVP_FLAG_MANDATORY, 0, vsai, vo) < 0) return -1;

    if (avp_put_u32(avps, cap, off, AVP_AUTH_SESSION_STATE,
                    DIAM_AVP_FLAG_MANDATORY, 0, 1 /* NO_STATE_MAINTAINED */) < 0)
        return -1;
    if (avp_put_str(avps, cap, off, AVP_ORIGIN_HOST,
                    DIAM_AVP_FLAG_MANDATORY, 0, c->diam_origin_host) < 0)
        return -1;
    if (avp_put_str(avps, cap, off, AVP_ORIGIN_REALM,
                    DIAM_AVP_FLAG_MANDATORY, 0, c->diam_origin_realm) < 0)
        return -1;
    if (c->diam_dest_host[0])
        if (avp_put_str(avps, cap, off, AVP_DESTINATION_HOST,
                        DIAM_AVP_FLAG_MANDATORY, 0, c->diam_dest_host) < 0)
            return -1;
    if (avp_put_str(avps, cap, off, AVP_DESTINATION_REALM,
                    DIAM_AVP_FLAG_MANDATORY, 0, c->diam_dest_realm) < 0)
        return -1;
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

static int diameter_send_cer(struct iwf_runtime *rt)
{
    diameter_state_t *d = &rt->map->diam;
    const iwf_config_t *c = &rt->cfg;
    uint8_t pkt[1024];
    int hl = build_header(pkt, sizeof(pkt),
                          DIAM_HDR_FLAG_REQUEST, DIAMETER_CMD_CER,
                          DIAMETER_APP_BASE,
                          next_hop_by_hop(d), next_end_to_end(d));
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
                DIAM_AVP_FLAG_MANDATORY, 0, d->origin_state_id);

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
    LOGI("diameter", "TX CER origin=%s realm=%s -> %s:%u",
         c->diam_origin_host, c->diam_origin_realm,
         inet_ntoa(d->peer.sin_addr), ntohs(d->peer.sin_port));
    return diameter_tx(d, pkt, off);
}

static int diameter_send_dwr(struct iwf_runtime *rt)
{
    diameter_state_t *d = &rt->map->diam;
    const iwf_config_t *c = &rt->cfg;
    uint8_t pkt[256];
    int hl = build_header(pkt, sizeof(pkt),
                          DIAM_HDR_FLAG_REQUEST, DIAMETER_CMD_DWR,
                          DIAMETER_APP_BASE,
                          next_hop_by_hop(d), next_end_to_end(d));
    size_t off = (size_t)hl;
    avp_put_str(pkt, sizeof(pkt), &off, AVP_ORIGIN_HOST,
                DIAM_AVP_FLAG_MANDATORY, 0, c->diam_origin_host);
    avp_put_str(pkt, sizeof(pkt), &off, AVP_ORIGIN_REALM,
                DIAM_AVP_FLAG_MANDATORY, 0, c->diam_origin_realm);
    avp_put_u32(pkt, sizeof(pkt), &off, AVP_ORIGIN_STATE_ID,
                DIAM_AVP_FLAG_MANDATORY, 0, d->origin_state_id);
    finalize_length(pkt, off);
    d->last_dwr_at = time(NULL);
    return diameter_tx(d, pkt, off);
}

static int diameter_send_dpr(struct iwf_runtime *rt)
{
    diameter_state_t *d = &rt->map->diam;
    const iwf_config_t *c = &rt->cfg;
    uint8_t pkt[256];
    int hl = build_header(pkt, sizeof(pkt),
                          DIAM_HDR_FLAG_REQUEST, DIAMETER_CMD_DPR,
                          DIAMETER_APP_BASE,
                          next_hop_by_hop(d), next_end_to_end(d));
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

static int send_dwa(struct iwf_runtime *rt, uint32_t hbh, uint32_t e2e)
{
    diameter_state_t *d = &rt->map->diam;
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
                DIAM_AVP_FLAG_MANDATORY, 0, d->origin_state_id);
    finalize_length(pkt, off);
    return diameter_tx(d, pkt, off);
}

/* ====================================================================== */
/* S6d requests (one builder per command)                                 */
/* ====================================================================== */

static int build_s6d_request_header(struct iwf_runtime *rt, map_session_t *s,
                                    uint8_t *pkt, size_t cap,
                                    uint32_t cmd_code)
{
    diameter_state_t *d = &rt->map->diam;
    if (s->diameter_hop_by_hop == 0) s->diameter_hop_by_hop = next_hop_by_hop(d);
    if (s->diameter_end_to_end == 0) s->diameter_end_to_end = next_end_to_end(d);
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

int diameter_send_air(struct iwf_runtime *rt, map_session_t *s)
{
    if (!diameter_is_open(rt)) {
        LOGW("diameter", "AIR not sent imsi=%s: peer not open", s->imsi_str);
        return -1;
    }
    diameter_state_t *d = &rt->map->diam;
    uint8_t pkt[1024];
    int hl = build_s6d_request_header(rt, s, pkt, sizeof(pkt),
                                      DIAMETER_CMD_AIR);
    size_t off = (size_t)hl;

    if (build_s6d_route_avps(rt, pkt, sizeof(pkt), &off,
                             s->diameter_session_id) < 0) return -1;

    /* User-Name = IMSI (UTF-8 digits). */
    avp_put_str(pkt, sizeof(pkt), &off, AVP_USER_NAME,
                DIAM_AVP_FLAG_MANDATORY, 0, s->imsi_str);

    /* Visited-PLMN-Id (3 BCD bytes), V+M. */
    if (s->have_visited_plmn) {
        avp_put(pkt, sizeof(pkt), &off, AVP_3GPP_VISITED_PLMN_ID,
                DIAM_AVP_FLAG_VENDOR | DIAM_AVP_FLAG_MANDATORY,
                DIAMETER_VENDOR_3GPP, s->visited_plmn_bcd, 3);
    }

    /* Requested-UTRAN-GERAN-Authentication-Info grouped. */
    {
        uint8_t inner[64]; size_t io = 0;
        avp_put_u32(inner, sizeof(inner), &io, AVP_3GPP_NUM_REQ_VECTORS,
                    DIAM_AVP_FLAG_VENDOR | DIAM_AVP_FLAG_MANDATORY,
                    DIAMETER_VENDOR_3GPP, 5);
        avp_put_u32(inner, sizeof(inner), &io, AVP_3GPP_IMMEDIATE_RESPONSE_PREFERRED,
                    DIAM_AVP_FLAG_VENDOR,
                    DIAMETER_VENDOR_3GPP, 1);
        avp_put_grouped(pkt, sizeof(pkt), &off,
                        AVP_3GPP_REQ_UTRAN_GERAN_AUTH_INFO,
                        DIAM_AVP_FLAG_VENDOR | DIAM_AVP_FLAG_MANDATORY,
                        DIAMETER_VENDOR_3GPP, inner, io);
    }

    /* RAT-Type = GPRS (1001 per project spec). */
    avp_put_u32(pkt, sizeof(pkt), &off, AVP_3GPP_RAT_TYPE,
                DIAM_AVP_FLAG_VENDOR | DIAM_AVP_FLAG_MANDATORY,
                DIAMETER_VENDOR_3GPP, DIAM_RAT_TYPE_GPRS);

    finalize_length(pkt, off);
    LOGI("diameter", "TX AIR imsi=%s sid=%s len=%zu",
         s->imsi_str, s->diameter_session_id, off);
    int rc = diameter_tx(d, pkt, off);
    if (rc == 0) rt->map->stat_diam_tx++;
    return rc;
}

int diameter_send_ulr(struct iwf_runtime *rt, map_session_t *s)
{
    if (!diameter_is_open(rt)) return -1;
    diameter_state_t *d = &rt->map->diam;
    uint8_t pkt[1024];
    int hl = build_s6d_request_header(rt, s, pkt, sizeof(pkt),
                                      DIAMETER_CMD_ULR);
    size_t off = (size_t)hl;

    if (build_s6d_route_avps(rt, pkt, sizeof(pkt), &off,
                             s->diameter_session_id) < 0) return -1;

    avp_put_str(pkt, sizeof(pkt), &off, AVP_USER_NAME,
                DIAM_AVP_FLAG_MANDATORY, 0, s->imsi_str);
    if (s->have_visited_plmn) {
        avp_put(pkt, sizeof(pkt), &off, AVP_3GPP_VISITED_PLMN_ID,
                DIAM_AVP_FLAG_VENDOR | DIAM_AVP_FLAG_MANDATORY,
                DIAMETER_VENDOR_3GPP, s->visited_plmn_bcd, 3);
    }

    /* ULR-Flags: S6d-Indicator + Skip-Subscriber-Data (per spec). */
    avp_put_u32(pkt, sizeof(pkt), &off, AVP_3GPP_ULR_FLAGS,
                DIAM_AVP_FLAG_VENDOR | DIAM_AVP_FLAG_MANDATORY,
                DIAMETER_VENDOR_3GPP,
                ULR_FLAG_S6A_S6D_INDICATOR | ULR_FLAG_GPRS_SUBSCRIPTION_REQ);

    avp_put_u32(pkt, sizeof(pkt), &off, AVP_3GPP_RAT_TYPE,
                DIAM_AVP_FLAG_VENDOR | DIAM_AVP_FLAG_MANDATORY,
                DIAMETER_VENDOR_3GPP, DIAM_RAT_TYPE_GPRS);

    finalize_length(pkt, off);
    LOGI("diameter", "TX ULR imsi=%s sid=%s len=%zu",
         s->imsi_str, s->diameter_session_id, off);
    int rc = diameter_tx(d, pkt, off);
    if (rc == 0) rt->map->stat_diam_tx++;
    return rc;
}

int diameter_send_clr(struct iwf_runtime *rt, map_session_t *s)
{
    if (!diameter_is_open(rt)) return -1;
    diameter_state_t *d = &rt->map->diam;
    uint8_t pkt[512];
    int hl = build_s6d_request_header(rt, s, pkt, sizeof(pkt),
                                      DIAMETER_CMD_CLR);
    size_t off = (size_t)hl;

    if (build_s6d_route_avps(rt, pkt, sizeof(pkt), &off,
                             s->diameter_session_id) < 0) return -1;

    avp_put_str(pkt, sizeof(pkt), &off, AVP_USER_NAME,
                DIAM_AVP_FLAG_MANDATORY, 0, s->imsi_str);
    avp_put_u32(pkt, sizeof(pkt), &off, AVP_3GPP_CANCELLATION_TYPE,
                DIAM_AVP_FLAG_VENDOR | DIAM_AVP_FLAG_MANDATORY,
                DIAMETER_VENDOR_3GPP, 0 /* MME_UPDATE_PROCEDURE */);

    finalize_length(pkt, off);
    LOGI("diameter", "TX CLR imsi=%s sid=%s", s->imsi_str, s->diameter_session_id);
    int rc = diameter_tx(d, pkt, off);
    if (rc == 0) rt->map->stat_diam_tx++;
    return rc;
}

int diameter_send_pur(struct iwf_runtime *rt, map_session_t *s)
{
    if (!diameter_is_open(rt)) return -1;
    diameter_state_t *d = &rt->map->diam;
    uint8_t pkt[512];
    int hl = build_s6d_request_header(rt, s, pkt, sizeof(pkt),
                                      DIAMETER_CMD_PUR);
    size_t off = (size_t)hl;

    if (build_s6d_route_avps(rt, pkt, sizeof(pkt), &off,
                             s->diameter_session_id) < 0) return -1;

    avp_put_str(pkt, sizeof(pkt), &off, AVP_USER_NAME,
                DIAM_AVP_FLAG_MANDATORY, 0, s->imsi_str);
    avp_put_u32(pkt, sizeof(pkt), &off, AVP_3GPP_PUR_FLAGS,
                DIAM_AVP_FLAG_VENDOR,
                DIAMETER_VENDOR_3GPP, 0);

    finalize_length(pkt, off);
    LOGI("diameter", "TX PUR imsi=%s sid=%s", s->imsi_str, s->diameter_session_id);
    int rc = diameter_tx(d, pkt, off);
    if (rc == 0) rt->map->stat_diam_tx++;
    return rc;
}

/* ====================================================================== */
/* TX / RX plumbing                                                       */
/* ====================================================================== */

static int diameter_tx(diameter_state_t *d, const uint8_t *buf, size_t len)
{
    if (d->fd < 0) return -1;
    if (d->tx_used + len > sizeof(d->tx)) {
        LOGE("diameter", "tx buffer overflow (used=%zu add=%zu)", d->tx_used, len);
        return -1;
    }
    /* If nothing buffered, attempt a direct write. */
    size_t off = 0;
    if (d->tx_used == 0) {
        ssize_t r = send(d->fd, buf, len, MSG_NOSIGNAL);
        if (r > 0) off = (size_t)r;
        else if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGE("diameter", "send: %s", strerror(errno));
            close(d->fd); d->fd = -1; d->state = DIAM_CONN_CLOSED;
            return -1;
        }
    }
    if (off < len) {
        memcpy(d->tx + d->tx_used, buf + off, len - off);
        d->tx_used += (len - off);
    }
    return 0;
}

static void try_flush_tx(diameter_state_t *d)
{
    if (d->fd < 0 || d->tx_used == 0) return;
    ssize_t r = send(d->fd, d->tx, d->tx_used, MSG_NOSIGNAL);
    if (r > 0) {
        if ((size_t)r < d->tx_used)
            memmove(d->tx, d->tx + r, d->tx_used - r);
        d->tx_used -= (size_t)r;
    } else if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        LOGE("diameter", "flush send: %s", strerror(errno));
        close(d->fd); d->fd = -1; d->state = DIAM_CONN_CLOSED;
    }
}

/* EPOLLOUT on a connected TCP socket is always ready and busy-loops epoll. */
static void diameter_epoll_attach(struct iwf_runtime *rt, int fd)
{
    if (fd < 0 || rt->map->epoll_fd < 0) return;
    struct epoll_event ev = {
        .events   = EPOLLIN | EPOLLRDHUP,
        .data.u64 = MAP_EPOLL_ROLE_DIAMETER,
    };
    if (epoll_ctl(rt->map->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0)
        LOGW("diameter", "epoll_ctl ADD fd=%d: %s", fd, strerror(errno));
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

static int connect_peer(struct iwf_runtime *rt)
{
    diameter_state_t *d = &rt->map->diam;
    const iwf_config_t *c = &rt->cfg;

    if (d->fd >= 0) {
        if (rt->map->epoll_fd >= 0)
            epoll_ctl(rt->map->epoll_fd, EPOLL_CTL_DEL, d->fd, NULL);
        close(d->fd);
        d->fd = -1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { LOGE("diameter", "socket: %s", strerror(errno)); return -1; }
    set_nonblock(fd);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    memset(&d->peer, 0, sizeof(d->peer));
    d->peer.sin_family = AF_INET;
    d->peer.sin_port   = htons(c->diam_peer_port ? c->diam_peer_port : DIAMETER_PORT_DEFAULT);
    if (inet_pton(AF_INET, c->diam_peer_ip, &d->peer.sin_addr) != 1) {
        LOGE("diameter", "bad diameter peer ip %s", c->diam_peer_ip);
        close(fd); return -1;
    }

    int rc = connect(fd, (struct sockaddr*)&d->peer, sizeof(d->peer));
    if (rc < 0) {
        if (errno == EINPROGRESS) {
            if (diameter_wait_connected(fd) < 0) {
                close(fd);
                return -1;
            }
        } else {
            LOGE("diameter", "connect %s:%u: %s",
                 c->diam_peer_ip, c->diam_peer_port, strerror(errno));
            close(fd);
            return -1;
        }
    }
    d->fd = fd;
    d->state = DIAM_CONN_CER_SENT;
    LOGI("diameter", "TCP connected to %s:%u",
         c->diam_peer_ip, c->diam_peer_port);
    diameter_epoll_attach(rt, fd);
    return diameter_send_cer(rt);
}

static void schedule_reconnect(struct iwf_runtime *rt)
{
    diameter_state_t *d = &rt->map->diam;
    if (d->reconnect_backoff_s == 0) d->reconnect_backoff_s = 1;
    else if (d->reconnect_backoff_s < 60) d->reconnect_backoff_s *= 2;
    LOGW("diameter", "scheduling reconnect in %us", d->reconnect_backoff_s);
}

/* ====================================================================== */
/* RX dispatch                                                            */
/* ====================================================================== */

static void on_cea(struct iwf_runtime *rt, const uint8_t *body, size_t len)
{
    uint32_t rc = 0;
    if (diameter_get_result_code(body, len, &rc) == 0 && rc == DIAM_RC_SUCCESS) {
        rt->map->diam.state = DIAM_CONN_OPEN;
        rt->map->diam.reconnect_backoff_s = 0;
        LOGI("diameter", "peer up: CEA Result-Code=2001 (S6d ready)");
    } else {
        LOGE("diameter", "CEA Result-Code=%u, closing peer", (unsigned)rc);
        close(rt->map->diam.fd); rt->map->diam.fd = -1;
        rt->map->diam.state = DIAM_CONN_CLOSED;
        schedule_reconnect(rt);
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

static void dispatch_message(struct iwf_runtime *rt,
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

    rt->map->diam.last_rx_at = time(NULL);
    rt->map->stat_diam_rx++;

    bool is_req = (flags & DIAM_HDR_FLAG_REQUEST) != 0;
    if (is_req) {
        if (cmd_code == DIAMETER_CMD_DWR) {
            LOGD("diameter", "RX DWR -> answering DWA");
            send_dwa(rt, hbh, e2e);
            return;
        }
        if (cmd_code == DIAMETER_CMD_DPR) {
            LOGI("diameter", "RX DPR from peer; closing");
            close(rt->map->diam.fd); rt->map->diam.fd = -1;
            rt->map->diam.state = DIAM_CONN_CLOSED;
            schedule_reconnect(rt);
            return;
        }
        /* CER and S6d requests from the peer to us: not expected for a client. */
        LOGW("diameter", "unexpected request cmd=%u app=%u (peer initiated)",
             (unsigned)cmd_code, (unsigned)app_id);
        return;
    }

    /* Answer. */
    if (cmd_code == DIAMETER_CMD_CER) {
        on_cea(rt, body, body_len);
        return;
    }
    if (cmd_code == DIAMETER_CMD_DWR) {
        /* DWA: peer is alive; nothing more to do. */
        LOGD("diameter", "RX DWA");
        return;
    }
    if (cmd_code == DIAMETER_CMD_DPR) {
        LOGI("diameter", "RX DPA");
        return;
    }
    on_answer(rt, cmd_code, body, body_len);
}

void diameter_on_readable(struct iwf_runtime *rt)
{
    diameter_state_t *d = &rt->map->diam;
    if (d->fd < 0) return;

    for (;;) {
        if (d->rx_used >= sizeof(d->rx)) {
            LOGE("diameter", "rx buffer full (%zu); resetting connection", d->rx_used);
            close(d->fd); d->fd = -1; d->state = DIAM_CONN_CLOSED;
            d->rx_used = 0; d->tx_used = 0;
            return;
        }
        ssize_t r = recv(d->fd, d->rx + d->rx_used, sizeof(d->rx) - d->rx_used, 0);
        if (r > 0) {
            d->rx_used += (size_t)r;
        } else if (r == 0) {
            LOGW("diameter", "peer closed TCP connection");
            close(d->fd); d->fd = -1; d->state = DIAM_CONN_CLOSED;
            schedule_reconnect(rt);
            return;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EINTR) continue;
            LOGE("diameter", "recv: %s", strerror(errno));
            close(d->fd); d->fd = -1; d->state = DIAM_CONN_CLOSED;
            schedule_reconnect(rt);
            return;
        }
    }

    /* Drain whole messages from the rx buffer. */
    size_t consumed = 0;
    while (d->rx_used - consumed >= 20) {
        const uint8_t *pkt = d->rx + consumed;
        if (pkt[0] != DIAMETER_VERSION) {
            LOGE("diameter", "bad version 0x%02x; resetting peer", pkt[0]);
            close(d->fd); d->fd = -1; d->state = DIAM_CONN_CLOSED;
            d->rx_used = 0; return;
        }
        uint32_t mlen = get_be24(pkt + 1);
        if (mlen < 20 || mlen > sizeof(d->rx)) {
            LOGE("diameter", "bad msg length %u", (unsigned)mlen);
            close(d->fd); d->fd = -1; d->state = DIAM_CONN_CLOSED;
            d->rx_used = 0; return;
        }
        if (d->rx_used - consumed < mlen) break;          /* need more bytes */
        dispatch_message(rt, pkt, mlen);
        consumed += mlen;
    }
    if (consumed) {
        if (consumed < d->rx_used)
            memmove(d->rx, d->rx + consumed, d->rx_used - consumed);
        d->rx_used -= consumed;
    }

    try_flush_tx(d);
}

/* ====================================================================== */
/* Module init / tick / shutdown                                          */
/* ====================================================================== */

int diameter_init(struct iwf_runtime *rt)
{
    diameter_state_t *d = &rt->map->diam;
    memset(d, 0, sizeof(*d));
    d->fd = -1;
    d->watchdog_timerfd = -1;
    d->state = DIAM_CONN_CLOSED;
    d->origin_state_id = (uint32_t)time(NULL);
    d->hop_by_hop_seed = (uint32_t)rand();
    d->end_to_end_seed = (uint32_t)rand();

    if (!rt->cfg.diam_peer_ip[0] ||
        !rt->cfg.diam_origin_host[0] || !rt->cfg.diam_origin_realm[0] ||
        !rt->cfg.diam_dest_realm[0]) {
        LOGE("diameter", "missing required [diameter_s6d] config: "
                         "peer_ip / origin_host / origin_realm / dest_realm");
        return -1;
    }

    /* Watchdog timer (Tw): RFC 6733 §3.4.1 default 30s, +/- jitter; we
     * stick to a flat period - good enough for an STP-fronted deployment. */
    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (tfd < 0) { LOGE("diameter", "timerfd: %s", strerror(errno)); return -1; }
    int ms = rt->cfg.diam_watchdog_ms > 0 ? rt->cfg.diam_watchdog_ms : 30000;
    struct itimerspec its = {
        .it_interval = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L },
        .it_value    = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L },
    };
    timerfd_settime(tfd, 0, &its, NULL);
    d->watchdog_timerfd = tfd;

    if (connect_peer(rt) < 0) {
        schedule_reconnect(rt);
        /* Module init still returns 0 - main loop will attempt reconnect. */
    }
    return 0;
}

void diameter_on_dwa_tick(struct iwf_runtime *rt)
{
    diameter_state_t *d = &rt->map->diam;
    uint64_t exp;
    ssize_t r = read(d->watchdog_timerfd, &exp, sizeof(exp));
    (void)r;

    if (d->state == DIAM_CONN_OPEN) {
        diameter_send_dwr(rt);
        return;
    }
    /* If closed/connecting and backoff elapsed, retry. */
    if (d->state == DIAM_CONN_CLOSED && d->reconnect_backoff_s > 0) {
        time_t now = time(NULL);
        if (now - d->last_rx_at >= (time_t)d->reconnect_backoff_s) {
            LOGI("diameter", "attempting reconnect (backoff=%us)",
                 d->reconnect_backoff_s);
            d->last_rx_at = now;
            connect_peer(rt);
        }
    }
}

void diameter_shutdown(struct iwf_runtime *rt)
{
    if (!rt->map) return;
    diameter_state_t *d = &rt->map->diam;
    if (d->state == DIAM_CONN_OPEN) {
        diameter_send_dpr(rt);
        try_flush_tx(d);
    }
    if (d->watchdog_timerfd >= 0) close(d->watchdog_timerfd);
    if (d->fd >= 0) close(d->fd);
    d->watchdog_timerfd = -1;
    d->fd = -1;
    d->state = DIAM_CONN_CLOSED;
}

int  diameter_get_fd(const struct iwf_runtime *rt)
{
    return rt->map ? rt->map->diam.fd : -1;
}
int  diameter_get_dwa_timer_fd(const struct iwf_runtime *rt)
{
    return rt->map ? rt->map->diam.watchdog_timerfd : -1;
}
bool diameter_is_open(const struct iwf_runtime *rt)
{
    return rt->map && rt->map->diam.state == DIAM_CONN_OPEN && rt->map->diam.fd >= 0;
}
