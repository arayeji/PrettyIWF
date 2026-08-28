/*
 * sip_iwf.c — SIP GMSC B2BUA (Kamailio Mg/Mj → local CS or roam MSRN).
 */

#include "sip_iwf.h"
#include "runtime.h"
#include "config.h"
#include "logging.h"
#include "map_codec.h"
#include "map_iwf.h"
#include "isup_call.h"
#include "in_iwf.h"
#ifdef GSUP_PROXY_ENABLED
#  include "msisdn_db.h"
#  include "gsup_map_proxy.h"
#endif

#include "uthash.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define SIP_MSG_MAX     8192
#define SIP_SDP_MAX     2048
#define SIP_CALL_MAX    256
#define SIP_HDR_MAX     512

typedef enum {
    SIP_ST_TRYING = 1,
    SIP_ST_WAIT_PRN,
    SIP_ST_EARLY,
    SIP_ST_CONNECTED,
    SIP_ST_TERM,
} sip_state_t;

typedef enum {
    SIP_CLASS_MT_LOCAL = 1,
    SIP_CLASS_MT_ROAM,
    SIP_CLASS_MO,
} sip_class_t;

typedef struct sip_call {
    uint32_t            id;
    sip_state_t         state;
    sip_class_t         klass;
    char                msisdn[24];
    char                imsi[16];
    char                vlr[24];
    char                msrn[24];

    struct sockaddr_in  north_addr;
    int                 north_tcp;          /* -1 = UDP */
    char                north_callid[128];
    char                north_from[SIP_HDR_MAX];
    char                north_to[SIP_HDR_MAX];
    char                north_via[1024];
    char                north_cseq[64];
    int                 north_cseq_num;
    char                to_tag[24];

    struct sockaddr_in  south_addr;
    char                south_ruri[160];
    char                south_callid[128];
    char                south_from[SIP_HDR_MAX];
    char                south_to[SIP_HDR_MAX];
    char                south_branch[40];
    char                south_from_tag[24];
    int                 south_cseq;
    int                 south_invite_sent;
    int                 south_final;
    int                 south_isup;
    uint16_t            cic;
    int                 in_pending;

    char                sdp[SIP_SDP_MAX];
    size_t              sdp_len;

    int                 sip_status;
    time_t              created;
    time_t              last;
    int                 invite_timeout_ms;

    UT_hash_handle      hh;
} sip_call_t;

typedef struct {
    int                 fd;
    struct sockaddr_in  addr;
    char                buf[SIP_MSG_MAX];
    size_t              len;
} sip_tcp_t;

typedef struct {
    int                 is_req;
    char                method[16];
    int                 status;
    char                reason[48];
    char                ruri[256];
    char                via[1024];
    char                from[SIP_HDR_MAX];
    char                to[SIP_HDR_MAX];
    char                callid[128];
    char                cseq[64];
    int                 cseq_num;
    char                cseq_method[16];
    char                contact[256];
    const char         *body;
    size_t              body_len;
} sip_msg_t;

typedef struct {
    struct iwf_runtime *rt;
    int                 epfd;
    int                 udp_fd;
    int                 tcp_fd;
    char                via_host[64];
    uint16_t            via_port;
    sip_tcp_t           tcp[SIP_EPOLL_TCP_MAX];
    sip_call_t         *calls;
    uint32_t            next_id;
    uint32_t            seq;
    int                 n_calls;
    time_t              last_options;
    unsigned            stat_invite;
    unsigned            stat_local;
    unsigned            stat_roam;
    unsigned            stat_fail;
} sip_iwf_state_t;

static sip_iwf_state_t g_sip;

static int set_nb(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static void sip_hdr_copy(char *dst, size_t cap, const char *src)
{
    if (!dst || !cap) return;
    dst[0] = '\0';
    if (!src) return;
    size_t n = strlen(src);
    if (n >= cap) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static int sip_peer_parse(const char *in, struct sockaddr_in *out)
{
    char host[128];
    uint16_t port = 5060;
    const char *p = in ? in : "";
    if (!strncmp(p, "sip:", 4)) p += 4;
    while (*p == '/') p++;

    char buf[128];
    snprintf(buf, sizeof(buf), "%s", p);
    char *semi = strchr(buf, ';');
    if (semi) *semi = '\0';
    char *sl = strchr(buf, '/');
    if (sl) *sl = '\0';
    char *at = strrchr(buf, '@');
    char *h = at ? at + 1 : buf;
    char *col = strrchr(h, ':');
    if (col && strchr(h, ':') == col) {
        *col = '\0';
        int po = atoi(col + 1);
        if (po > 0 && po < 65536) port = (uint16_t)po;
    }
    snprintf(host, sizeof(host), "%s", h);

    memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    out->sin_port = htons(port);
    if (!host[0] || inet_pton(AF_INET, host, &out->sin_addr) != 1)
        return -1;
    return 0;
}

static int sip_addr_eq(const struct sockaddr_in *a, const struct sockaddr_in *b)
{
    return a && b && a->sin_addr.s_addr == b->sin_addr.s_addr;
}

static void sip_digits(const char *in, char *out, size_t cap)
{
    size_t n = 0;
    if (!out || !cap) return;
    out[0] = '\0';
    if (!in) return;
    if (*in == '+') in++;
    for (; *in && n + 1 < cap; in++) {
        if (isdigit((unsigned char)*in))
            out[n++] = *in;
    }
    out[n] = '\0';
}

static void sip_msisdn_from_uri(const char *uri, char *out, size_t cap)
{
    char raw[64] = "";
    const char *p = uri ? uri : "";
    /* name-addr: "display" <sip:user@host>;tag=… — use the URI in <>. */
    const char *lt = strchr(p, '<');
    if (lt)
        p = lt + 1;
    else {
        while (*p == ' ' || *p == '"') {
            if (*p == '"') {
                p++;
                while (*p && *p != '"') p++;
                if (*p == '"') p++;
                continue;
            }
            p++;
        }
    }
    while (*p == ' ' || *p == '<') p++;
    if (!strncasecmp(p, "tel:", 4)) {
        sip_digits(p + 4, raw, sizeof(raw));
    } else {
        if (!strncasecmp(p, "sip:", 4)) p += 4;
        char buf[128];
        snprintf(buf, sizeof(buf), "%s", p);
        char *gt = strchr(buf, '>');
        if (gt) *gt = '\0';
        char *at = strchr(buf, '@');
        if (at) *at = '\0';
        char *sc = strchr(buf, ';');
        if (sc) *sc = '\0';
        sip_digits(buf, raw, sizeof(raw));
    }
    if (raw[0])
        map_normalize_msisdn_digits(raw, out, cap);
    else if (out && cap)
        out[0] = '\0';
}

static const char *sip_hdr_val(const char *msg, const char *name)
{
    size_t nlen = strlen(name);
    const char *p = msg;
    while (p && *p) {
        const char *eol = strstr(p, "\r\n");
        if (!eol) break;
        if (eol == p) break;
        if (!strncasecmp(p, name, nlen) && p[nlen] == ':') {
            const char *v = p + nlen + 1;
            while (*v == ' ' || *v == '\t') v++;
            return v;
        }
        p = eol + 2;
    }
    return NULL;
}

static void sip_hdr_line(const char *src, char *dst, size_t cap)
{
    dst[0] = '\0';
    if (!src || !cap) return;
    size_t n = 0;
    for (; src[n] && n + 1 < cap; n++) {
        if (src[n] == '\r' || src[n] == '\n') break;
    }
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static int sip_parse(const char *raw, size_t len, sip_msg_t *m)
{
    memset(m, 0, sizeof(*m));
    if (!raw || len < 8) return -1;
    const char *eol = strstr(raw, "\r\n");
    if (!eol) return -1;
    char line[512];
    size_t ll = (size_t)(eol - raw);
    if (ll >= sizeof(line)) ll = sizeof(line) - 1;
    memcpy(line, raw, ll);
    line[ll] = '\0';

    if (!strncmp(line, "SIP/2.0 ", 8)) {
        m->is_req = 0;
        m->status = atoi(line + 8);
        const char *rs = line + 8;
        while (*rs && *rs != ' ') rs++;
        while (*rs == ' ') rs++;
        sip_hdr_copy(m->reason, sizeof(m->reason), rs);
    } else {
        m->is_req = 1;
        char *sp = strchr(line, ' ');
        if (!sp) return -1;
        *sp = '\0';
        sip_hdr_copy(m->method, sizeof(m->method), line);
        char *sp2 = strchr(sp + 1, ' ');
        if (sp2) *sp2 = '\0';
        snprintf(m->ruri, sizeof(m->ruri), "%s", sp + 1);
    }

    const char *v;
    if ((v = sip_hdr_val(raw, "Via")) || (v = sip_hdr_val(raw, "v"))) {
        /* collect Via chain until a non-Via header */
        const char *p = raw;
        char *w = m->via;
        size_t left = sizeof(m->via);
        while (p && left > 8) {
            const char *e = strstr(p, "\r\n");
            if (!e || e == p) break;
            if (!strncasecmp(p, "Via:", 4) || !strncasecmp(p, "v:", 2)) {
                size_t n = (size_t)(e - p);
                if (n + 3 >= left) break;
                memcpy(w, p, n);
                w += n;
                memcpy(w, "\r\n", 2);
                w += 2;
                left -= n + 2;
                *w = '\0';
            } else if (p[0] == ' ' || p[0] == '\t') {
                /* folded — skip */
            } else if (m->via[0])
                break;
            p = e + 2;
        }
    }
    if ((v = sip_hdr_val(raw, "From")) || (v = sip_hdr_val(raw, "f")))
        sip_hdr_line(v, m->from, sizeof(m->from));
    if ((v = sip_hdr_val(raw, "To")) || (v = sip_hdr_val(raw, "t")))
        sip_hdr_line(v, m->to, sizeof(m->to));
    if ((v = sip_hdr_val(raw, "Call-ID")) || (v = sip_hdr_val(raw, "i")))
        sip_hdr_line(v, m->callid, sizeof(m->callid));
    if ((v = sip_hdr_val(raw, "CSeq"))) {
        sip_hdr_line(v, m->cseq, sizeof(m->cseq));
        m->cseq_num = atoi(m->cseq);
        const char *cm = m->cseq;
        while (*cm && *cm != ' ') cm++;
        while (*cm == ' ') cm++;
        sip_hdr_copy(m->cseq_method, sizeof(m->cseq_method), cm);
    }
    if ((v = sip_hdr_val(raw, "Contact")) || (v = sip_hdr_val(raw, "m")))
        sip_hdr_line(v, m->contact, sizeof(m->contact));

    const char *sep = strstr(raw, "\r\n\r\n");
    if (sep) {
        m->body = sep + 4;
        size_t hdr = (size_t)(m->body - raw);
        m->body_len = (len > hdr) ? (len - hdr) : 0;
        const char *cl = sip_hdr_val(raw, "Content-Length");
        if (!cl) cl = sip_hdr_val(raw, "l");
        if (cl) {
            int n = atoi(cl);
            if (n >= 0 && (size_t)n < m->body_len)
                m->body_len = (size_t)n;
        }
    }
    return (m->callid[0] || m->is_req) ? 0 : -1;
}

static int sip_complete_len(const char *buf, size_t n)
{
    const char *sep = NULL;
    for (size_t i = 0; i + 3 < n; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' &&
            buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            sep = buf + i;
            break;
        }
    }
    if (!sep) return 0;
    size_t hdr = (size_t)(sep - buf) + 4;
    int cl = 0;
    const char *v = sip_hdr_val(buf, "Content-Length");
    if (!v) v = sip_hdr_val(buf, "l");
    if (v) cl = atoi(v);
    if (cl < 0) cl = 0;
    size_t need = hdr + (size_t)cl;
    if (n < need) return 0;
    return (int)need;
}

static uint32_t sip_next_seq(void)
{
    g_sip.seq++;
    if (!g_sip.seq) g_sip.seq = 1;
    return g_sip.seq;
}

static void sip_mint(char *out, size_t cap, const char *pfx)
{
    snprintf(out, cap, "%s%08x%04x", pfx ? pfx : "",
             sip_next_seq(), (unsigned)(time(NULL) & 0xffff));
}

static const char *sip_reason(int code)
{
    switch (code) {
    case 100: return "Trying";
    case 180: return "Ringing";
    case 183: return "Session Progress";
    case 200: return "OK";
    case 202: return "Accepted";
    case 400: return "Bad Request";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 408: return "Request Timeout";
    case 480: return "Temporarily Unavailable";
    case 481: return "Call/Transaction Does Not Exist";
    case 486: return "Busy Here";
    case 487: return "Request Terminated";
    case 488: return "Not Acceptable Here";
    case 500: return "Server Internal Error";
    case 501: return "Not Implemented";
    case 503: return "Service Unavailable";
    default:  return "Unknown";
    }
}

static int sip_send_bytes(int fd, const struct sockaddr_in *to,
                          const char *buf, size_t len)
{
    if (fd < 0 || !buf || !len) return -1;
    ssize_t r;
    if (to) {
        r = sendto(fd, buf, len, 0, (const struct sockaddr *)to, sizeof(*to));
    } else {
        r = send(fd, buf, len, 0);
    }
    if (r < 0) {
        LOGW("sip", "send failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static int sip_north_fd(const sip_call_t *c)
{
    if (c->north_tcp >= 0 && c->north_tcp < SIP_EPOLL_TCP_MAX &&
        g_sip.tcp[c->north_tcp].fd >= 0)
        return g_sip.tcp[c->north_tcp].fd;
    return g_sip.udp_fd;
}

static int sip_send_north(const sip_call_t *c, const char *buf, size_t len)
{
    int fd = sip_north_fd(c);
    if (c->north_tcp >= 0)
        return sip_send_bytes(fd, NULL, buf, len);
    return sip_send_bytes(fd, &c->north_addr, buf, len);
}

static int sip_send_south(const sip_call_t *c, const char *buf, size_t len)
{
    if (g_sip.udp_fd < 0) return -1;
    return sip_send_bytes(g_sip.udp_fd, &c->south_addr, buf, len);
}

static void sip_reply_ex(const sip_call_t *c, int code, const char *body,
                         size_t blen, const char *ctype)
{
    char to[SIP_HDR_MAX + 40];
    if (c->to_tag[0] && !strcasestr(c->north_to, ";tag="))
        snprintf(to, sizeof(to), "%s;tag=%s", c->north_to, c->to_tag);
    else
        snprintf(to, sizeof(to), "%s", c->north_to);

    char msg[SIP_MSG_MAX];
    int n = snprintf(msg, sizeof(msg),
        "SIP/2.0 %d %s\r\n"
        "%s"
        "From: %s\r\n"
        "To: %s\r\n"
        "Call-ID: %s\r\n"
        "CSeq: %s\r\n"
        "Contact: <sip:iwf@%s:%u>\r\n"
        "Server: PrettyIWF\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "\r\n",
        code, sip_reason(code),
        c->north_via[0] ? c->north_via : "",
        c->north_from, to, c->north_callid, c->north_cseq,
        g_sip.via_host, (unsigned)g_sip.via_port,
        (body && blen) ? (ctype ? ctype : "application/sdp") : "application/sdp",
        body ? blen : 0);
    if (n < 0 || (size_t)n >= sizeof(msg)) return;
    if (body && blen && (size_t)n + blen < sizeof(msg)) {
        memcpy(msg + n, body, blen);
        n += (int)blen;
    }
    sip_send_north(c, msg, (size_t)n);
}

static void sip_reply(const sip_call_t *c, int code)
{
    sip_reply_ex(c, code, NULL, 0, NULL);
}

static void sip_reply_stateless(const struct sockaddr_in *from, int tcp_idx,
                                const sip_msg_t *m, int code)
{
    sip_call_t tmp;
    memset(&tmp, 0, sizeof(tmp));
    if (from) tmp.north_addr = *from;
    tmp.north_tcp = tcp_idx;
    sip_hdr_copy(tmp.north_via, sizeof(tmp.north_via), m->via);
    sip_hdr_copy(tmp.north_from, sizeof(tmp.north_from), m->from);
    sip_hdr_copy(tmp.north_to, sizeof(tmp.north_to), m->to);
    sip_hdr_copy(tmp.north_callid, sizeof(tmp.north_callid), m->callid);
    sip_hdr_copy(tmp.north_cseq, sizeof(tmp.north_cseq), m->cseq);
    sip_reply(&tmp, code);
}

static sip_call_t *sip_find_north(const char *callid)
{
    sip_call_t *c = NULL;
    if (!callid || !callid[0]) return NULL;
    HASH_FIND_STR(g_sip.calls, callid, c);
    return c;
}

static sip_call_t *sip_find_south(const char *callid)
{
    sip_call_t *c, *tmp;
    if (!callid || !callid[0]) return NULL;
    HASH_ITER(hh, g_sip.calls, c, tmp) {
        if (!strcmp(c->south_callid, callid))
            return c;
    }
    return NULL;
}

static sip_call_t *sip_find_id(uint32_t id)
{
    sip_call_t *c, *tmp;
    HASH_ITER(hh, g_sip.calls, c, tmp) {
        if (c->id == id) return c;
    }
    return NULL;
}

static void sip_cdr(const sip_call_t *c, const char *event)
{
    LOGI("sip",
         "CDR event=%s id=%u class=%s msisdn=%s imsi=%s vlr=%s msrn=%s "
         "status=%d callid=%s",
         event, c->id,
         c->klass == SIP_CLASS_MT_LOCAL ? "local" :
         c->klass == SIP_CLASS_MT_ROAM ? "roam" :
         c->klass == SIP_CLASS_MO ? "mo" : "-",
         c->msisdn[0] ? c->msisdn : "-",
         c->imsi[0] ? c->imsi : "-",
         c->vlr[0] ? c->vlr : "-",
         c->msrn[0] ? c->msrn : "-",
         c->sip_status,
         c->north_callid[0] ? c->north_callid : "-");
}

static void sip_call_free(sip_call_t *c)
{
    if (!c) return;
    in_iwf_cancel(c->id);
    if (c->south_isup)
        isup_call_detach(c->id);
    HASH_DEL(g_sip.calls, c);
    if (g_sip.n_calls > 0) g_sip.n_calls--;
    free(c);
}

static sip_call_t *sip_call_new(const sip_msg_t *m,
                                const struct sockaddr_in *from, int tcp_idx)
{
    if (g_sip.n_calls >= g_sip.rt->cfg.sip_max_sessions)
        return NULL;
    sip_call_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->id = ++g_sip.next_id;
    c->state = SIP_ST_TRYING;
    c->north_tcp = tcp_idx;
    if (from) c->north_addr = *from;
    sip_hdr_copy(c->north_callid, sizeof(c->north_callid), m->callid);
    sip_hdr_copy(c->north_from, sizeof(c->north_from), m->from);
    sip_hdr_copy(c->north_to, sizeof(c->north_to), m->to);
    sip_hdr_copy(c->north_via, sizeof(c->north_via), m->via);
    sip_hdr_copy(c->north_cseq, sizeof(c->north_cseq), m->cseq);
    c->north_cseq_num = m->cseq_num;
    sip_mint(c->to_tag, sizeof(c->to_tag), "t");
    if (m->body && m->body_len && m->body_len < sizeof(c->sdp)) {
        memcpy(c->sdp, m->body, m->body_len);
        c->sdp_len = m->body_len;
    }
    c->created = c->last = time(NULL);
    c->invite_timeout_ms = g_sip.rt->cfg.sip_invite_timeout_ms;
    HASH_ADD_STR(g_sip.calls, north_callid, c);
    g_sip.n_calls++;
    return c;
}

static int sip_vlr_is_local(const iwf_config_t *cfg, const char *vlr)
{
    if (!cfg || !vlr || !vlr[0]) return 0;
    if (cfg->local_msc_vlr_gt[0] && !strcmp(vlr, cfg->local_msc_vlr_gt))
        return 1;
    if (cfg->local_msc_msc_gt[0] && !strcmp(vlr, cfg->local_msc_msc_gt))
        return 1;
    if (cfg->map_local_gt[0] && !strcmp(vlr, cfg->map_local_gt))
        return 1;
#ifdef SMS_IWF_ENABLED
    if (cfg->sms_local_msc_gt[0] && !strcmp(vlr, cfg->sms_local_msc_gt))
        return 1;
#endif
    return 0;
}

static int sip_vlr_is_roam(const iwf_config_t *cfg, const char *vlr)
{
    if (!cfg || !vlr || !vlr[0]) return 0;
    if (cfg->n_roam_cs_vlr_prefix <= 0)
        return !sip_vlr_is_local(cfg, vlr);
    for (int i = 0; i < cfg->n_roam_cs_vlr_prefix; i++) {
        const char *p = cfg->roam_cs_vlr_prefix[i];
        if (p[0] && !strncmp(vlr, p, strlen(p)))
            return 1;
    }
    return 0;
}

static int sip_msrn_ok(const iwf_config_t *cfg, const char *msrn)
{
    if (!msrn || !msrn[0]) return 0;
    if (!cfg->roam_cs_msrn_prefix_ok[0]) return 1;
    return !strncmp(msrn, cfg->roam_cs_msrn_prefix_ok,
                    strlen(cfg->roam_cs_msrn_prefix_ok));
}

static int sip_map_to_sip(int map_err)
{
    switch (map_err) {
    case 1:  return 404; /* unknownSubscriber */
    case 8:  return 403; /* roamingNotAllowed */
    case 27: return 480; /* absentSubscriber */
    case 39: return 503; /* noRoamingNumberAvailable */
    default: return 503;
    }
}

static int sip_resolve_mt(sip_call_t *c)
{
    const iwf_config_t *cfg = &g_sip.rt->cfg;
    char imsi[16] = "";
    char vlr[24] = "";
    int cs_active = 0;

#ifdef GSUP_PROXY_ENABLED
    msisdn_db_cs_t cs;
    if (msisdn_db_lookup_cs(c->msisdn, &cs) == 0) {
        snprintf(imsi, sizeof(imsi), "%s", cs.imsi);
        cs_active = cs.cs_active ? 1 : 0;
        if (cs.have_vlr)
            snprintf(vlr, sizeof(vlr), "%s", cs.vlr_number);
        if (cs.imsi[0])
            gsup_map_proxy_note_msisdn(cs.imsi, c->msisdn);
    }
    if (!imsi[0])
        (void)gsup_map_proxy_imsi_for_msisdn(c->msisdn, imsi, sizeof(imsi));
#else
    (void)cfg;
#endif

    if (!imsi[0]) {
        LOGI("sip", "resolve msisdn=%s -> 404 unknown", c->msisdn);
        return 404;
    }
    snprintf(c->imsi, sizeof(c->imsi), "%s", imsi);
    snprintf(c->vlr, sizeof(c->vlr), "%s", vlr);

    if (!cs_active || !vlr[0]) {
        LOGI("sip", "resolve msisdn=%s imsi=%s -> 480 absent vlr=%s cs=%d",
             c->msisdn, imsi, vlr[0] ? vlr : "-", cs_active);
        return 480;
    }
    if (sip_vlr_is_local(cfg, vlr)) {
        c->klass = SIP_CLASS_MT_LOCAL;
        return 0;
    }
    if (sip_vlr_is_roam(cfg, vlr)) {
        c->klass = SIP_CLASS_MT_ROAM;
        return 0;
    }
    LOGW("sip", "resolve msisdn=%s vlr=%s not local and not roam_cs -> 503",
         c->msisdn, vlr);
    return 503;
}

static int sip_originate_south(sip_call_t *c, const char *user);
static void sip_fail(sip_call_t *c, int code);

static void sip_on_in(void *user, int result, const char *connect_dest)
{
    sip_call_t *c = user;
    sip_call_t *cur, *tmp;
    int alive = 0;
    HASH_ITER(hh, g_sip.calls, cur, tmp) {
        if (cur == c) { alive = 1; break; }
    }
    if (!alive) return;
    c->in_pending = 0;
    if (result == IWF_IN_FAIL) {
        sip_fail(c, 503);
        return;
    }
    const char *dest = c->msrn[0] ? c->msrn : c->msisdn;
    if (result == IWF_IN_CONNECT && connect_dest && connect_dest[0])
        dest = connect_dest;
    if (sip_originate_south(c, dest) < 0)
        sip_fail(c, 503);
}

static int sip_originate_south_isup(sip_call_t *c, const char *dst,
                                      const char *cli)
{
    int pres = (!cli || !cli[0]);
    c->south_isup = 1;
    if (isup_call_originate(g_sip.rt, c->id, dst, cli, pres) < 0)
        return -1;
    c->south_invite_sent = 1;
    c->last = time(NULL);
    LOGI("sip", "id=%u TX IAM called=%s class=roam cli=%s",
         c->id, dst, cli && cli[0] ? cli : "-");
    return 0;
}

static int sip_originate_south(sip_call_t *c, const char *user)
{
    const iwf_config_t *cfg = &g_sip.rt->cfg;
    const iwf_cs_route_t *rte = iwf_cs_route_lookup(cfg, user);

    char dst[32];
    if (user && !strncmp(user, "98", 2))
        snprintf(dst, sizeof(dst), "0%s", user + 2);
    else
        snprintf(dst, sizeof(dst), "%s", user ? user : "");

    char caller[32] = "", cli[36] = "";
    if (c->klass == SIP_CLASS_MT_ROAM && cfg->roam_cs_cli[0]) {
        snprintf(cli, sizeof(cli), "%s", cfg->roam_cs_cli);
    } else {
        sip_msisdn_from_uri(c->north_from, caller, sizeof(caller));
        if (caller[0] == '0')
            snprintf(cli, sizeof(cli), "+98%s", caller + 1);
        else if (!strncmp(caller, "98", 2))
            snprintf(cli, sizeof(cli), "+%s", caller);
        else if (caller[0])
            snprintf(cli, sizeof(cli), "+98%s", caller);
    }

    int south_bicc = 0;
    if (c->klass == SIP_CLASS_MT_ROAM)
        south_bicc = isup_call_south_is_bicc(g_sip.rt, user);
    if (south_bicc)
        return sip_originate_south_isup(c, user && user[0] ? user : dst, cli);

    const char *peer = NULL;
    if (c->klass == SIP_CLASS_MT_LOCAL)
        peer = cfg->local_cs_sip_peer;
    else if (c->klass == SIP_CLASS_MT_ROAM) {
        if (rte && rte->sip_peer[0])
            peer = rte->sip_peer;
        else
            peer = cfg->roam_cs_sipi_peer;
    } else
        peer = cfg->sip_kamailio_peer;

    if (!peer || !peer[0] || sip_peer_parse(peer, &c->south_addr) < 0) {
        LOGW("sip", "id=%u no southbound peer for class=%d", c->id, c->klass);
        return -1;
    }

    char host[32];
    inet_ntop(AF_INET, &c->south_addr.sin_addr, host, sizeof(host));
    uint16_t port = ntohs(c->south_addr.sin_port);

    snprintf(c->south_ruri, sizeof(c->south_ruri),
             "sip:%s@%s:%u", dst, host, (unsigned)port);
    sip_mint(c->south_callid, sizeof(c->south_callid), "");
    size_t n = strlen(c->south_callid);
    snprintf(c->south_callid + n, sizeof(c->south_callid) - n, "@%s",
             g_sip.via_host);
    sip_mint(c->south_from_tag, sizeof(c->south_from_tag), "f");
    sip_mint(c->south_branch, sizeof(c->south_branch), "z9hG4bK");
    c->south_cseq = 1;

    snprintf(c->south_from, sizeof(c->south_from),
             "<sip:%s@%s:%u>;tag=%s",
             cli[0] ? cli : "iwf",
             g_sip.via_host, (unsigned)g_sip.via_port, c->south_from_tag);
    snprintf(c->south_to, sizeof(c->south_to), "<%s>", c->south_ruri);

    char msg[SIP_MSG_MAX];
    int k = snprintf(msg, sizeof(msg),
        "INVITE %s SIP/2.0\r\n"
        "Via: SIP/2.0/UDP %s:%u;branch=%s;rport\r\n"
        "From: %s\r\n"
        "To: %s\r\n"
        "Call-ID: %s\r\n"
        "CSeq: %d INVITE\r\n"
        "Contact: <sip:iwf@%s:%u>\r\n"
        "Max-Forwards: 70\r\n"
        "User-Agent: PrettyIWF\r\n"
        "Content-Type: application/sdp\r\n"
        "Content-Length: %zu\r\n"
        "\r\n",
        c->south_ruri,
        g_sip.via_host, (unsigned)g_sip.via_port, c->south_branch,
        c->south_from, c->south_to, c->south_callid, c->south_cseq,
        g_sip.via_host, (unsigned)g_sip.via_port,
        c->sdp_len);
    if (k < 0 || (size_t)k >= sizeof(msg)) return -1;
    if (c->sdp_len && (size_t)k + c->sdp_len < sizeof(msg)) {
        memcpy(msg + k, c->sdp, c->sdp_len);
        k += (int)c->sdp_len;
    }
    if (sip_send_south(c, msg, (size_t)k) < 0)
        return -1;
    c->south_invite_sent = 1;
    c->last = time(NULL);
    LOGI("sip", "id=%u TX INVITE %s class=%s from=%s",
         c->id, c->south_ruri,
         c->klass == SIP_CLASS_MT_LOCAL ? "local" :
         c->klass == SIP_CLASS_MT_ROAM ? "roam" : "mo",
         cli[0] ? cli : "iwf");
    return 0;
}

static void sip_send_ack_south(sip_call_t *c)
{
    char msg[1024];
    int n = snprintf(msg, sizeof(msg),
        "ACK %s SIP/2.0\r\n"
        "Via: SIP/2.0/UDP %s:%u;branch=%sA;rport\r\n"
        "From: %s\r\n"
        "To: %s\r\n"
        "Call-ID: %s\r\n"
        "CSeq: %d ACK\r\n"
        "Max-Forwards: 70\r\n"
        "Content-Length: 0\r\n"
        "\r\n",
        c->south_ruri, g_sip.via_host, (unsigned)g_sip.via_port,
        c->south_branch, c->south_from, c->south_to,
        c->south_callid, c->south_cseq);
    if (n > 0)
        sip_send_south(c, msg, (size_t)n);
}

static void sip_send_cancel_south(sip_call_t *c)
{
    if (!c->south_invite_sent || c->south_final) return;
    if (c->south_isup) {
        isup_call_release(c->id, 31);
        return;
    }
    char msg[1024];
    int n = snprintf(msg, sizeof(msg),
        "CANCEL %s SIP/2.0\r\n"
        "Via: SIP/2.0/UDP %s:%u;branch=%s;rport\r\n"
        "From: %s\r\n"
        "To: %s\r\n"
        "Call-ID: %s\r\n"
        "CSeq: %d CANCEL\r\n"
        "Max-Forwards: 70\r\n"
        "Content-Length: 0\r\n"
        "\r\n",
        c->south_ruri, g_sip.via_host, (unsigned)g_sip.via_port,
        c->south_branch, c->south_from, c->south_to,
        c->south_callid, c->south_cseq);
    if (n > 0)
        sip_send_south(c, msg, (size_t)n);
}

static void sip_send_bye(sip_call_t *c, int south)
{
    char msg[1024];
    if (south && c->south_isup) {
        isup_call_release(c->id, 16);
        return;
    }
    if (south && c->south_invite_sent) {
        c->south_cseq++;
        int n = snprintf(msg, sizeof(msg),
            "BYE %s SIP/2.0\r\n"
            "Via: SIP/2.0/UDP %s:%u;branch=%sB;rport\r\n"
            "From: %s\r\n"
            "To: %s\r\n"
            "Call-ID: %s\r\n"
            "CSeq: %d BYE\r\n"
            "Max-Forwards: 70\r\n"
            "Content-Length: 0\r\n"
            "\r\n",
            c->south_ruri, g_sip.via_host, (unsigned)g_sip.via_port,
            c->south_branch, c->south_from, c->south_to,
            c->south_callid, c->south_cseq);
        if (n > 0) sip_send_south(c, msg, (size_t)n);
    } else {
        sip_reply(c, 200);
    }
}

static void sip_fail(sip_call_t *c, int code)
{
    c->sip_status = code;
    c->state = SIP_ST_TERM;
    sip_reply(c, code);
    sip_cdr(c, "fail");
    g_sip.stat_fail++;
    sip_send_cancel_south(c);
    sip_call_free(c);
}

static void sip_on_prn(struct iwf_runtime *rt, void *user,
                       int map_err, const char *msrn)
{
    (void)rt;
    sip_call_t *c = (sip_call_t *)user;
    sip_call_t *cur, *tmp;
    int alive = 0;
    HASH_ITER(hh, g_sip.calls, cur, tmp) {
        if (cur == c) { alive = 1; break; }
    }
    if (!alive) return;
    if (c->state != SIP_ST_WAIT_PRN) return;
    c->last = time(NULL);
    if (map_err || !msrn || !msrn[0]) {
        LOGW("sip", "id=%u PRN fail map_err=%d", c->id, map_err);
        sip_fail(c, sip_map_to_sip(map_err));
        return;
    }
    if (!sip_msrn_ok(&g_sip.rt->cfg, msrn)) {
        LOGW("sip", "id=%u MSRN %s outside msrn_prefix_ok", c->id, msrn);
        sip_fail(c, 503);
        return;
    }
    snprintf(c->msrn, sizeof(c->msrn), "%s", msrn);
    const iwf_cs_route_t *rte = iwf_cs_route_lookup(&g_sip.rt->cfg, c->msrn);
    int in_mode = rte ? rte->in_mode : -1;
    c->in_pending = 1;
    if (in_iwf_query(g_sip.rt, c->id, c->msrn, c->msisdn, in_mode,
                     sip_on_in, c) < 0)
        sip_fail(c, 503);
}

static void sip_route_mt(sip_call_t *c)
{
    if (c->klass == SIP_CLASS_MT_LOCAL) {
        if (!g_sip.rt->cfg.local_cs_sip_peer[0]) {
            sip_fail(c, 503);
            return;
        }
        g_sip.stat_local++;
        if (sip_originate_south(c, c->msisdn) < 0)
            sip_fail(c, 503);
        return;
    }

    /* Visited VLR: PRN, then prefix-route SIP or BICC. Never sip-connector. */
    int bicc = isup_call_south_is_bicc(g_sip.rt, c->msisdn);
    if (!bicc && !g_sip.rt->cfg.roam_cs_sipi_peer[0] &&
        !iwf_cs_route_lookup(&g_sip.rt->cfg, c->msisdn)) {
        LOGW("sip", "id=%u no sipi_peer and no cs_route; cannot originate",
             c->id);
        sip_fail(c, 503);
        return;
    }
    c->state = SIP_ST_WAIT_PRN;
    g_sip.stat_roam++;
    if (map_iwf_prn_request(g_sip.rt, c->imsi, c->msisdn, c->vlr,
                            sip_on_prn, c) < 0)
        sip_fail(c, 503);
}

static void sip_handle_invite(struct iwf_runtime *rt, const sip_msg_t *m,
                              const struct sockaddr_in *from, int tcp_idx)
{
    (void)rt;
    g_sip.stat_invite++;
    if (sip_find_north(m->callid)) {
        /* retransmit — 100 already sent */
        return;
    }
    if (g_sip.n_calls >= g_sip.rt->cfg.sip_max_sessions) {
        sip_reply_stateless(from, tcp_idx, m, 503);
        return;
    }

    struct sockaddr_in kama, localcs;
    int from_kama = 0, from_cs = 0;
    if (g_sip.rt->cfg.sip_kamailio_peer[0] &&
        sip_peer_parse(g_sip.rt->cfg.sip_kamailio_peer, &kama) == 0)
        from_kama = sip_addr_eq(from, &kama);
    if (g_sip.rt->cfg.local_cs_sip_peer[0] &&
        sip_peer_parse(g_sip.rt->cfg.local_cs_sip_peer, &localcs) == 0)
        from_cs = sip_addr_eq(from, &localcs);

    if (g_sip.rt->cfg.sip_kamailio_peer[0] && !from_kama && !from_cs) {
        sip_reply_stateless(from, tcp_idx, m, 403);
        return;
    }

    sip_call_t *c = sip_call_new(m, from, tcp_idx);
    if (!c) {
        sip_reply_stateless(from, tcp_idx, m, 503);
        return;
    }
    sip_reply(c, 100);

    if (from_cs && !from_kama) {
        c->klass = SIP_CLASS_MO;
        sip_msisdn_from_uri(m->ruri, c->msisdn, sizeof(c->msisdn));
        if (sip_originate_south(c, c->msisdn[0] ? c->msisdn : "unknown") < 0)
            sip_fail(c, 503);
        return;
    }

    sip_msisdn_from_uri(m->ruri, c->msisdn, sizeof(c->msisdn));
    if (!c->msisdn[0]) {
        sip_fail(c, 400);
        return;
    }
    int rc = sip_resolve_mt(c);
    if (rc > 0) {
        sip_fail(c, rc);
        return;
    }
    sip_route_mt(c);
}

static void sip_handle_cancel(const sip_msg_t *m,
                              const struct sockaddr_in *from, int tcp_idx)
{
    sip_call_t *c = sip_find_north(m->callid);
    if (!c) {
        sip_reply_stateless(from, tcp_idx, m, 481);
        return;
    }
    sip_reply_stateless(from, tcp_idx, m, 200);
    sip_send_cancel_south(c);
    c->sip_status = 487;
    sip_reply(c, 487);
    sip_cdr(c, "cancel");
    sip_call_free(c);
}

static void sip_handle_bye(const sip_msg_t *m,
                           const struct sockaddr_in *from, int tcp_idx)
{
    sip_call_t *c = sip_find_north(m->callid);
    if (!c) {
        sip_reply_stateless(from, tcp_idx, m, 481);
        return;
    }
    sip_reply_stateless(from, tcp_idx, m, 200);
    sip_send_bye(c, 1);
    c->sip_status = 200;
    sip_cdr(c, "bye");
    sip_call_free(c);
}

static void sip_handle_ack(const sip_msg_t *m)
{
    sip_call_t *c = sip_find_north(m->callid);
    if (!c) return;
    if (c->south_final && c->south_final >= 200 && c->south_final < 300)
        sip_send_ack_south(c);
}

static void sip_handle_south_resp(sip_call_t *c, const sip_msg_t *m)
{
    c->last = time(NULL);
    if (m->to[0])
        sip_hdr_copy(c->south_to, sizeof(c->south_to), m->to);
    if (m->status >= 180 && m->status < 200) {
        c->state = SIP_ST_EARLY;
        sip_reply_ex(c, m->status, m->body, m->body_len, "application/sdp");
        return;
    }
    if (m->status >= 200 && m->status < 300) {
        c->state = SIP_ST_CONNECTED;
        c->south_final = m->status;
        c->sip_status = 200;
        sip_reply_ex(c, 200, m->body, m->body_len, "application/sdp");
        sip_cdr(c, "answer");
        return;
    }
    if (m->status >= 300) {
        c->south_final = m->status;
        c->sip_status = m->status;
        sip_send_ack_south(c);
        sip_reply(c, m->status);
        sip_cdr(c, "south_fail");
        g_sip.stat_fail++;
        sip_call_free(c);
    }
}

static void sip_handle_south_bye(sip_call_t *c, const sip_msg_t *m,
                                 const struct sockaddr_in *from)
{
    char msg[1024];
    int n = snprintf(msg, sizeof(msg),
        "SIP/2.0 200 OK\r\n"
        "Via: SIP/2.0/UDP %s:%u;branch=%s\r\n"
        "From: %s\r\n"
        "To: %s\r\n"
        "Call-ID: %s\r\n"
        "CSeq: %s\r\n"
        "Content-Length: 0\r\n"
        "\r\n",
        g_sip.via_host, (unsigned)g_sip.via_port, c->south_branch,
        c->south_from, c->south_to, c->south_callid,
        m->cseq[0] ? m->cseq : "2 BYE");
    if (n > 0)
        sip_send_bytes(g_sip.udp_fd, from, msg, (size_t)n);
    sip_reply(c, 200);
    /* North BYE (we are UAS on that dialog). */
    {
        char bye[1024];
        char branch[40];
        sip_mint(branch, sizeof(branch), "z9hG4bK");
        int bn = snprintf(bye, sizeof(bye),
            "BYE sip:peer@%s SIP/2.0\r\n"
            "Via: SIP/2.0/UDP %s:%u;branch=%s;rport\r\n"
            "From: %s;tag=%s\r\n"
            "To: %s\r\n"
            "Call-ID: %s\r\n"
            "CSeq: %d BYE\r\n"
            "Max-Forwards: 70\r\n"
            "Content-Length: 0\r\n"
            "\r\n",
            g_sip.via_host,
            g_sip.via_host, (unsigned)g_sip.via_port, branch,
            c->north_to, c->to_tag, c->north_from,
            c->north_callid, c->north_cseq_num + 1);
        if (bn > 0) sip_send_north(c, bye, (size_t)bn);
    }
    c->sip_status = 200;
    sip_cdr(c, "bye_south");
    sip_call_free(c);
}

static void sip_handle_options(const sip_msg_t *m,
                               const struct sockaddr_in *from, int tcp_idx)
{
    sip_reply_stateless(from, tcp_idx, m, 200);
}

static void sip_dispatch(struct iwf_runtime *rt, const char *raw, size_t len,
                         const struct sockaddr_in *from, int tcp_idx)
{
    sip_msg_t m;
    if (sip_parse(raw, len, &m) < 0) {
        LOGW("sip", "parse fail len=%zu from=%s:%u",
             len, from ? inet_ntoa(from->sin_addr) : "-",
             from ? ntohs(from->sin_port) : 0);
        return;
    }
    LOGD("sip", "RX %s %s%s from=%s:%u callid=%s",
         m.is_req ? m.method : "SIP/2.0",
         m.is_req ? m.ruri : "",
         m.is_req ? "" : m.reason,
         from ? inet_ntoa(from->sin_addr) : "-",
         from ? ntohs(from->sin_port) : 0,
         m.callid);

    if (!m.is_req) {
        sip_call_t *c = sip_find_south(m.callid);
        if (c)
            sip_handle_south_resp(c, &m);
        else
            in_iwf_on_sip(m.callid, m.status, m.contact);
        return;
    }
    if (!strcasecmp(m.method, "OPTIONS")) {
        sip_handle_options(&m, from, tcp_idx);
        return;
    }
    if (!strcasecmp(m.method, "INVITE")) {
        sip_handle_invite(rt, &m, from, tcp_idx);
        return;
    }
    if (!strcasecmp(m.method, "ACK")) {
        sip_handle_ack(&m);
        return;
    }
    if (!strcasecmp(m.method, "CANCEL")) {
        sip_handle_cancel(&m, from, tcp_idx);
        return;
    }
    if (!strcasecmp(m.method, "BYE")) {
        sip_call_t *sc = sip_find_south(m.callid);
        if (sc) {
            sip_handle_south_bye(sc, &m, from);
            return;
        }
        sip_handle_bye(&m, from, tcp_idx);
        return;
    }
    sip_reply_stateless(from, tcp_idx, &m, 405);
}

static void sip_options_out(void)
{
    struct sockaddr_in to;
    if (!g_sip.rt->cfg.sip_kamailio_peer[0] ||
        sip_peer_parse(g_sip.rt->cfg.sip_kamailio_peer, &to) < 0)
        return;
    char branch[40];
    sip_mint(branch, sizeof(branch), "z9hG4bK");
    char msg[512];
    int n = snprintf(msg, sizeof(msg),
        "OPTIONS sip:kamailio@%s:%u SIP/2.0\r\n"
        "Via: SIP/2.0/UDP %s:%u;branch=%s;rport\r\n"
        "From: <sip:iwf@%s:%u>;tag=opt\r\n"
        "To: <sip:kamailio@%s:%u>\r\n"
        "Call-ID: opt%08x@%s\r\n"
        "CSeq: 1 OPTIONS\r\n"
        "Max-Forwards: 70\r\n"
        "Content-Length: 0\r\n"
        "\r\n",
        inet_ntoa(to.sin_addr), ntohs(to.sin_port),
        g_sip.via_host, (unsigned)g_sip.via_port, branch,
        g_sip.via_host, (unsigned)g_sip.via_port,
        inet_ntoa(to.sin_addr), ntohs(to.sin_port),
        sip_next_seq(), g_sip.via_host);
    if (n > 0 && g_sip.udp_fd >= 0)
        sip_send_bytes(g_sip.udp_fd, &to, msg, (size_t)n);
}

bool sip_iwf_enabled(const struct iwf_runtime *rt)
{
    return rt && rt->cfg.sip_iwf_enabled;
}

int sip_iwf_parse_peer(const char *in, struct sockaddr_in *out)
{
    return sip_peer_parse(in, out);
}

int sip_iwf_send_raw(const struct sockaddr_in *to, const char *buf, size_t len)
{
    if (g_sip.udp_fd < 0) return -1;
    return sip_send_bytes(g_sip.udp_fd, to, buf, len);
}

int sip_iwf_on_isup_acm(uint32_t id)
{
    sip_call_t *c = sip_find_id(id);
    if (!c) return -1;
    c->state = SIP_ST_EARLY;
    c->last = time(NULL);
    sip_reply(c, 183);
    return 0;
}

int sip_iwf_on_isup_anm(uint32_t id)
{
    sip_call_t *c = sip_find_id(id);
    if (!c) return -1;
    c->state = SIP_ST_CONNECTED;
    c->south_final = 200;
    c->sip_status = 200;
    c->last = time(NULL);
    sip_reply_ex(c, 200, c->sdp, c->sdp_len, "application/sdp");
    sip_cdr(c, "answer");
    return 0;
}

int sip_iwf_on_isup_rel(uint32_t id, int sip_status)
{
    sip_call_t *c = sip_find_id(id);
    if (!c) return -1;
    c->south_final = sip_status;
    if (c->state == SIP_ST_CONNECTED && sip_status == 200) {
        sip_send_bye(c, 0);
        c->sip_status = 200;
        sip_cdr(c, "bye_isup");
        c->south_isup = 0;
        sip_call_free(c);
        return 0;
    }
    c->south_isup = 0;
    sip_fail(c, sip_status > 0 ? sip_status : 503);
    return 0;
}

int sip_iwf_init(struct iwf_runtime *rt, int epfd)
{
    memset(&g_sip, 0, sizeof(g_sip));
    g_sip.udp_fd = -1;
    g_sip.tcp_fd = -1;
    for (int i = 0; i < SIP_EPOLL_TCP_MAX; i++)
        g_sip.tcp[i].fd = -1;
    if (!rt || !rt->cfg.sip_iwf_enabled)
        return 0;
    g_sip.rt = rt;
    g_sip.epfd = epfd;

    const char *bind_ip = rt->cfg.sip_listen_ip[0] ? rt->cfg.sip_listen_ip
                                                   : "0.0.0.0";
    if (!strcmp(bind_ip, "0.0.0.0") && rt->cfg.local_ip[0])
        snprintf(g_sip.via_host, sizeof(g_sip.via_host), "%s", rt->cfg.local_ip);
    else if (strcmp(bind_ip, "0.0.0.0") != 0)
        snprintf(g_sip.via_host, sizeof(g_sip.via_host), "%s", bind_ip);
    else
        snprintf(g_sip.via_host, sizeof(g_sip.via_host), "%s",
                 rt->cfg.local_ip[0] ? rt->cfg.local_ip : "127.0.0.1");
    g_sip.via_port = rt->cfg.sip_listen_port ? rt->cfg.sip_listen_port : 5060;

    if (rt->cfg.sip_transport_udp) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) { LOGE("sip", "udp socket: %s", strerror(errno)); return -1; }
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_port = htons(g_sip.via_port);
        if (inet_pton(AF_INET, bind_ip, &a.sin_addr) != 1)
            a.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
            LOGE("sip", "udp bind %s:%u: %s", bind_ip,
                 (unsigned)g_sip.via_port, strerror(errno));
            close(fd);
            return -1;
        }
        set_nb(fd);
        g_sip.udp_fd = fd;
        struct epoll_event ev = { .events = EPOLLIN,
                                  .data = { .u64 = SIP_EPOLL_ROLE_UDP } };
        epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
        LOGI("sip", "UDP %s:%u via_host=%s", bind_ip,
             (unsigned)g_sip.via_port, g_sip.via_host);
    }

    if (rt->cfg.sip_transport_tcp) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) { LOGE("sip", "tcp socket: %s", strerror(errno)); return -1; }
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_port = htons(g_sip.via_port);
        if (inet_pton(AF_INET, bind_ip, &a.sin_addr) != 1)
            a.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
            LOGE("sip", "tcp bind %s:%u: %s", bind_ip,
                 (unsigned)g_sip.via_port, strerror(errno));
            close(fd);
            return -1;
        }
        if (listen(fd, 16) < 0) {
            LOGE("sip", "tcp listen: %s", strerror(errno));
            close(fd);
            return -1;
        }
        set_nb(fd);
        g_sip.tcp_fd = fd;
        struct epoll_event ev = { .events = EPOLLIN,
                                  .data = { .u64 = SIP_EPOLL_ROLE_TCP_LISTEN } };
        epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
        LOGI("sip", "TCP %s:%u", bind_ip, (unsigned)g_sip.via_port);
    }

    if (g_sip.udp_fd < 0 && g_sip.tcp_fd < 0) {
        LOGE("sip", "no SIP transport enabled");
        return -1;
    }
    g_sip.last_options = time(NULL);
    LOGI("sip", "GMSC ready kamailio=%s local_cs=%s roam_cs=%s",
         rt->cfg.sip_kamailio_peer[0] ? rt->cfg.sip_kamailio_peer : "(any)",
         rt->cfg.local_cs_sip_peer[0] ? rt->cfg.local_cs_sip_peer : "(unset)",
         rt->cfg.roam_cs_sipi_peer[0] ? rt->cfg.roam_cs_sipi_peer : "(unset)");
    return 0;
}

void sip_iwf_shutdown(struct iwf_runtime *rt)
{
    (void)rt;
    sip_call_t *c, *tmp;
    HASH_ITER(hh, g_sip.calls, c, tmp)
        sip_call_free(c);
    for (int i = 0; i < SIP_EPOLL_TCP_MAX; i++) {
        if (g_sip.tcp[i].fd >= 0) {
            close(g_sip.tcp[i].fd);
            g_sip.tcp[i].fd = -1;
        }
    }
    if (g_sip.udp_fd >= 0) { close(g_sip.udp_fd); g_sip.udp_fd = -1; }
    if (g_sip.tcp_fd >= 0) { close(g_sip.tcp_fd); g_sip.tcp_fd = -1; }
    if (g_sip.stat_invite)
        LOGI("sip", "stats invite=%u local=%u roam=%u fail=%u",
             g_sip.stat_invite, g_sip.stat_local, g_sip.stat_roam,
             g_sip.stat_fail);
    memset(&g_sip, 0, sizeof(g_sip));
    g_sip.udp_fd = g_sip.tcp_fd = -1;
}

void sip_iwf_on_udp(struct iwf_runtime *rt)
{
    if (g_sip.udp_fd < 0) return;
    for (;;) {
        char buf[SIP_MSG_MAX];
        struct sockaddr_in from;
        socklen_t fl = sizeof(from);
        ssize_t r = recvfrom(g_sip.udp_fd, buf, sizeof(buf) - 1, 0,
                             (struct sockaddr *)&from, &fl);
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            LOGW("sip", "recvfrom: %s", strerror(errno));
            return;
        }
        if (r == 0) return;
        buf[r] = '\0';
        sip_dispatch(rt, buf, (size_t)r, &from, -1);
    }
}

void sip_iwf_on_tcp_listen(struct iwf_runtime *rt)
{
    (void)rt;
    if (g_sip.tcp_fd < 0) return;
    for (;;) {
        struct sockaddr_in from;
        socklen_t fl = sizeof(from);
        int cfd = accept(g_sip.tcp_fd, (struct sockaddr *)&from, &fl);
        if (cfd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            return;
        }
        int slot = -1;
        for (int i = 0; i < SIP_EPOLL_TCP_MAX; i++) {
            if (g_sip.tcp[i].fd < 0) { slot = i; break; }
        }
        if (slot < 0) {
            LOGW("sip", "tcp slots full");
            close(cfd);
            continue;
        }
        set_nb(cfd);
        memset(&g_sip.tcp[slot], 0, sizeof(g_sip.tcp[slot]));
        g_sip.tcp[slot].fd = cfd;
        g_sip.tcp[slot].addr = from;
        struct epoll_event ev = { .events = EPOLLIN,
                                  .data = { .u64 = SIP_EPOLL_ROLE_TCP(slot) } };
        epoll_ctl(g_sip.epfd, EPOLL_CTL_ADD, cfd, &ev);
        LOGD("sip", "tcp accept %s:%u slot=%d",
             inet_ntoa(from.sin_addr), ntohs(from.sin_port), slot);
    }
}

void sip_iwf_on_tcp_conn(struct iwf_runtime *rt, int idx)
{
    if (idx < 0 || idx >= SIP_EPOLL_TCP_MAX) return;
    sip_tcp_t *t = &g_sip.tcp[idx];
    if (t->fd < 0) return;
    for (;;) {
        if (t->len >= sizeof(t->buf) - 1) {
            LOGW("sip", "tcp overflow slot=%d", idx);
            close(t->fd);
            t->fd = -1;
            t->len = 0;
            return;
        }
        ssize_t r = recv(t->fd, t->buf + t->len,
                         sizeof(t->buf) - 1 - t->len, 0);
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            close(t->fd);
            t->fd = -1;
            t->len = 0;
            return;
        }
        if (r == 0) {
            close(t->fd);
            t->fd = -1;
            t->len = 0;
            return;
        }
        t->len += (size_t)r;
        t->buf[t->len] = '\0';
        for (;;) {
            int need = sip_complete_len(t->buf, t->len);
            if (need <= 0) break;
            sip_dispatch(rt, t->buf, (size_t)need, &t->addr, idx);
            memmove(t->buf, t->buf + need, t->len - (size_t)need);
            t->len -= (size_t)need;
            t->buf[t->len] = '\0';
        }
    }
}

void sip_iwf_on_timer(struct iwf_runtime *rt)
{
    if (!g_sip.rt) return;
    time_t now = time(NULL);
    int inv_s = (rt->cfg.sip_invite_timeout_ms + 999) / 1000;
    if (inv_s < 1) inv_s = 8;
    int idle = rt->cfg.sip_session_timer_s > 0 ? rt->cfg.sip_session_timer_s
                                               : 1800;
    sip_call_t *c, *tmp;
    HASH_ITER(hh, g_sip.calls, c, tmp) {
        if (c->state != SIP_ST_CONNECTED &&
            now - c->created >= inv_s) {
            sip_fail(c, 503);
            continue;
        }
        if (c->state == SIP_ST_CONNECTED && now - c->last >= idle) {
            sip_send_bye(c, 1);
            sip_cdr(c, "idle");
            sip_call_free(c);
        }
    }
    isup_call_on_timer(rt);
    in_iwf_on_timer(rt);
    if (rt->cfg.sip_options_interval_s > 0 &&
        now - g_sip.last_options >= rt->cfg.sip_options_interval_s) {
        g_sip.last_options = now;
        sip_options_out();
    }
}
