/*
 * gsup_client.c - IPA-framed GSUP TCP client to PyHSS (SRI-SM lookup).
 *
 * IPA framing (from osmocom_ipa.py add_header / del_header / split_combined):
 *
 *   Frame layout:
 *     [u16 BE: ipa_len] [proto] [ext/msgtype] [data...]
 *     Total frame size = 3 + ipa_len   (ipa_len does NOT include proto byte)
 *     ipa_len = 1 + len(data)           (counts ext/msgtype byte + data)
 *
 *   CCM  (proto=0xFE): [u16: 1+len(data)] [0xFE] [msgtype] [data]
 *     PING  (msgtype=0x00): data=b'', ipa_len=1, frame=[0x00,0x01,0xFE,0x00]
 *     PONG  (msgtype=0x01): data=b'', ipa_len=1, frame=[0x00,0x01,0xFE,0x01]
 *     ID_GET  (msgtype=0x04): data=req_identity(12 bytes), ipa_len=13
 *     ID_RESP (msgtype=0x05): data=tag_list, ipa_len=1+len(tags)
 *     ID_ACK  (msgtype=0x06): data=b'', ipa_len=1
 *
 *   OSMO/GSUP (proto=0xEE, ext=0x05):
 *     [u16: 1+len(body)] [0xEE] [0x05] [gsup_body...]
 *     ipa_len = 1(ext) + len(body)
 *
 *   CCM IPA tag format (_tag(t, v)):
 *     [u16 BE: len(v)+1] [u8: tag_id] [v bytes]
 *     Tags:  UNIT=8 (primary id), UNITNAME=1
 *
 * ID_RESP must include at least one of UNIT (tag=8) or MACADDR (tag=7)
 * as a "primary ID" or PyHSS rejects the connection.
 *
 * On TCP connect PyHSS sends CCM ID_GET; we must respond with ID_RESP.
 * PyHSS will then close after 60 s of idle; a 30 s timerfd sends
 * periodic IPA CCM PING to keep the link alive (role 0x205).
 */

#include "gsup_client.h"
#include "sms_iwf.h"    /* for SMS_EPOLL_ROLE_GSUP_TIMER */
#include "logging.h"

#ifndef SMS_EPOLL_ROLE_GSUP_SOCK
#define SMS_EPOLL_ROLE_GSUP_SOCK 0x203
#endif

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* IPA proto bytes */
#define IPA_PROTO_CCM           0xFE
#define IPA_PROTO_OSMO          0xEE
#define IPA_EXT_GSUP            0x05

/* CCM message types */
#define CCM_PING                0x00
#define CCM_PONG                0x01
#define CCM_ID_GET              0x04
#define CCM_ID_RESP             0x05
#define CCM_ID_ACK              0x06

/* IPA tag ids */
#define IPA_TAG_UNITNAME        0x01
#define IPA_TAG_UNIT            0x08

/* GSUP message types */
#define GSUP_MSG_SRI_SM_REQ     0x45
#define GSUP_MSG_SRI_SM_ERR     0x46
#define GSUP_MSG_SRI_SM_RES     0x47

/* GSUP IE tags */
#define GSUP_IE_IMSI            0x01
#define GSUP_IE_MSISDN          0x08

#define GSUP_RX_CAP             8192
#define GSUP_KEEPALIVE_SECS     30

static int      g_fd         = -1;
static int      g_epfd       = -1;
static int      g_timer_fd   = -1;
static char     g_remote_ip[64];
static uint16_t g_remote_port;
static char     g_client_name[64];
static uint8_t  g_rx[GSUP_RX_CAP];
static size_t   g_rx_used    = 0;
static unsigned g_backoff_s  = 1;
static void   (*g_cb)(uint32_t, int, const char *) = NULL;

/* ------------------------------------------------------------------ */

static int set_nb(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static void gsup_disconnect(void)
{
    if (g_fd >= 0) {
        if (g_epfd >= 0)
            epoll_ctl(g_epfd, EPOLL_CTL_DEL, g_fd, NULL);
        close(g_fd);
        g_fd = -1;
    }
    g_rx_used = 0;
}

static int gsup_connect_now(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (set_nb(fd) < 0) { close(fd); return -1; }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(g_remote_port);
    if (inet_pton(AF_INET, g_remote_ip, &sa.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 &&
        errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    g_fd = fd;
    if (g_epfd >= 0) {
        struct epoll_event ev = { .events = EPOLLIN | EPOLLOUT,
                                  .data = { .u64 = SMS_EPOLL_ROLE_GSUP_SOCK } };
        epoll_ctl(g_epfd, EPOLL_CTL_ADD, g_fd, &ev);
    }
    g_backoff_s = 1;
    LOGI("gsup", "connected to %s:%u", g_remote_ip, (unsigned)g_remote_port);
    return 0;
}

static void gsup_try_reconnect(void)
{
    gsup_disconnect();
    if (g_backoff_s > 30) g_backoff_s = 30;
    LOGW("gsup", "reconnect to %s:%u in %us",
         g_remote_ip, (unsigned)g_remote_port, g_backoff_s);
    sleep(g_backoff_s);
    if (gsup_connect_now() < 0)
        g_backoff_s *= 2;
}

/* ------------------------------------------------------------------ */
/* CCM helpers                                                          */
/* ------------------------------------------------------------------ */

/*
 * CCM PING: [0x00,0x01,0xFE,0x00]
 * CCM PONG: [0x00,0x01,0xFE,0x01]
 *   ipa_len=1 (just the msgtype/ext byte, no data payload)
 */
static void send_ccm_ping(void)
{
    if (g_fd < 0) return;
    static const uint8_t ping[] = { 0x00, 0x01, IPA_PROTO_CCM, CCM_PING };
    (void)write(g_fd, ping, sizeof(ping));
    LOGD("gsup", "CCM: sent PING");
}

static void send_ccm_pong(void)
{
    if (g_fd < 0) return;
    static const uint8_t pong[] = { 0x00, 0x01, IPA_PROTO_CCM, CCM_PONG };
    (void)write(g_fd, pong, sizeof(pong));
    LOGD("gsup", "CCM: sent PONG");
}

/*
 * Build a _tag(t, v) per PyHSS convention:
 *   [u16 BE: len(v)+1] [u8: t] [v bytes]
 * Appends to buf at *pos; returns bytes written or -1 on overflow.
 */
static int append_tag(uint8_t *buf, size_t cap, size_t *pos,
                      uint8_t tag_id, const char *value)
{
    size_t vlen   = strlen(value);
    uint16_t tlen = (uint16_t)(vlen + 1); /* len(v)+1 stored in u16 */
    if (*pos + 2 + 1 + vlen > cap) return -1;
    buf[(*pos)++] = (uint8_t)(tlen >> 8);
    buf[(*pos)++] = (uint8_t)(tlen & 0xff);
    buf[(*pos)++] = tag_id;
    memcpy(buf + *pos, value, vlen);
    *pos += vlen;
    return 0;
}

/*
 * CCM ID_RESP:
 *   tags = UNIT("0/0/0") + UNITNAME(g_client_name)
 *   frame = [u16: 1+len(tags)] [0xFE] [0x05] [tags]
 *
 * PyHSS requires at least one of UNIT (tag=8) or MACADDR (tag=7)
 * as a primary_id to accept the connection.
 */
static void send_id_resp(void)
{
    uint8_t tags[128];
    size_t  tpos = 0;

    /* Primary ID: UNIT tag (tag_id=8), value "0/0/0" */
    /* TYPE tag (tag_id=3) must contain 'msc' or 'sgsn' for PyHSS role check */
    if (append_tag(tags, sizeof(tags), &tpos, IPA_TAG_UNIT, "0/0/0") < 0 ||
        append_tag(tags, sizeof(tags), &tpos, 0x03 /* TYPE */, "msc") < 0 ||
        append_tag(tags, sizeof(tags), &tpos, IPA_TAG_UNITNAME, g_client_name) < 0) {
        LOGE("gsup", "send_id_resp: tag overflow");
        return;
    }

    /* IPA CCM frame: [u16: 1+tpos] [0xFE] [0x05] [tags] */
    uint16_t ipa_len = (uint16_t)(1 + tpos);
    uint8_t  buf[160];
    size_t   i = 0;
    buf[i++] = (uint8_t)(ipa_len >> 8);
    buf[i++] = (uint8_t)(ipa_len & 0xff);
    buf[i++] = IPA_PROTO_CCM;
    buf[i++] = CCM_ID_RESP;
    memcpy(buf + i, tags, tpos); i += tpos;

    (void)write(g_fd, buf, i);
    LOGI("gsup", "CCM: sent ID_RESP UNIT=0/0/0 UNITNAME=%s", g_client_name);
}

/* ------------------------------------------------------------------ */
/* GSUP helpers                                                         */
/* ------------------------------------------------------------------ */

static int gsup_enc_ie(uint8_t *buf, size_t cap, size_t *off,
                       uint8_t ie, const uint8_t *val, size_t len)
{
    if (*off + 2 + len > cap) return -1;
    buf[(*off)++] = ie;
    buf[(*off)++] = (uint8_t)len;
    if (val && len)
        memcpy(buf + *off, val, len);
    *off += len;
    return 0;
}

static void gsup_dispatch_msg(const uint8_t *body, size_t blen, uint32_t corr_id)
{
    if (!g_cb || blen < 1) return;
    uint8_t mtype = body[0];
    if (mtype == GSUP_MSG_SRI_SM_ERR) {
        g_cb(corr_id, -1, NULL);
        return;
    }
    if (mtype != GSUP_MSG_SRI_SM_RES) return;

    char   imsi[32] = "";
    size_t off = 1;
    while (off + 2 <= blen) {
        uint8_t ie  = body[off++];
        uint8_t len = body[off++];
        if (off + len > blen) break;
        if (ie == GSUP_IE_IMSI && len < sizeof(imsi)) {
            memcpy(imsi, body + off, len);
            imsi[len] = '\0';
        }
        off += len;
    }
    g_cb(corr_id, imsi[0] ? 0 : -1, imsi[0] ? imsi : NULL);
}

/* ------------------------------------------------------------------ */
/* RX drain                                                             */
/* ------------------------------------------------------------------ */

/*
 * IPA frame at buf[off]:
 *   off+0, off+1 : ipa_len  (u16 BE, does NOT include proto byte)
 *   off+2        : proto
 *   off+3        : ext/msgtype  (1st of ipa_len bytes)
 *   off+4 ..     : data       (ipa_len-1 more bytes)
 *   Total frame  : 3 + ipa_len bytes
 */
static void gsup_drain_rx(void)
{
    for (;;) {
        if (g_rx_used >= GSUP_RX_CAP) g_rx_used = 0;
        ssize_t r = read(g_fd, g_rx + g_rx_used, GSUP_RX_CAP - g_rx_used);
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            LOGE("gsup", "read: %s", strerror(errno));
            gsup_try_reconnect();
            return;
        }
        if (r == 0) {
            LOGW("gsup", "peer closed");
            gsup_try_reconnect();
            return;
        }
        g_rx_used += (size_t)r;

        size_t off = 0;
        while (off + 4 <= g_rx_used) {
            uint16_t ipa_len = (uint16_t)((g_rx[off] << 8) | g_rx[off + 1]);
            if (ipa_len < 1) { off += 3; continue; }
            /* wait until complete frame is buffered */
            if (off + 3 + ipa_len > g_rx_used) break;

            uint8_t proto = g_rx[off + 2];
            uint8_t ext   = g_rx[off + 3]; /* ext byte or CCM msgtype */

            if (proto == IPA_PROTO_OSMO && ext == IPA_EXT_GSUP) {
                /* GSUP body: ipa_len - 1 bytes (after ext byte) */
                if (ipa_len >= 2)
                    gsup_dispatch_msg(g_rx + off + 4,
                                      (size_t)(ipa_len - 1), 0);

            } else if (proto == IPA_PROTO_CCM) {
                switch (ext) {
                case CCM_PING:    send_ccm_pong();  break;
                case CCM_ID_GET:  send_id_resp();   break;
                case CCM_ID_ACK:
                    LOGI("gsup", "CCM: ID_ACK – handshake complete");
                    break;
                default:
                    LOGD("gsup", "CCM: unknown msgtype=0x%02x", ext);
                    break;
                }
            } else {
                LOGD("gsup", "IPA: unknown proto=0x%02x ext=0x%02x len=%u",
                     proto, ext, (unsigned)ipa_len);
            }

            off += 3 + ipa_len; /* advance past complete frame */
        }

        if (off > 0) {
            memmove(g_rx, g_rx + off, g_rx_used - off);
            g_rx_used -= off;
        }
        if (off == 0) break;
    }
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

int gsup_client_send_sri_sm_req(const char *msisdn, uint32_t corr_id)
{
    (void)corr_id;
    if (g_fd < 0 || !msisdn) return -1;

    /* Encode MSISDN as BCD (TON=international 0x91) */
    uint8_t msisdn_ie[16];
    size_t  mi = 0;
    msisdn_ie[mi++] = 0x91;
    int di = 0;
    for (size_t k = 0; msisdn[k] && di < 22; k++) {
        if (msisdn[k] < '0' || msisdn[k] > '9') continue;
        uint8_t d    = (uint8_t)(msisdn[k] - '0');
        size_t  boff = mi + (size_t)(di / 2);
        if (boff >= sizeof(msisdn_ie)) break;
        if ((di & 1) == 0) msisdn_ie[boff] = d;
        else               msisdn_ie[boff] = (uint8_t)(msisdn_ie[boff] | (d << 4));
        di++;
    }
    if (di & 1) {
        size_t boff = mi + (size_t)(di / 2);
        if (boff < sizeof(msisdn_ie))
            msisdn_ie[boff] = (uint8_t)((msisdn_ie[boff] & 0x0f) | 0xf0);
    }
    size_t mlen = mi + (size_t)((di + 1) / 2);

    /* GSUP body */
    uint8_t body[128];
    size_t  bo = 0;
    body[bo++] = GSUP_MSG_SRI_SM_REQ;
    if (gsup_enc_ie(body, sizeof(body), &bo, GSUP_IE_IMSI, NULL, 0) < 0)
        return -1;
    if (gsup_enc_ie(body, sizeof(body), &bo, GSUP_IE_MSISDN,
                    msisdn_ie, mlen) < 0)
        return -1;

    /*
     * OSMO/GSUP IPA frame: add_header(body, OSMO, GSUP)
     *   = [u16: 1+len(body)] [0xEE] [0x05] [body]
     *   ipa_len = 1(ext) + bo
     */
    uint8_t  ipa[160];
    uint16_t ipa_len = (uint16_t)(1 + bo);
    ipa[0] = (uint8_t)(ipa_len >> 8);
    ipa[1] = (uint8_t)(ipa_len & 0xff);
    ipa[2] = IPA_PROTO_OSMO;
    ipa[3] = IPA_EXT_GSUP;
    memcpy(ipa + 4, body, bo);

    ssize_t w = write(g_fd, ipa, 4 + bo);
    if (w < 0) {
        LOGE("gsup", "write SRI-SM-REQ: %s", strerror(errno));
        return -1;
    }
    LOGD("gsup", "sent SRI-SM-REQ msisdn=%s", msisdn);
    return 0;
}

int gsup_client_init(const char *remote_ip, uint16_t remote_port,
                     const char *client_name, int epoll_fd)
{
    g_epfd      = epoll_fd;
    g_rx_used   = 0;
    g_backoff_s = 1;

    strncpy(g_remote_ip, remote_ip ? remote_ip : "127.0.0.1",
            sizeof(g_remote_ip) - 1);
    g_remote_ip[sizeof(g_remote_ip) - 1] = '\0';

    strncpy(g_client_name, client_name ? client_name : "IWF",
            sizeof(g_client_name) - 1);
    g_client_name[sizeof(g_client_name) - 1] = '\0';

    g_remote_port = remote_port;

    /* Create a 30 s periodic keepalive timerfd */
    g_timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (g_timer_fd >= 0) {
        struct itimerspec its = {
            .it_value    = { .tv_sec = GSUP_KEEPALIVE_SECS, .tv_nsec = 0 },
            .it_interval = { .tv_sec = GSUP_KEEPALIVE_SECS, .tv_nsec = 0 },
        };
        timerfd_settime(g_timer_fd, 0, &its, NULL);
        if (epoll_fd >= 0) {
            struct epoll_event ev = {
                .events = EPOLLIN,
                .data   = { .u64 = SMS_EPOLL_ROLE_GSUP_TIMER },
            };
            epoll_ctl(epoll_fd, EPOLL_CTL_ADD, g_timer_fd, &ev);
        }
        LOGI("gsup", "GSUP keepalive timer: %ds interval", GSUP_KEEPALIVE_SECS);
    } else {
        LOGW("gsup", "timerfd_create failed: %s (no keepalive)", strerror(errno));
    }

    if (gsup_connect_now() < 0)
        LOGW("gsup", "initial connect to %s:%u failed; will retry",
             g_remote_ip, (unsigned)g_remote_port);
    return 0;
}

void gsup_client_on_readable(void)
{
    if (g_fd < 0) {
        gsup_try_reconnect();
        return;
    }
    gsup_drain_rx();
}

/* Called when the keepalive timerfd fires (SMS_EPOLL_ROLE_GSUP_TIMER). */
void gsup_client_on_keepalive(int fd)
{
    /* Drain the timerfd to re-arm it */
    uint64_t expirations;
    (void)read(fd, &expirations, sizeof(expirations));

    if (g_fd >= 0) {
        send_ccm_ping();
    }
    /* If g_fd < 0 we're already reconnecting; no-op until back up */
}

void gsup_client_set_cb(
        void (*cb)(uint32_t corr_id, int error, const char *imsi))
{
    g_cb = cb;
}

void gsup_client_shutdown(void)
{
    if (g_timer_fd >= 0) {
        if (g_epfd >= 0)
            epoll_ctl(g_epfd, EPOLL_CTL_DEL, g_timer_fd, NULL);
        close(g_timer_fd);
        g_timer_fd = -1;
    }
    gsup_disconnect();
    g_cb = NULL;
}

int gsup_client_get_fd(void) { return g_fd; }
