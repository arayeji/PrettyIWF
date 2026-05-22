/*
 * gsup_client.c - IPA-framed GSUP TCP client to PyHSS (SRI-SM lookup).
 */

#include "gsup_client.h"
#include "logging.h"

#ifndef SMS_EPOLL_ROLE_GSUP_SOCK
#define SMS_EPOLL_ROLE_GSUP_SOCK 0x203
#endif

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define GSUP_IPA_PROTO_GSUP     0x05
#define GSUP_IPA_STREAM         0xFE

#define GSUP_MSG_SRI_SM_REQ     0x45
#define GSUP_MSG_SRI_SM_ERR     0x46
#define GSUP_MSG_SRI_SM_RES     0x47

#define GSUP_IE_IMSI            0x01
#define GSUP_IE_MSISDN          0x08

#define GSUP_RX_CAP             8192

static int g_fd = -1;
static int g_epfd = -1;
static char g_remote_ip[64];
static uint16_t g_remote_port;
static uint8_t g_rx[GSUP_RX_CAP];
static size_t g_rx_used = 0;
static unsigned g_backoff_s = 1;
static void (*g_cb)(uint32_t, int, const char *) = NULL;

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
    LOGW("gsup", "reconnect to %s:%u in %us", g_remote_ip, (unsigned)g_remote_port,
         g_backoff_s);
    sleep(g_backoff_s);
    if (gsup_connect_now() < 0)
        g_backoff_s *= 2;
}

static int gsup_enc_ie(uint8_t *buf, size_t cap, size_t *off,
                       uint8_t ie, const uint8_t *val, size_t len)
{
    if (*off + 2 + len > cap) return -1;
    buf[(*off)++] = ie;
    buf[(*off)++] = (uint8_t)len;
    memcpy(buf + *off, val, len);
    *off += len;
    return 0;
}

int gsup_client_send_sri_sm_req(const char *msisdn, uint32_t corr_id)
{
    (void)corr_id;
    if (g_fd < 0 || !msisdn) return -1;

    uint8_t msisdn_ie[16];
    size_t mi = 0;
    msisdn_ie[mi++] = 0x91;
    int di = 0;
    for (size_t i = 0; msisdn[i] && di < 22; i++) {
        if (msisdn[i] < '0' || msisdn[i] > '9') continue;
        uint8_t d = (uint8_t)(msisdn[i] - '0');
        size_t off = mi + (size_t)(di / 2);
        if (off >= sizeof(msisdn_ie)) break;
        if ((di & 1) == 0) msisdn_ie[off] = d;
        else msisdn_ie[off] = (uint8_t)(msisdn_ie[off] | (d << 4));
        di++;
    }
    if (di & 1) {
        size_t off = mi + (size_t)(di / 2);
        if (off < sizeof(msisdn_ie))
            msisdn_ie[off] = (uint8_t)((msisdn_ie[off] & 0x0f) | 0xf0);
    }
    size_t mlen = mi + (size_t)((di + 1) / 2);

    uint8_t body[128];
    size_t bo = 0;
    body[bo++] = GSUP_MSG_SRI_SM_REQ;
    if (gsup_enc_ie(body, sizeof(body), &bo, GSUP_IE_IMSI, NULL, 0) < 0)
        return -1;
    if (gsup_enc_ie(body, sizeof(body), &bo, GSUP_IE_MSISDN,
                    msisdn_ie, mlen) < 0)
        return -1;

    uint8_t ipa[160];
    uint16_t ipa_len = (uint16_t)(2 + bo);
    ipa[0] = (uint8_t)(ipa_len >> 8);
    ipa[1] = (uint8_t)(ipa_len & 0xff);
    ipa[2] = GSUP_IPA_STREAM;
    ipa[3] = GSUP_IPA_PROTO_GSUP;
    memcpy(ipa + 4, body, bo);

    ssize_t w = write(g_fd, ipa, 4 + bo);
    if (w < 0) {
        LOGE("gsup", "write failed: %s", strerror(errno));
        return -1;
    }
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

    char imsi[16] = "";
    size_t off = 1;
    while (off + 2 <= blen) {
        uint8_t ie = body[off++];
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
            if (ipa_len < 2 || off + 2 + ipa_len > g_rx_used) break;
            if (g_rx[off + 2] != GSUP_IPA_STREAM ||
                g_rx[off + 3] != GSUP_IPA_PROTO_GSUP) {
                /* IPA CCM on stream 0xFE (proto 0x00): PING(0x00) needs PONG(0x01). */
                if (ipa_len >= 3 &&
                    g_rx[off + 2] == GSUP_IPA_STREAM &&
                    g_rx[off + 3] == 0x00 &&
                    g_rx[off + 4] == 0x00) {
                    static const uint8_t pong[] = {
                        0x00, 0x03, GSUP_IPA_STREAM, 0x00, 0x01
                    };
                    (void)write(g_fd, pong, sizeof(pong));
                }
                off += 2 + ipa_len;
                continue;
            }
            gsup_dispatch_msg(g_rx + off + 4, ipa_len - 2, 0);
            off += 2 + ipa_len;
        }
        if (off > 0) {
            memmove(g_rx, g_rx + off, g_rx_used - off);
            g_rx_used -= off;
        }
        if (off == 0) break;
    }
}

int gsup_client_init(const char *remote_ip, uint16_t remote_port,
                     const char *client_name, int epoll_fd)
{
    (void)client_name;
    g_epfd = epoll_fd;
    g_rx_used = 0;
    strncpy(g_remote_ip, remote_ip ? remote_ip : "127.0.0.1",
            sizeof(g_remote_ip) - 1);
    g_remote_port = remote_port;
    if (gsup_connect_now() < 0)
        LOGW("gsup", "initial connect to %s:%u failed; retry on activity",
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

void gsup_client_set_cb(
        void (*cb)(uint32_t corr_id, int error, const char *imsi))
{
    g_cb = cb;
}

void gsup_client_shutdown(void)
{
    gsup_disconnect();
    g_cb = NULL;
}

int gsup_client_get_fd(void) { return g_fd; }
