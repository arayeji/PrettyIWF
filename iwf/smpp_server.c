/*
 * smpp_server.c - minimal SMPP 3.4 server for Jasmin MO SMS handoff.
 */

#include "smpp_server.h"
#include "logging.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/uio.h>

#define SMPP_CMD_BIND_TRX         0x00000009u
#define SMPP_CMD_BIND_TRX_RESP    0x80000009u
#define SMPP_CMD_SUBMIT_SM        0x00000004u
#define SMPP_CMD_SUBMIT_SM_RESP   0x80000004u
#define SMPP_CMD_ENQUIRE_LINK     0x00000015u
#define SMPP_CMD_ENQUIRE_LINK_RESP 0x80000015u
#define SMPP_CMD_UNBIND           0x00000006u
#define SMPP_CMD_UNBIND_RESP      0x80000006u
#define SMPP_CMD_GENERIC_NACK     0x80000000u

#define SMPP_HDR_LEN              16
#define SMPP_RX_CAP               4096

static int g_listen_fd = -1;
static int g_conn_fd = -1;
static int g_epfd = -1;
static char g_system_id[32];
static char g_password[64];
static uint8_t g_rx[SMPP_RX_CAP];
static size_t g_rx_used = 0;
static bool g_bound = false;

static void (*g_disconnect_cb)(void) = NULL;
static void (*g_submit_cb)(uint32_t, const char *, uint8_t, uint8_t,
                           const char *, uint8_t, uint8_t,
                           uint8_t, uint8_t, const uint8_t *, uint8_t) = NULL;

static int set_nb(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void write_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static int smpp_send_pdu(uint32_t cmd_id, uint32_t status, uint32_t seq,
                         const uint8_t *body, size_t body_len)
{
    if (g_conn_fd < 0) return -1;
    uint8_t hdr[SMPP_HDR_LEN];
    uint32_t len = (uint32_t)(SMPP_HDR_LEN + body_len);
    write_be32(hdr, len);
    write_be32(hdr + 4, cmd_id);
    write_be32(hdr + 8, status);
    write_be32(hdr + 12, seq);
    struct iovec iov[2];
    iov[0].iov_base = hdr;
    iov[0].iov_len = SMPP_HDR_LEN;
    iov[1].iov_base = (void *)body;
    iov[1].iov_len = body_len;
    ssize_t w = writev(g_conn_fd, iov, body ? 2 : 1);
    return (w >= 0) ? 0 : -1;
}

int smpp_server_send_submit_resp(uint32_t seq, uint32_t status)
{
    const char mid[] = "";
    return smpp_send_pdu(SMPP_CMD_SUBMIT_SM_RESP, status, seq,
                         (const uint8_t *)mid, 1);
}

static const char *read_cstr(const uint8_t *p, size_t n, size_t *off)
{
    if (*off >= n) return NULL;
    const char *s = (const char *)(p + *off);
    size_t rem = n - *off;
    size_t l = strnlen(s, rem);
    if (l >= rem) return NULL;
    *off += l + 1;
    return s;
}

static void handle_submit_sm(uint32_t seq, const uint8_t *body, size_t n)
{
    size_t off = 0;
    (void)read_cstr(body, n, &off);
    if (off + 6 > n) {
        smpp_server_send_submit_resp(seq, SMPP_ESME_RSUBMITFAIL);
        return;
    }
    uint8_t src_ton = body[off++];
    uint8_t src_npi = body[off++];
    const char *src = read_cstr(body, n, &off);
    if (!src || off + 2 > n) {
        smpp_server_send_submit_resp(seq, SMPP_ESME_RSUBMITFAIL);
        return;
    }
    uint8_t dst_ton = body[off++];
    uint8_t dst_npi = body[off++];
    const char *dst = read_cstr(body, n, &off);
    if (!dst || off + 8 > n) {
        smpp_server_send_submit_resp(seq, SMPP_ESME_RSUBMITFAIL);
        return;
    }
    uint8_t esm_class = body[off++];
    off++; /* protocol_id */
    off++; /* priority */
    (void)read_cstr(body, n, &off);
    (void)read_cstr(body, n, &off);
    off += 2; /* reg_delivery, replace */
    uint8_t data_coding = body[off++];
    off++; /* sm_default_msg_id */
    uint8_t sm_len = body[off++];
    if (off + sm_len > n) {
        smpp_server_send_submit_resp(seq, SMPP_ESME_RSUBMITFAIL);
        return;
    }
    if (g_submit_cb)
        g_submit_cb(seq, src, src_ton, src_npi, dst, dst_ton, dst_npi,
                    data_coding, esm_class, body + off, sm_len);
    else
        smpp_server_send_submit_resp(seq, SMPP_ESME_RSUBMITFAIL);
}

static void handle_bind_trx(uint32_t seq, const uint8_t *body, size_t n)
{
    size_t off = 0;
    const char *sys = read_cstr(body, n, &off);
    const char *pass = read_cstr(body, n, &off);
    uint32_t st = SMPP_ESME_RSUBMITFAIL;
    if (sys && pass &&
        !strcmp(sys, g_system_id) && !strcmp(pass, g_password))
        st = SMPP_ESME_ROK;
    g_bound = (st == SMPP_ESME_ROK);
    smpp_send_pdu(SMPP_CMD_BIND_TRX_RESP, st, seq, NULL, 0);
}

static void dispatch_pdu(const uint8_t *pdu, size_t pdu_len)
{
    if (pdu_len < SMPP_HDR_LEN) return;
    uint32_t cmd_len = read_be32(pdu);
    if (cmd_len != pdu_len || cmd_len < SMPP_HDR_LEN) return;
    uint32_t cmd_id  = read_be32(pdu + 4);
    uint32_t status  = read_be32(pdu + 8);
    uint32_t seq     = read_be32(pdu + 12);
    const uint8_t *body = pdu + SMPP_HDR_LEN;
    size_t blen = pdu_len - SMPP_HDR_LEN;
    (void)status;

    switch (cmd_id) {
    case SMPP_CMD_BIND_TRX:
        handle_bind_trx(seq, body, blen);
        break;
    case SMPP_CMD_SUBMIT_SM:
        if (!g_bound)
            smpp_server_send_submit_resp(seq, SMPP_ESME_RSUBMITFAIL);
        else
            handle_submit_sm(seq, body, blen);
        break;
    case SMPP_CMD_ENQUIRE_LINK:
        smpp_send_pdu(SMPP_CMD_ENQUIRE_LINK_RESP, SMPP_ESME_ROK, seq, NULL, 0);
        break;
    case SMPP_CMD_UNBIND:
        smpp_send_pdu(SMPP_CMD_UNBIND_RESP, SMPP_ESME_ROK, seq, NULL, 0);
        g_bound = false;
        break;
    default:
        smpp_send_pdu(SMPP_CMD_GENERIC_NACK, 0x00000003u, seq, NULL, 0);
        break;
    }
}

static void drain_conn(void)
{
    for (;;) {
        ssize_t r = read(g_conn_fd, g_rx + g_rx_used, SMPP_RX_CAP - g_rx_used);
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            goto drop_conn;
        }
        if (r == 0) goto drop_conn;
        g_rx_used += (size_t)r;
        size_t off = 0;
        while (g_rx_used >= SMPP_HDR_LEN) {
            uint32_t len = read_be32(g_rx + off);
            if (len < SMPP_HDR_LEN || len > SMPP_RX_CAP) {
                off = g_rx_used;
                break;
            }
            if (off + len > g_rx_used) break;
            dispatch_pdu(g_rx + off, len);
            off += len;
        }
        if (off > 0) {
            memmove(g_rx, g_rx + off, g_rx_used - off);
            g_rx_used -= off;
        }
        if (off == 0) break;
    }
    return;
drop_conn:
    LOGW("smpp", "Jasmin disconnected");
    if (g_epfd >= 0 && g_conn_fd >= 0)
        epoll_ctl(g_epfd, EPOLL_CTL_DEL, g_conn_fd, NULL);
    close(g_conn_fd);
    g_conn_fd = -1;
    g_rx_used = 0;
    g_bound = false;
}

#ifndef SMS_EPOLL_ROLE_SMPP_SRV
#define SMS_EPOLL_ROLE_SMPP_SRV  0x201
#define SMS_EPOLL_ROLE_SMPP_CONN 0x202
#endif

int smpp_server_init(const char *bind_ip, uint16_t port,
                     const char *system_id, const char *password,
                     int epoll_fd)
{
    g_epfd = epoll_fd;
    strncpy(g_system_id, system_id ? system_id : "iwf", sizeof(g_system_id) - 1);
    strncpy(g_password, password ? password : "", sizeof(g_password) - 1);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (set_nb(fd) < 0) { close(fd); return -1; }

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port   = htons(port);
    inet_pton(AF_INET, bind_ip ? bind_ip : "127.0.0.1", &a.sin_addr);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
        LOGE("smpp", "bind %s:%u failed: %s", bind_ip, (unsigned)port,
             strerror(errno));
        close(fd);
        return -1;
    }
    if (listen(fd, 1) < 0) {
        close(fd);
        return -1;
    }
    g_listen_fd = fd;
    struct epoll_event ev = { .events = EPOLLIN,
                              .data = { .u64 = SMS_EPOLL_ROLE_SMPP_SRV } };
    epoll_ctl(g_epfd, EPOLL_CTL_ADD, g_listen_fd, &ev);
    LOGI("smpp", "listening on %s:%u", bind_ip, (unsigned)port);
    return 0;
}

void smpp_server_on_listen_readable(void)
{
    if (g_listen_fd < 0) return;
    struct sockaddr_in peer;
    socklen_t plen = sizeof(peer);
    int cfd = accept(g_listen_fd, (struct sockaddr *)&peer, &plen);
    if (cfd < 0) return;

    if (g_conn_fd >= 0) {
        LOGW("smpp", "replacing existing Jasmin connection");
        if (g_disconnect_cb) g_disconnect_cb();
        smpp_server_abort_inflight();
        if (g_epfd >= 0)
            epoll_ctl(g_epfd, EPOLL_CTL_DEL, g_conn_fd, NULL);
        close(g_conn_fd);
        g_conn_fd = -1;
    }
    set_nb(cfd);
    g_conn_fd = cfd;
    g_rx_used = 0;
    g_bound = false;
    struct epoll_event ev = { .events = EPOLLIN,
                              .data = { .u64 = SMS_EPOLL_ROLE_SMPP_CONN } };
    epoll_ctl(g_epfd, EPOLL_CTL_ADD, g_conn_fd, &ev);
    LOGI("smpp", "accepted Jasmin from %s:%u",
         inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));
}

void smpp_server_on_conn_readable(void)
{
    if (g_conn_fd >= 0) drain_conn();
}

void smpp_server_set_submit_cb(
        void (*cb)(uint32_t seq,
                   const char *src, uint8_t src_ton, uint8_t src_npi,
                   const char *dst, uint8_t dst_ton, uint8_t dst_npi,
                   uint8_t data_coding, uint8_t esm_class,
                   const uint8_t *ud, uint8_t ud_len))
{
    g_submit_cb = cb;
}

void smpp_server_set_disconnect_cb(void (*cb)(void))
{
    g_disconnect_cb = cb;
}

void smpp_server_abort_inflight(void)
{
    g_bound = false;
}

void smpp_server_shutdown(void)
{
    if (g_conn_fd >= 0) {
        if (g_epfd >= 0) epoll_ctl(g_epfd, EPOLL_CTL_DEL, g_conn_fd, NULL);
        close(g_conn_fd);
        g_conn_fd = -1;
    }
    if (g_listen_fd >= 0) {
        if (g_epfd >= 0) epoll_ctl(g_epfd, EPOLL_CTL_DEL, g_listen_fd, NULL);
        close(g_listen_fd);
        g_listen_fd = -1;
    }
    g_submit_cb = NULL;
    g_rx_used = 0;
    g_bound = false;
}

int smpp_server_get_listen_fd(void) { return g_listen_fd; }
int smpp_server_get_conn_fd(void) { return g_conn_fd; }
