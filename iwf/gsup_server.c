#include "gsup_server.h"
#include "gsup_map_proxy.h"
#include "gsup_proto.h"
#include "config.h"
#include "runtime.h"
#include "logging.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#define GSUP_MAX_CONN       32
#define GSUP_RX_CAP         8192
#define GSUP_IPA_PROTO_CCM  0xFE
#define CCM_PONG            0x01

typedef struct {
    int         fd;
    int         listen_idx;
    char        bind_ip[64];
    uint8_t     rx[GSUP_RX_CAP];
    size_t      rx_used;
    bool        in_use;
} gsup_conn_t;

static struct {
    bool        active;
    int         epfd;
    int         n_listen;
    int         listen_fd[GSUP_MAX_LISTEN_IPS];
    char        listen_ip[GSUP_MAX_LISTEN_IPS][64];
    gsup_conn_t conn[GSUP_MAX_CONN];
    iwf_runtime_t *rt;
} g_srv;

static int set_nb(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static void conn_close(int cid)
{
    gsup_conn_t *c = &g_srv.conn[cid];
    if (c->fd >= 0) {
        if (g_srv.epfd >= 0)
            epoll_ctl(g_srv.epfd, EPOLL_CTL_DEL, c->fd, NULL);
        close(c->fd);
    }
    memset(c, 0, sizeof(*c));
    c->fd = -1;
}

static int conn_alloc(int fd, int listen_idx, const char *bind_ip)
{
    for (int i = 0; i < GSUP_MAX_CONN; i++) {
        if (!g_srv.conn[i].in_use) {
            g_srv.conn[i].in_use     = true;
            g_srv.conn[i].fd         = fd;
            g_srv.conn[i].listen_idx = listen_idx;
            g_srv.conn[i].rx_used    = 0;
            if (bind_ip)
                strncpy(g_srv.conn[i].bind_ip, bind_ip,
                        sizeof(g_srv.conn[i].bind_ip) - 1);
            return i;
        }
    }
    return -1;
}

static void dispatch_gsup(int conn_id, const uint8_t *gsup, size_t len)
{
    if (!g_srv.rt) return;
    gsup_map_proxy_on_gsup(g_srv.rt, conn_id, gsup, len);
}

static void handle_ipa_frame(int conn_id, const uint8_t *frame, size_t flen)
{
    if (flen < 4) return;
    uint8_t proto = frame[2];
    if (proto == GSUP_IPA_PROTO_CCM) {
        if (flen >= 4 && frame[3] == 0x00) { /* PING */
            uint8_t pong[] = { 0x00, 0x01, GSUP_IPA_PROTO_CCM, CCM_PONG };
            gsup_conn_t *c = &g_srv.conn[conn_id];
            if (c->fd >= 0)
                (void)send(c->fd, pong, sizeof(pong), MSG_NOSIGNAL);
        }
        return;
    }
    if (proto != GSUP_IPA_PROTO_OSMO || flen < 5)
        return;
    if (frame[3] != GSUP_IPA_EXT_GSUP)
        return;
    dispatch_gsup(conn_id, frame + 4, flen - 4);
}

static void conn_drain(int conn_id)
{
    gsup_conn_t *c = &g_srv.conn[conn_id];
    if (!c->in_use || c->fd < 0) return;

    for (;;) {
        if (c->rx_used >= GSUP_RX_CAP) {
            LOGW("gsup", "conn %d rx overflow; closing", conn_id);
            conn_close(conn_id);
            return;
        }
        ssize_t n = recv(c->fd, c->rx + c->rx_used,
                         GSUP_RX_CAP - c->rx_used, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            conn_close(conn_id);
            return;
        }
        if (n == 0) {
            conn_close(conn_id);
            return;
        }
        c->rx_used += (size_t)n;

        while (c->rx_used >= 3) {
            size_t ipa_len = ((size_t)c->rx[0] << 8) | (size_t)c->rx[1];
            size_t frame   = 3u + ipa_len;
            if (ipa_len < 1 || frame > GSUP_RX_CAP) {
                LOGW("gsup", "conn %d bad ipa_len=%zu; closing", conn_id, ipa_len);
                conn_close(conn_id);
                return;
            }
            if (c->rx_used < frame) break;
            handle_ipa_frame(conn_id, c->rx, frame);
            memmove(c->rx, c->rx + frame, c->rx_used - frame);
            c->rx_used -= frame;
        }
    }
}

static void accept_on_listen(int li)
{
    if (li < 0 || li >= g_srv.n_listen || g_srv.listen_fd[li] < 0)
        return;
    for (;;) {
        struct sockaddr_in peer;
        socklen_t pl = sizeof(peer);
        int cfd = accept(g_srv.listen_fd[li], (struct sockaddr *)&peer, &pl);
        if (cfd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            LOGW("gsup", "accept on %s failed: %s",
                 g_srv.listen_ip[li], strerror(errno));
            break;
        }
        if (set_nb(cfd) < 0) {
            close(cfd);
            continue;
        }
        int cid = conn_alloc(cfd, li, g_srv.listen_ip[li]);
        if (cid < 0) {
            LOGW("gsup", "conn table full; dropping peer");
            close(cfd);
            continue;
        }
        struct epoll_event ev = {
            .events = EPOLLIN | EPOLLET,
            .data.u64 = GSUP_EPOLL_PACK(GSUP_EPOLL_ROLE_CONN, (uint32_t)cid),
        };
        if (epoll_ctl(g_srv.epfd, EPOLL_CTL_ADD, cfd, &ev) < 0) {
            LOGE("gsup", "epoll_ctl conn: %s", strerror(errno));
            conn_close(cid);
            continue;
        }
        LOGI("gsup", "accepted conn=%d from %s:%u on listen %s:%u",
             cid, inet_ntoa(peer.sin_addr), (unsigned)ntohs(peer.sin_port),
             g_srv.listen_ip[li],
             (unsigned)(g_srv.rt ? g_srv.rt->cfg.gsup_listen_port : 0));
    }
}

bool gsup_server_enabled(void)
{
    return g_srv.active;
}

int gsup_server_send(int conn_id, const uint8_t *gsup, size_t len)
{
    if (!g_srv.active || conn_id < 0 || conn_id >= GSUP_MAX_CONN)
        return -1;
    gsup_conn_t *c = &g_srv.conn[conn_id];
    if (!c->in_use || c->fd < 0 || !gsup || !len)
        return -1;

    uint8_t frame[4096];
    int fl = gsup_ipa_wrap(gsup, len, frame, sizeof(frame));
    if (fl < 0) return -1;

    size_t sent = 0;
    while (sent < (size_t)fl) {
        ssize_t n = send(c->fd, frame + sent, (size_t)fl - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            conn_close(conn_id);
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

const char *gsup_server_conn_bind_ip(int conn_id)
{
    if (conn_id < 0 || conn_id >= GSUP_MAX_CONN || !g_srv.conn[conn_id].in_use)
        return "";
    return g_srv.conn[conn_id].bind_ip;
}

void gsup_server_on_epoll(iwf_runtime_t *rt, uint64_t tag)
{
    (void)rt;
    uint32_t role = GSUP_EPOLL_ROLE(tag);
    uint32_t idx  = GSUP_EPOLL_INDEX(tag);
    if (role == GSUP_EPOLL_ROLE_LISTEN)
        accept_on_listen((int)idx);
    else if (role == GSUP_EPOLL_ROLE_CONN)
        conn_drain((int)idx);
}

static int listen_one(const char *ip, uint16_t port, int li)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (set_nb(fd) < 0) { close(fd); return -1; }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        LOGE("gsup", "bind %s:%u failed: %s", ip, (unsigned)port, strerror(errno));
        close(fd);
        return -1;
    }
    if (listen(fd, 16) < 0) {
        close(fd);
        return -1;
    }
    struct epoll_event ev = {
        .events = EPOLLIN,
        .data.u64 = GSUP_EPOLL_PACK(GSUP_EPOLL_ROLE_LISTEN, (uint32_t)li),
    };
    if (epoll_ctl(g_srv.epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        close(fd);
        return -1;
    }
    g_srv.listen_fd[li] = fd;
    strncpy(g_srv.listen_ip[li], ip, sizeof(g_srv.listen_ip[li]) - 1);
    return 0;
}

static void add_runtime_listen_ip(iwf_runtime_t *rt, const char *ip)
{
    if (!ip || !*ip || rt->cfg.gsup_n_listen_ips >= GSUP_MAX_LISTEN_IPS)
        return;
    int n = rt->cfg.gsup_n_listen_ips;
    strncpy(rt->cfg.gsup_listen_ips[n], ip,
            sizeof(rt->cfg.gsup_listen_ips[n]) - 1);
    rt->cfg.gsup_n_listen_ips++;
}

int gsup_server_init(iwf_runtime_t *rt, int epfd)
{
    memset(&g_srv, 0, sizeof(g_srv));
    for (int i = 0; i < GSUP_MAX_CONN; i++)
        g_srv.conn[i].fd = -1;

    if (!rt || !rt->cfg.gsup_server_enabled)
        return 0;
    if (!rt->cfg.map_iwf_enabled) {
        LOGW("gsup", "[gsup_server].enabled=1 requires [map_iwf].enabled=1");
        return -1;
    }

    g_srv.rt   = rt;
    g_srv.epfd = epfd;

    if (rt->cfg.gsup_n_listen_ips == 0) {
        if (rt->cfg.local_ip[0])
            add_runtime_listen_ip(rt, rt->cfg.local_ip);
        else if (strcmp(rt->cfg.listen_ip, "0.0.0.0") != 0)
            add_runtime_listen_ip(rt, rt->cfg.listen_ip);
    }
    if (rt->cfg.gsup_n_listen_ips == 0) {
        LOGE("gsup", "no listen_ip/listen_ips in [gsup_server]");
        return -1;
    }

    g_srv.n_listen = rt->cfg.gsup_n_listen_ips;
    if (g_srv.n_listen > GSUP_MAX_LISTEN_IPS)
        g_srv.n_listen = GSUP_MAX_LISTEN_IPS;

    int ok = 0;
    for (int i = 0; i < g_srv.n_listen; i++) {
        if (listen_one(rt->cfg.gsup_listen_ips[i],
                       rt->cfg.gsup_listen_port, i) == 0) {
            LOGI("gsup", "listening TCP %s:%u",
                 rt->cfg.gsup_listen_ips[i],
                 (unsigned)rt->cfg.gsup_listen_port);
            ok++;
        }
    }
    if (ok == 0)
        return -1;

    gsup_map_proxy_init(rt);
    g_srv.active = true;
    return 0;
}

void gsup_server_shutdown(void)
{
    gsup_map_proxy_shutdown();
    for (int i = 0; i < GSUP_MAX_CONN; i++)
        conn_close(i);
    for (int i = 0; i < g_srv.n_listen; i++) {
        if (g_srv.listen_fd[i] >= 0) {
            if (g_srv.epfd >= 0)
                epoll_ctl(g_srv.epfd, EPOLL_CTL_DEL, g_srv.listen_fd[i], NULL);
            close(g_srv.listen_fd[i]);
            g_srv.listen_fd[i] = -1;
        }
    }
    memset(&g_srv, 0, sizeof(g_srv));
}
