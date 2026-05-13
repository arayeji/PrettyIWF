/*
 * main.c - entry point and epoll event loop for the IWF.
 *
 * 3GPP reserves UDP/2123 for both GTPv1-C and GTPv2-C, and a node that
 * speaks both versions multiplexes them on the same socket. The first
 * octet's "Version" field (bits 7..5) tells us which version a datagram
 * carries (1 or 2). We therefore use a SINGLE UDP socket bound to 2123
 * and dispatch by version on receive.
 *
 * The IWF is signaling-only: no GTP-U traffic ever traverses this
 * socket. Direct Tunnel ensures GTP-U flows directly RNC <-> UPG-VPP.
 */

#include "iwf.h"
#include "runtime.h"
#include "config.h"
#include "logging.h"
#include "gtpv1.h"
#include "gtpv2.h"
#include "session.h"
#include "translate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig) { (void)sig; g_stop = 1; }

static int set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int open_udp(const char *bind_ip, uint16_t port, int *out_fd)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port   = htons(port);
    if (inet_pton(AF_INET, bind_ip, &a.sin_addr) != 1) {
        LOGE("net", "bad bind ip %s", bind_ip);
        close(fd);
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
        LOGE("net", "bind %s:%u failed: %s", bind_ip, port, strerror(errno));
        if (errno == EADDRINUSE) {
            LOGE("net", "UDP %u is already in use (often Open5GS SGW-C/MME on the same host). "
                        "Run on another machine, or set [iwf] listen_ip to a different local IPv4 than the other GTP stack, or stop the conflicting service. "
                        "Check: ss -ulnp | grep %u", port, port);
        }
        close(fd);
        return -1;
    }
    if (set_nonblock(fd) < 0) {
        LOGE("net", "fcntl O_NONBLOCK failed: %s", strerror(errno));
        close(fd);
        return -1;
    }
    *out_fd = fd;
    LOGI("net", "UDP bound on %s:%u (fd=%d)", bind_ip, port, fd);
    return 0;
}

int iwf_send_v1(iwf_runtime_t *rt, const iwf_endpoint_t *to,
                const uint8_t *buf, size_t len)
{
    ssize_t r = sendto(rt->v1_sock, buf, len, 0,
                       (const struct sockaddr *)&to->addr, to->addrlen);
    if (r < 0) {
        LOGE("net", "sendto v1 failed: %s", strerror(errno));
        return -1;
    }
    return (int)r;
}

int iwf_send_v2(iwf_runtime_t *rt, const uint8_t *buf, size_t len)
{
    /* v2 leaves on the same multiplexed socket. */
    ssize_t r = sendto(rt->v1_sock, buf, len, 0,
                       (const struct sockaddr *)&rt->sgwc_addr,
                       sizeof(rt->sgwc_addr));
    if (r < 0) {
        LOGE("net", "sendto v2 failed: %s", strerror(errno));
        return -1;
    }
    return (int)r;
}

enum sock_role { SOCK_GTP = 1, SOCK_TIMER = 3 };

static void handle_v1_packet(iwf_runtime_t *rt,
                             const iwf_endpoint_t *from,
                             const uint8_t *buf, size_t len)
{
    iwf_msg_t msg;
    if (gtpv1_parse(buf, len, &msg) < 0) {
        LOGW("net", "malformed GTPv1-C packet from %s:%u len=%zu",
             inet_ntoa(from->addr.sin_addr),
             ntohs(from->addr.sin_port), len);
        return;
    }
    iwf_log_hex("net", "RX-Gn raw", buf, len);
    translate_v1_request(rt, from, &msg);
}

static void handle_v2_packet(iwf_runtime_t *rt,
                             const iwf_endpoint_t *from,
                             const uint8_t *buf, size_t len)
{
    iwf_msg_t msg;
    if (gtpv2_parse(buf, len, &msg) < 0) {
        LOGW("net", "malformed GTPv2-C packet from %s:%u len=%zu",
             inet_ntoa(from->addr.sin_addr),
             ntohs(from->addr.sin_port), len);
        return;
    }
    iwf_log_hex("net", "RX-S4 raw", buf, len);
    translate_v2_response(rt, from, &msg);
}

static void drain_gtp_socket(iwf_runtime_t *rt)
{
    for (;;) {
        uint8_t buf[IWF_MAX_PKT];
        iwf_endpoint_t from;
        from.addrlen = sizeof(from.addr);
        ssize_t r = recvfrom(rt->v1_sock, buf, sizeof(buf), 0,
                             (struct sockaddr *)&from.addr, &from.addrlen);
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            LOGW("net", "recvfrom: %s", strerror(errno));
            return;
        }
        if (r < 1) return;

        /* Dispatch by GTP version (bits 7..5 of octet 1). */
        uint8_t version = (buf[0] >> 5) & 0x07;
        if (version == 1)      handle_v1_packet(rt, &from, buf, (size_t)r);
        else if (version == 2) handle_v2_packet(rt, &from, buf, (size_t)r);
        else {
            LOGW("net", "ignoring unknown GTP version=%u from %s:%u",
                 version, inet_ntoa(from.addr.sin_addr),
                 ntohs(from.addr.sin_port));
        }
    }
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [-c CONFIG] [-l LEVEL] [-h]\n"
        "  -c PATH    config file (default ./iwf.conf)\n"
        "  -l LEVEL   override log level: error|warn|info|debug|trace\n"
        "  -h         show this help\n", prog);
}

int main(int argc, char **argv)
{
    const char *conf_path = "iwf.conf";
    const char *level_override = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "c:l:h")) != -1) {
        switch (opt) {
        case 'c': conf_path = optarg; break;
        case 'l': level_override = optarg; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 2;
        }
    }

    iwf_runtime_t rt;
    memset(&rt, 0, sizeof(rt));

    if (iwf_config_load(conf_path, &rt.cfg) < 0) {
        fprintf(stderr, "failed to load config %s\n", conf_path);
        return 1;
    }

    iwf_log_init(iwf_log_level_from_str(level_override ? level_override
                                                       : rt.cfg.log_level),
                 rt.cfg.log_file);

    LOGI("iwf", "starting IWF v%s pid=%d config=%s",
         IWF_VERSION, (int)getpid(), conf_path);
    iwf_config_dump(&rt.cfg);

    sess_init();

    /* Resolve local IPv4 (network order) for GTP F-TEID / GSN Address IEs. */
    if (rt.cfg.local_ip[0]) {
        struct in_addr a;
        if (inet_pton(AF_INET, rt.cfg.local_ip, &a) == 1)
            rt.local_ipv4_be = a.s_addr;
    }
    if (rt.local_ipv4_be == 0) {
        struct in_addr a;
        if (inet_pton(AF_INET, rt.cfg.listen_ip, &a) == 1 &&
            a.s_addr != htonl(INADDR_ANY)) {
            rt.local_ipv4_be = a.s_addr;
        }
    }
    if (rt.local_ipv4_be == 0) {
        LOGE("iwf",
             "local_ip must be set (listen_ip is 0.0.0.0); use [iwf] local_ip");
        return 1;
    }

    /* Bind address: config listen_ip, unless 0.0.0.0 + local_ip set — then bind
     * only on local_ip so this host can share UDP/2123 with another GTP stack
     * (e.g. Open5GS SGW-C) on a different local address. */
    const char *listen_any = getenv("IWF_LISTEN_ON_ANY");
    int         force_listen_any = (listen_any && strcmp(listen_any, "1") == 0);

    const char *bind_ip = rt.cfg.listen_ip;
    if (strcmp(rt.cfg.listen_ip, "0.0.0.0") == 0 &&
        rt.cfg.local_ip[0] != '\0' &&
        !force_listen_any) {
        bind_ip = rt.cfg.local_ip;
        LOGI("iwf",
             "listen_ip is 0.0.0.0: binding UDP on local_ip %s:%u (not on all interfaces). "
             "Set env IWF_LISTEN_ON_ANY=1 to bind 0.0.0.0 instead.",
             bind_ip, (unsigned)rt.cfg.listen_port);
    }

    if (open_udp(bind_ip, rt.cfg.listen_port, &rt.v1_sock) < 0) return 1;
    rt.v2_sock = rt.v1_sock; /* multiplexed - see header comment */

    rt.sgwc_addr.sin_family = AF_INET;
    rt.sgwc_addr.sin_port   = htons(rt.cfg.sgwc_port);
    if (inet_pton(AF_INET, rt.cfg.sgwc_ip, &rt.sgwc_addr.sin_addr) != 1) {
        LOGE("iwf", "bad sgwc ip %s", rt.cfg.sgwc_ip);
        return 1;
    }

    /* Sweep timer: fires every 5 s. */
    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (tfd < 0) { perror("timerfd"); return 1; }
    struct itimerspec its = {
        .it_interval = { .tv_sec = 5, .tv_nsec = 0 },
        .it_value    = { .tv_sec = 5, .tv_nsec = 0 },
    };
    timerfd_settime(tfd, 0, &its, NULL);

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) { perror("epoll_create1"); return 1; }
    struct epoll_event ev;
    ev.events = EPOLLIN;

    ev.data.u64 = SOCK_GTP;
    epoll_ctl(epfd, EPOLL_CTL_ADD, rt.v1_sock, &ev);
    ev.data.u64 = SOCK_TIMER;
    epoll_ctl(epfd, EPOLL_CTL_ADD, tfd, &ev);

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    LOGI("iwf", "ready: UDP %s:%u (listen_ip=%s) -> S4 SGW-C=%s:%u (F-TEID/GSN %s)",
         bind_ip, rt.cfg.listen_port,
         rt.cfg.listen_ip,
         rt.cfg.sgwc_ip, rt.cfg.sgwc_port,
         inet_ntoa(*(struct in_addr *)&rt.local_ipv4_be));

    while (!g_stop) {
        struct epoll_event events[IWF_MAX_EVENTS];
        int n = epoll_wait(epfd, events, IWF_MAX_EVENTS, 1000);
        if (n < 0) {
            if (errno == EINTR) continue;
            LOGE("iwf", "epoll_wait: %s", strerror(errno));
            break;
        }
        for (int i = 0; i < n; i++) {
            uint64_t role = events[i].data.u64;
            if (role == SOCK_GTP) {
                drain_gtp_socket(&rt);
            } else if (role == SOCK_TIMER) {
                uint64_t exp;
                ssize_t r = read(tfd, &exp, sizeof(exp));
                (void)r;
                sess_sweep(time(NULL), IWF_SESSION_TIMEOUT_S);
            }
        }
    }

    LOGI("iwf", "shutting down");
    close(epfd);
    close(tfd);
    close(rt.v1_sock);
    sess_shutdown();
    iwf_log_close();
    return 0;
}
