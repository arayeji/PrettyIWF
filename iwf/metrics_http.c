/*
 * metrics_http.c - HTTP admin API (Pretty5GS-compatible trace endpoints).
 *
 *   GET /admin/trace/imsi?imsi=<prefix>
 *   GET /admin/trace/imsi?imsi=<imsi>&match=exact
 *   GET /admin/trace/imsi?imsi=list
 *   GET /admin/trace/imsi?imsi=<prefix>&remove=1
 *   GET /admin/trace/imsi?force=1
 *   GET /admin/trace/imsi?imsi=<prefix>&replace=1
 */

#include "metrics_http.h"
#include "imsi_trace.h"
#include "logging.h"
#include "runtime.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

enum { HTTP_REQ_MAX = 8192, HTTP_BODY_MAX = 65536, LISTEN_BACKLOG = 8 };

static int g_listen_fd = -1;

static int set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int wr_all(int fd, const void *buf, size_t len)
{
    const char *p = (const char *)buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static void http_url_decode(char *s)
{
    char *src = s, *dst = s;
    while (*src) {
        if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else if (*src == '%' && isxdigit((unsigned char)src[1]) &&
                   isxdigit((unsigned char)src[2])) {
            char hex[3] = { src[1], src[2], '\0' };
            *dst++ = (char)strtol(hex, NULL, 16);
            src += 3;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

static const char *query_val(const char *query, const char *key, char *buf, size_t cap)
{
    size_t klen;
    const char *p, *end, *amp;

    if (!query || !key || !buf || cap == 0)
        return NULL;
    klen = strlen(key);
    for (p = query; *p; p = amp ? amp + 1 : p + strlen(p)) {
        amp = strchr(p, '&');
        end = amp ? amp : p + strlen(p);
        if ((size_t)(end - p) <= klen + 1 || p[klen] != '=' ||
            strncmp(p, key, klen) != 0)
            continue;
        p += klen + 1;
        if ((size_t)(end - p) >= cap)
            return NULL;
        memcpy(buf, p, (size_t)(end - p));
        buf[end - p] = '\0';
        http_url_decode(buf);
        return buf;
    }
    return NULL;
}

static int query_flag(const char *query, const char *key)
{
    char tmp[16];
    const char *v = query_val(query, key, tmp, sizeof(tmp));
    if (!v) return 0;
    return (strcmp(v, "1") == 0 || strcasecmp(v, "true") == 0 ||
            strcasecmp(v, "yes") == 0);
}

static void handle_trace_imsi(const char *query, int cfd)
{
    char body[HTTP_BODY_MAX];
    size_t body_len = 0;
    char imsi_buf[32];
    char match_buf[16];
    iwf_imsi_trace_query_t q = {0};
    int status;

    q.imsi = query_val(query, "imsi", imsi_buf, sizeof(imsi_buf));
    q.match = query_val(query, "match", match_buf, sizeof(match_buf));
    q.remove = query_flag(query, "remove");
    q.replace = query_flag(query, "replace");
    q.force = query_flag(query, "force");

    status = iwf_imsi_trace_admin(&q, body, sizeof(body), &body_len);
    if (body_len >= sizeof(body))
        body_len = sizeof(body) - 1;

    const char *status_line = "200 OK";
    if (status == 400) status_line = "400 Bad Request";
    else if (status == 500) status_line = "500 Internal Server Error";

    char hdr[256];
    int hlen = snprintf(hdr, sizeof(hdr),
                        "HTTP/1.1 %s\r\n"
                        "Content-Type: application/json\r\n"
                        "Content-Length: %zu\r\n"
                        "Connection: close\r\n\r\n",
                        status_line, body_len);
    if (hlen > 0)
        wr_all(cfd, hdr, (size_t)hlen);
    if (body_len > 0)
        wr_all(cfd, body, body_len);
}

static void serve_client(int cfd)
{
    char req[HTTP_REQ_MAX];
    ssize_t n = read(cfd, req, sizeof(req) - 1);
    if (n <= 0)
        return;
    req[n] = '\0';

    char *line_end = strstr(req, "\r\n");
    if (!line_end)
        return;
    *line_end = '\0';

    char method[16] = {0}, path[512] = {0}, proto[16] = {0};
    if (sscanf(req, "%15s %511s %15s", method, path, proto) != 3)
        return;
    if (strcasecmp(method, "GET") != 0) {
        const char *resp =
            "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n";
        wr_all(cfd, resp, strlen(resp));
        return;
    }

    char *query = strchr(path, '?');
    if (query) {
        *query = '\0';
        query++;
    }

    if (strcmp(path, "/admin/trace/imsi") == 0) {
        handle_trace_imsi(query ? query : "", cfd);
        return;
    }
    if (strcmp(path, "/metrics") == 0 || strcmp(path, "/") == 0) {
        const char *body = "# IWF metrics placeholder\n";
        char hdr[256];
        int hlen = snprintf(hdr, sizeof(hdr),
                            "HTTP/1.1 200 OK\r\n"
                            "Content-Type: text/plain\r\n"
                            "Content-Length: %zu\r\n"
                            "Connection: close\r\n\r\n",
                            strlen(body));
        if (hlen > 0) wr_all(cfd, hdr, (size_t)hlen);
        wr_all(cfd, body, strlen(body));
        return;
    }

    const char *nf =
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    wr_all(cfd, nf, strlen(nf));
}

static int open_listen(const char *bind_ip, uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    if (inet_pton(AF_INET, bind_ip, &a.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, LISTEN_BACKLOG) < 0) {
        close(fd);
        return -1;
    }
    if (set_nonblock(fd) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int metrics_http_init(struct iwf_runtime *rt, int epfd)
{
    if (!rt || !rt->cfg.metrics_enabled)
        return 0;

    g_listen_fd = open_listen(rt->cfg.metrics_listen_ip,
                              rt->cfg.metrics_listen_port);
    if (g_listen_fd < 0) {
        LOGE("metrics", "bind %s:%u failed: %s",
             rt->cfg.metrics_listen_ip,
             (unsigned)rt->cfg.metrics_listen_port,
             strerror(errno));
        return -1;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.u64 = METRICS_EPOLL_ROLE;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, g_listen_fd, &ev) < 0) {
        LOGE("metrics", "epoll_ctl failed: %s", strerror(errno));
        close(g_listen_fd);
        g_listen_fd = -1;
        return -1;
    }

    LOGI("metrics", "HTTP admin on http://%s:%u/admin/trace/imsi",
         rt->cfg.metrics_listen_ip,
         (unsigned)rt->cfg.metrics_listen_port);
    return 0;
}

void metrics_http_shutdown(void)
{
    if (g_listen_fd >= 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
    }
}

void metrics_http_on_readable(void)
{
    if (g_listen_fd < 0)
        return;

    for (;;) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        int cfd = accept(g_listen_fd, (struct sockaddr *)&peer, &plen);
        if (cfd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            LOGW("metrics", "accept: %s", strerror(errno));
            return;
        }
        set_nonblock(cfd);
        serve_client(cfd);
        close(cfd);
    }
}
