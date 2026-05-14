/*
 * test_cmd.c - /tmp/iwf_cmd.sock command interface.
 *
 * Line-oriented commands (newline-terminated):
 *   sai <IMSI>\n  -> outbound Diameter AIR (same internal path as MAP SAI from SGSN).
 */

#include "test_cmd.h"

#include "map_iwf.h"
#include "runtime.h"
#include "logging.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

enum { SOCK_PATH_CAP = (int)sizeof(((struct sockaddr_un *)0)->sun_path) };
enum { LISTEN_BACKLOG = 8, CMD_LINE_MAX = 256 };

static int g_listen_fd = -1;
static char g_bound_sock_path[128];

static int mkdir_parent(const char *path)
{
    char buf[256];
    size_t n = strlen(path);
    if (n == 0 || n >= sizeof(buf))
        return -1;
    memcpy(buf, path, n + 1);
    char *sl = strrchr(buf, '/');
    if (!sl || sl == buf)
        return 0;
    *sl = '\0';
    if (mkdir(buf, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

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

static void hex16(char *dst, size_t dst_cap, const uint8_t bin[16])
{
    static const char *xd = "0123456789abcdef";
    size_t o = 0;
    if (dst_cap < 33) return;
    for (size_t i = 0; i < 16; i++) {
        dst[o++] = xd[(bin[i] >> 4) & 0x0f];
        dst[o++] = xd[bin[i] & 0x0f];
    }
    dst[o] = '\0';
}

void test_cmd_reply_ok(int fd, unsigned n_vec,
                       const uint8_t rand16[16], const uint8_t autn16[16])
{
    char hrand[48], hautn[48];
    hex16(hrand, sizeof(hrand), rand16);
    hex16(hautn, sizeof(hautn), autn16);
    char line[384];
    int n = snprintf(line, sizeof(line),
                     "OK vectors=%u rand=%s autn=%s\n",
                     n_vec, hrand, hautn);
    if (n <= 0 || (size_t)n >= sizeof(line)) {
        snprintf(line, sizeof(line), "ERR encode_response\n");
    }
    (void)wr_all(fd, line, strlen(line));
}

void test_cmd_reply_err(int fd, const char *reason)
{
    const char *r = reason ? reason : "unknown";
    char line[320];
    int n = snprintf(line, sizeof(line), "ERR %s\n", r);
    if (n <= 0 || (size_t)n >= sizeof(line))
        snprintf(line, sizeof(line), "ERR overflow\n");
    (void)wr_all(fd, line, strlen(line));
}

static void handle_accepted_client(struct iwf_runtime *rt, int cfd)
{
    char buf[CMD_LINE_MAX];
    ssize_t n = read(cfd, buf, sizeof(buf) - 1);
    if (n <= 0) {
        close(cfd);
        return;
    }
    buf[n] = '\0';
    char *nl = strchr(buf, '\n');
    if (!nl) {
        test_cmd_reply_err(cfd, "no_newline_full_line_expected");
        close(cfd);
        return;
    }
    *nl = '\0';

    while (nl > buf && nl[-1] == '\r') *--nl = '\0';

    char *pb = buf;
    while (*pb && isspace((unsigned char)*pb)) pb++;

    /* "sai" + IMSI tail */
    if (strncasecmp(pb, "sai", 3) != 0) {
        test_cmd_reply_err(cfd, "unknown_command");
        close(cfd);
        return;
    }
    pb += 3;
    while (*pb && isspace((unsigned char)*pb)) pb++;
    size_t dl = strlen(pb);
    if (dl == 0 || dl > 31) {
        test_cmd_reply_err(cfd, "usage_sai_<IMSI>");
        close(cfd);
        return;
    }

    if (map_iwf_cmd_test_sai(rt, pb, cfd) == 0) {
        /* cfd owned until AIA/error/timeout completes */
        return;
    }

    close(cfd);
}

int test_cmd_init(struct iwf_runtime *rt, int epfd)
{
    g_bound_sock_path[0] = '\0';

    if (!rt) {
        LOGW("test_cmd", "init: no runtime");
        return -1;
    }

    const char *path = rt->cfg.map_cmd_sock_path[0]
                           ? rt->cfg.map_cmd_sock_path
                           : IWF_TEST_CMD_SOCK_PATH;

    if (strlen(path) >= (size_t)SOCK_PATH_CAP) {
        LOGW("test_cmd", "cmd_sock path too long (max %d): %s",
             SOCK_PATH_CAP - 1, path);
        return -1;
    }

    if (strchr(path, '/') && mkdir_parent(path) < 0) {
        LOGW("test_cmd", "could not create parent dir for %s: %s",
             path, strerror(errno));
        /* bind may still succeed if dir exists */
    }

    unlink(path);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        LOGW("test_cmd", "socket(AF_UNIX): %s", strerror(errno));
        return -1;
    }
    if (set_nonblock(fd) < 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_un sun = { .sun_family = AF_UNIX };
    strncpy(sun.sun_path, path, sizeof(sun.sun_path) - 1);
    sun.sun_path[sizeof(sun.sun_path) - 1] = '\0';

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
        LOGW("test_cmd", "bind %s: %s", path, strerror(errno));
        close(fd);
        return -1;
    }
    if (chmod(path, 0666) < 0) {
        LOGW("test_cmd", "chmod(%s): %s", path, strerror(errno));
    }

    if (listen(fd, LISTEN_BACKLOG) < 0) {
        LOGW("test_cmd", "listen: %s", strerror(errno));
        close(fd);
        unlink(path);
        return -1;
    }

    struct epoll_event ev = { .events = EPOLLIN, .data = { .u64 = MAP_EPOLL_ROLE_TEST_CMD } };
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        LOGW("test_cmd", "epoll_ctl ADD cmd sock: %s", strerror(errno));
        close(fd);
        unlink(path);
        return -1;
    }

    strncpy(g_bound_sock_path, path, sizeof(g_bound_sock_path) - 1);
    g_bound_sock_path[sizeof(g_bound_sock_path) - 1] = '\0';

    g_listen_fd = fd;
    LOGI("test_cmd", "listening on %s (fd=%d)", path, fd);
    return 0;
}

void test_cmd_shutdown(void)
{
    if (g_listen_fd >= 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
    }
    if (g_bound_sock_path[0])
        unlink(g_bound_sock_path);
    g_bound_sock_path[0] = '\0';
}

void test_cmd_on_readable(struct iwf_runtime *rt)
{
    if (!rt || !rt->map) return;
    if (g_listen_fd < 0) return;

    for (;;) {
        int cfd = accept4(g_listen_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (cfd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EINTR) continue;
            LOGW("test_cmd", "accept: %s", strerror(errno));
            break;
        }
        handle_accepted_client(rt, cfd);
    }
}
