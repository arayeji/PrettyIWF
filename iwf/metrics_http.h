/*
 * metrics_http.h - lightweight HTTP server for metrics and admin APIs.
 */

#ifndef IWF_METRICS_HTTP_H
#define IWF_METRICS_HTTP_H

#include <stdint.h>

struct iwf_runtime;

#define METRICS_EPOLL_ROLE  0x200

int  metrics_http_init(struct iwf_runtime *rt, int epfd);
void metrics_http_shutdown(void);
void metrics_http_on_readable(void);

#endif /* IWF_METRICS_HTTP_H */
