/*
 * test_cmd.h - UNIX control socket for manual MAP-auth (Diameter AIR/AIA) tests.
 */

#ifndef IWF_TEST_CMD_H
#define IWF_TEST_CMD_H

#include <stddef.h>
#include <stdint.h>

struct iwf_runtime;

/* Default path if [map_iwf] cmd_sock is unset (see iwf.conf). */
#ifndef IWF_TEST_CMD_SOCK_PATH
#define IWF_TEST_CMD_SOCK_PATH "/tmp/iwf_cmd.sock"
#endif

/* Create listener unix stream socket, chmod 0666, register with epoll. */
int test_cmd_init(struct iwf_runtime *rt, int epfd);
void test_cmd_shutdown(void);
void test_cmd_on_readable(struct iwf_runtime *rt);

void test_cmd_reply_ok(int fd, unsigned n_vec,
                       const uint8_t rand16[16], const uint8_t autn16[16]);
void test_cmd_reply_err(int fd, const char *reason);

#endif /* IWF_TEST_CMD_H */
