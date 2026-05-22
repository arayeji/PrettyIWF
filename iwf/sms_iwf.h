#ifndef IWF_SMS_IWF_H
#define IWF_SMS_IWF_H

#include <stdint.h>
#include <stdbool.h>

struct iwf_runtime;

enum sms_iwf_epoll_role {
    SMS_EPOLL_ROLE_SMPP_SRV  = 0x201,
    SMS_EPOLL_ROLE_SMPP_CONN = 0x202,
    SMS_EPOLL_ROLE_GSUP_SOCK = 0x203,
    SMS_EPOLL_ROLE_SMS_TIMER = 0x204,
};

int  sms_iwf_init(struct iwf_runtime *rt, int epfd);
void sms_iwf_shutdown(struct iwf_runtime *rt);
bool sms_iwf_enabled(const struct iwf_runtime *rt);

/* SS7 dispatch is via ss7_link HLR recv callback registered at init. */
void sms_iwf_on_smpp_srv_readable(void);
void sms_iwf_on_smpp_conn_readable(void);
void sms_iwf_on_gsup_readable(void);
void sms_iwf_on_timer(int fd);

#endif /* IWF_SMS_IWF_H */
