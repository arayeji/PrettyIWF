/*
 * sip_iwf.h — SIP GMSC / B2BUA toward Kamailio (3GPP Mg/Mj).
 *
 * Kamailio sends INVITE(MSISDN). IWF resolves VLR via HSS Mongo (SRI
 * equivalent), PRNs a visited VLR when needed, and originates SIP toward
 * sip-connector (local 3G) or SIP-I (roam MSRN). Kamailio never speaks MAP.
 */

#ifndef IWF_SIP_IWF_H
#define IWF_SIP_IWF_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <netinet/in.h>

struct iwf_runtime;

enum sip_iwf_epoll_role {
    SIP_EPOLL_ROLE_UDP        = 0x300,
    SIP_EPOLL_ROLE_TCP_LISTEN = 0x301,
    SIP_EPOLL_ROLE_TCP_BASE   = 0x310,
};

#define SIP_EPOLL_TCP_MAX 16
#define SIP_EPOLL_ROLE_TCP(i) (SIP_EPOLL_ROLE_TCP_BASE + (unsigned)(i))

static inline int sip_iwf_epoll_tcp_idx(uint64_t role)
{
    if (role >= SIP_EPOLL_ROLE_TCP_BASE &&
        role < SIP_EPOLL_ROLE_TCP_BASE + SIP_EPOLL_TCP_MAX)
        return (int)(role - SIP_EPOLL_ROLE_TCP_BASE);
    return -1;
}

int  sip_iwf_init(struct iwf_runtime *rt, int epfd);
void sip_iwf_shutdown(struct iwf_runtime *rt);
bool sip_iwf_enabled(const struct iwf_runtime *rt);

void sip_iwf_on_udp(struct iwf_runtime *rt);
void sip_iwf_on_tcp_listen(struct iwf_runtime *rt);
void sip_iwf_on_tcp_conn(struct iwf_runtime *rt, int idx);
void sip_iwf_on_timer(struct iwf_runtime *rt);

int  sip_iwf_parse_peer(const char *in, struct sockaddr_in *out);
int  sip_iwf_send_raw(const struct sockaddr_in *to, const char *buf, size_t len);
int  sip_iwf_on_isup_acm(uint32_t id);
int  sip_iwf_on_isup_anm(uint32_t id);
int  sip_iwf_on_isup_rel(uint32_t id, int sip_status);

#endif /* IWF_SIP_IWF_H */
