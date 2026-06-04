#ifndef IWF_GSUP_CLIENT_H
#define IWF_GSUP_CLIENT_H

#include <stddef.h>
#include <stdint.h>

int  gsup_client_init(const char *remote_ip, uint16_t remote_port,
                     const char *client_name, int epoll_fd);
int  gsup_client_send_sri_sm_req(const char *msisdn, uint32_t corr_id);
int  gsup_client_send_raw(const uint8_t *gsup, size_t len);
void gsup_client_on_readable(void);
void gsup_client_set_cb(
        void (*cb)(uint32_t corr_id, int error, const char *imsi));
void gsup_client_set_auth_relay_cb(
        void (*cb)(const uint8_t *gsup, size_t len));
void gsup_client_shutdown(void);
int  gsup_client_get_fd(void);
void gsup_client_on_keepalive(void);

#endif /* IWF_GSUP_CLIENT_H */
