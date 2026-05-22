#ifndef IWF_SMPP_SERVER_H
#define IWF_SMPP_SERVER_H

#include <stdint.h>

#define SMPP_ESME_ROK              0x00000000u
#define SMPP_ESME_RINVDSTADR       0x0000000Bu
#define SMPP_ESME_RSUBMITFAIL      0x00000045u

int  smpp_server_init(const char *bind_ip, uint16_t port,
                      const char *system_id, const char *password,
                      int epoll_fd);
void smpp_server_on_listen_readable(void);
void smpp_server_on_conn_readable(void);
int  smpp_server_send_submit_resp(uint32_t seq, uint32_t status);
void smpp_server_set_submit_cb(
        void (*cb)(uint32_t seq,
                   const char *src, uint8_t src_ton, uint8_t src_npi,
                   const char *dst, uint8_t dst_ton, uint8_t dst_npi,
                   uint8_t data_coding, uint8_t esm_class,
                   const uint8_t *ud, uint8_t ud_len));
void smpp_server_shutdown(void);
void smpp_server_set_disconnect_cb(void (*cb)(void));
void smpp_server_abort_inflight(void);
int  smpp_server_get_listen_fd(void);
int  smpp_server_get_conn_fd(void);

#endif /* IWF_SMPP_SERVER_H */
