#ifndef IWF_CONFIG_H
#define IWF_CONFIG_H

#include <stdint.h>
#include <netinet/in.h>

typedef struct {
    /* [iwf] */
    char        listen_ip[64];
    uint16_t    listen_port;
    char        local_ip[64];     /* IWF source IP for S4 (defaults to listen_ip) */

    /* [sgsn] - allowed peer (informational; we accept any source by default) */
    char        sgsn_ip[64];

    /* [sgwc] - the Open5GS SGW-C we send GTPv2-C to */
    char        sgwc_ip[64];
    uint16_t    sgwc_port;

    /* [logging] */
    char        log_level[16];
    char        log_file[256];
} iwf_config_t;

int  iwf_config_load(const char *path, iwf_config_t *out);
void iwf_config_dump(const iwf_config_t *c);

#endif /* IWF_CONFIG_H */
