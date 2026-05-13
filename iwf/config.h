#ifndef IWF_CONFIG_H
#define IWF_CONFIG_H

#include <stdint.h>
#include <netinet/in.h>

typedef struct {
    /* [iwf] */
    char        listen_ip[64];
    uint16_t    listen_port;
    char        local_ip[64];     /* IWF source IP for S4 (defaults to listen_ip) */
    int         synthetic_uli_no_rai; /* lab: build ULI from IMSI PLMN if Gn omits RAI */
    uint8_t     rat_type;         /* GTPv2 RAT Type sent in Create Session Request */

    /* [sgsn] - allowed peer (informational; we accept any source by default) */
    char        sgsn_ip[64];

    /* [sgwc] - the Open5GS SGW-C we send GTPv2-C to */
    char        sgwc_ip[64];
    uint16_t    sgwc_port;

    /* [smf] PGW-C / SMF GTP-C (S5/S8) — F-TEID IE instance 1 in Create Session Request */
    char        smf_ip[64];
    uint32_t    smf_teid;         /* host byte order; SGW uses this toward SMF */

    /* [logging] */
    char        log_level[16];
    char        log_file[256];

    char        cfg_path[256];    /* set by main after load; for diagnostics only */
} iwf_config_t;

int  iwf_config_load(const char *path, iwf_config_t *out);
void iwf_config_dump(const iwf_config_t *c);

#endif /* IWF_CONFIG_H */
