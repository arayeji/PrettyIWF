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

    /* [sgsn] - osmo-sgsn Gn GTP-C (Context Request / inter-SGSN transfer) */
    char        sgsn_ip[64];
    uint16_t    sgsn_port;

    /* [mme] LTE MME/SGW GTP-C (S11) — Gn inbound SGSN Context Request relay */
    char        mme_ip[64];
    uint16_t    mme_port;

    /* [sgwc] - the Open5GS SGW-C we send GTPv2-C to */
    char        sgwc_ip[64];
    uint16_t    sgwc_port;

    /* [smf] PGW-C / SMF GTP-C (S5/S8) — F-TEID IE instance 1 in Create Session Request */
    char        smf_ip[64];
    uint32_t    smf_teid;         /* host byte order; SGW uses this toward SMF */

    /* [logging] */
    char        log_level[16];
    char        log_file[256];

    /* ============================================================== */
    /* MAP <-> Diameter S6d IWF (independent of the GTP IWF above).   */
    /* All fields are zero/empty when the [map_iwf] section is absent */
    /* or map_iwf.enabled = 0; main.c then skips bring-up entirely.   */
    /* ============================================================== */

    /* [map_iwf] */
    int         map_iwf_enabled;          /* 0 = module disabled (default) */
    char        map_local_gt[24];         /* Global Title (E.164 digits)   */
    char        map_local_pc[16];         /* dotted SS7 point code         */
    uint8_t     map_local_ssn;            /* default 149 (SGSN)            */
    int         map_t_dialogue_ms;        /* TCAP T-timeout default        */

    /* [stp] */
    char        stp_local_ip[64];   /* optional: source IPv4 for M3UA SCTP (0.0.0.0 = any) */
    uint16_t    stp_local_port;     /* optional: local SCTP port; 0 = ephemeral (normal for client→STP) */
    char        stp_ip[64];
    uint16_t    stp_port;
    char        stp_remote_pc[16];

    /* [diameter_s6d] */
    char        diam_peer_ip[64];
    uint16_t    diam_peer_port;
    char        diam_origin_host[128];
    char        diam_origin_realm[128];
    char        diam_dest_host[128];
    char        diam_dest_realm[128];
    char        diam_product_name[64];
    uint32_t    diam_vendor_id;
    int         diam_watchdog_ms;         /* Tw, default 30000 */
    int         diam_request_timeout_ms;  /* default 10000     */

    char        cfg_path[256];    /* set by main after load; for diagnostics only */
} iwf_config_t;

int  iwf_config_load(const char *path, iwf_config_t *out);
void iwf_config_dump(const iwf_config_t *c);

#endif /* IWF_CONFIG_H */
