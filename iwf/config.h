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
    char        map_cmd_sock_path[128];   /* UNIX cmd socket (SAI test); default /tmp/iwf_cmd.sock */

    /* [stp] */
    char        stp_local_ip[64];   /* optional: source IPv4 for M3UA SCTP (0.0.0.0 = any) */
    uint16_t    stp_local_port;     /* optional: local SCTP port; 0 = ephemeral (normal for client→STP) */
    char        stp_ip[64];
    uint16_t    stp_port;
    char        stp_remote_pc[16];
    /* M3UA RKM routing context ID (distinct per ASP on shared STP). 0 =
     * omit ROUTE_CTX so SG allocates (libosmo). Default 1 avoids clashes
     * with stacks that commonly use RCTX 3 (e.g. osmo-sgsn). */
    uint32_t    stp_routing_context;

    /* [diameter_s6d] */
    char        diam_peer_ip[64];
    uint16_t    diam_peer_port;
    char        diam_local_ip[64];  /* optional TCP bind before connect (DRA ACL) */
    char        diam_origin_host[128];
    char        diam_origin_realm[128];
    char        diam_dest_host[128];
    char        diam_dest_realm[128];
    char        diam_product_name[64];
    uint32_t    diam_vendor_id;
    int         diam_watchdog_ms;         /* Tw, default 30000 */
    int         diam_request_timeout_ms;  /* default 10000     */

    char        cfg_path[256];    /* set by main after load; for diagnostics only */

    /* [gsup_server] GSUP proxy/router toward osmo-sgsn/osmo-msc (TCP/4222).
     * Requires MAP-IWF build (make MAP_IWF_ENABLED=1) and [map_iwf].enabled=1
     * for Diameter + SS7 backends.  When gsup_server.enabled=0 (default) the
     * GTP and inbound MAP-IWF paths are unchanged. */
    int         gsup_server_enabled;
    uint16_t    gsup_listen_port;
#define GSUP_MAX_LISTEN_IPS 8
    char        gsup_listen_ips[GSUP_MAX_LISTEN_IPS][64];
    int         gsup_n_listen_ips;
    char        gsup_local_mnc[4];        /* home PLMN MNC digits, default 012 */
    int         gsup_timeout_ms;

    /* [roaming_hlr] per-partner MAP route (foreign HLR GT + optional src IP/GT). */
#define GSUP_MAX_ROAM_ROUTES 8
    struct {
        char    mnc[4];           /* three-digit MNC string e.g. "035" */
        char    hlr_gt[24];
        uint8_t hlr_ssn;            /* default 6 (HLR) or 149 per partner */
        char    src_ip[64];         /* optional SCTP/source hint for this route */
        char    src_gt[24];         /* optional SCCP CallingParty GT override */
        int     is_local;           /* 1 = PyHSS/Diameter path (no foreign GT) */
    } gsup_roam_routes[GSUP_MAX_ROAM_ROUTES];
    int         gsup_n_roam_routes;

#ifdef SMS_IWF_ENABLED
    /* [sms_iwf] — MAP SMS interworking (requires MAP-IWF + SMS_IWF_ENABLED build). */
    int         sms_iwf_enabled;
    uint8_t     sms_hlr_ssn;
    char        sms_local_msc_gt[24];
    char        sms_local_smsc_gt[24];
    int         sms_gsup_timeout_ms;
    int         sms_sri_sm_timeout_ms;
    int         sms_fwdsm_timeout_ms;

    /* [gsup_client] */
    char        gsup_remote_ip[64];
    uint16_t    gsup_remote_port;
    char        gsup_client_name[64];

    /* [smpp_server] */
    char        smpp_bind_ip[64];
    uint16_t    smpp_port;
    char        smpp_system_id[32];
    char        smpp_password[64];

#define SMS_MAX_PARTNERS 8
#define SMS_MAX_PREFIXES 16
    struct {
        char    name[32];
        char    hlr_gt[24];
        char    prefixes_raw[256];
        char    prefix[SMS_MAX_PREFIXES][16];
        int     n_prefixes;
    } sms_partners[SMS_MAX_PARTNERS];
    int         sms_n_partners;
#endif /* SMS_IWF_ENABLED */

} iwf_config_t;

int  iwf_config_load(const char *path, iwf_config_t *out);
void iwf_config_dump(const iwf_config_t *c);

#endif /* IWF_CONFIG_H */
