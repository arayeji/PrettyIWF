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

    /* [smf] PGW-C / SMF GTP-C (S5/S8) — F-TEID IE instance 1 in Create Session Request.
     * Used when pgw_select includes smf. Optional if ULA / per-partner PGW covers all. */
    char        smf_ip[64];
    uint32_t    smf_teid;         /* host byte order; SGW uses this toward SMF */

    /* [iwf] pgw_from_subscription — legacy boolean. When 0 and pgw_select is
     * unset, forces order static,dns,smf (skip ULA MIP). Prefer pgw_select. */
    int         pgw_from_subscription;

    /* PGW Create-Session source order (tried until one yields IPv4):
     *   mip    — ULA MIP6-Agent-Info IPv4 (MIP-Home-Agent-Address)
     *   dns    — DNS-resolve FQDN from ULA MIP-Home-Agent-Host, else
     *            [roaming_hlr] mncNNN_pgw_fqdn, else 3GPP APN FQDN
     *            <apn>.apn.epc.mncXXX.mccYYY.3gppnetwork.org
     *   static — [roaming_hlr] mncNNN_pgw_ip (literal, no DNS)
     *   smf    — [smf] ip
     * Default: mip,dns,static,smf. Override globally via [iwf] pgw_select
     * or per partner via [roaming_hlr] mncNNN_pgw_select. */
#define IWF_PGW_SRC_MIP     1
#define IWF_PGW_SRC_DNS     2
#define IWF_PGW_SRC_STATIC  3
#define IWF_PGW_SRC_SMF     4
#define IWF_PGW_SELECT_MAX  4
    uint8_t     pgw_select[IWF_PGW_SELECT_MAX];
    int         pgw_n_select;           /* 1..4 */
    int         pgw_select_explicit;    /* 1 if [iwf] pgw_select was set */

    /* [iwf] pgw_cache_ttl_s — subscription PGW cache invalidation (default 300). */
    int         pgw_cache_ttl_s;

    /* [logging] */
    char        log_level[16];
    char        log_file[256];
    char        trace_imsi[512];          /* optional startup prefixes (comma-sep) */

    /* [metrics] HTTP admin (Pretty5GS-compatible /admin/trace/imsi) */
    int         metrics_enabled;
    char        metrics_listen_ip[64];
    uint16_t    metrics_listen_port;

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
    /* SCCP routing indicator for CdPA/CgPA when a GT is present.
     * IWF_SCCP_RI_GT  (default): Route on GT (osmo-stp GTT).
     * IWF_SCCP_RI_SSN: Route on SSN+PC; GT digits still included in the address. */
#define IWF_SCCP_RI_GT  0
#define IWF_SCCP_RI_SSN 1
    int         map_sccp_ri;              /* default IWF_SCCP_RI_GT */
    int         map_t_dialogue_ms;        /* TCAP T-timeout default        */
    /* 1 = insertSubscriberData before updateLocation/updateGprsLocation
     *     ReturnResult (TS 29.002; UL ISD on same dialogue CONTINUE).
     * 0 = loc-up ReturnResult first, then ISD on subscriberDataMngt BEGIN. */
    int         map_isd_before_loc_up;
    char        map_cmd_sock_path[128];   /* UNIX cmd socket (SAI test); default /tmp/iwf_cmd.sock */

    /* MSRN pools for ProvideRoamingNumber (optional; empty = feature off). */
#define IWF_MSRN_MAX_POOLS    4
#define IWF_MSRN_MAX_MSC_MAPS 8
    struct {
        char     name[16];              /* thr1 / thr2 */
        char     start[20];             /* inclusive E.164 digits */
        char     end[20];
    } map_msrn_pools[IWF_MSRN_MAX_POOLS];
    int         map_msrn_n_pools;
    struct {
        char     msc_gt[24];            /* PRN msc-Number digits */
        char     pool_name[16];
    } map_msrn_msc_map[IWF_MSRN_MAX_MSC_MAPS];
    int         map_msrn_n_msc_map;
    int         map_msrn_ttl_sec;       /* default 30 */
    int         map_msrn_consume_on_lookup; /* 1 = free on msrn_lookup (default) */

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
    /* MTP Network Indicator in M3UA protocol data (Q.704). Must match the
     * STP cs7 instance (osmo-stp: network-indicator reserved = 3). */
    uint8_t     stp_network_indicator;

    /* [diameter_s6d] — up to DIAM_MAX_PEERS TCP peers (DRA load share). */
    char        diam_peer_ip[64];   /* legacy single-peer (peers[] if unset) */
    uint16_t    diam_peer_port;
#define DIAM_MAX_PEERS_CFG 8
    struct {
        char        ip[64];
        uint16_t    port;
    } diam_peers[DIAM_MAX_PEERS_CFG];
    int         diam_n_peers;
    char        diam_local_ip[64];  /* optional TCP bind before connect (DRA ACL) */
    char        diam_origin_host[128];
    /* Optional CS/VLR identity for GSUP CN=CS (osmo-msc).  When set, ULR/AIR/PUR
     * from CS sessions use this Origin-Host so HSS stores a distinct peer from
     * PS/SGSN (TS 29.272 Origin-Host registration). */
    char        diam_origin_host_cs[128];
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
    /* CN-domain eastbound backends for GSUP combine mode (CSFB vs PS):
     *   cs_backend = map|diameter   (default diameter)
     *   ps_backend = map|diameter   (default diameter)
     * CS=map uses MAP-C updateLocation toward [roaming_hlr] hlr_gt (or home
     * mncNNN_hlr_gt). PS=diameter keeps S6d AIR/ULR. */
#define GSUP_BACKEND_DIAMETER 0
#define GSUP_BACKEND_MAP      1
    int         gsup_cs_backend;
    int         gsup_ps_backend;

    /* [roaming_hlr] per-partner MAP route (foreign HLR GT + optional src IP/GT). */
#define GSUP_MAX_ROAM_ROUTES 8
    struct {
        char    mnc[4];           /* three-digit MNC string e.g. "035" */
        char    hlr_gt[24];
        uint8_t hlr_ssn;            /* default 6 (HLR) or 149 per partner */
        char    src_ip[64];         /* optional SCTP/source hint for this route */
        char    src_gt[24];         /* optional SCCP CallingParty GT override */
        int     is_local;           /* 1 = home PLMN → local Diameter dest      */
        int     use_diameter;       /* 1 = S6d via DRA (not MAP) for this MNC   */
        char    dest_realm[128];    /* partner HSS realm (DRA routing)          */
        char    dest_host[128];     /* optional pinned HSS Origin-Host          */
        /* Preconfigured PGW for this partner (S5/S8-C F-TEID). Used when
         * pgw_select includes static (pgw_ip) and/or dns (pgw_fqdn). */
        char    pgw_ip[64];
        char    pgw_fqdn[256];
        /* Optional per-partner override of [iwf] pgw_select (same tokens). */
        uint8_t pgw_select[IWF_PGW_SELECT_MAX];
        int     pgw_n_select;           /* 0 = inherit global */
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

/* Look up the preconfigured per-roaming-partner PGW for an IMSI (matches the
 * IMSI PLMN against [roaming_hlr] mncNNN_pgw_ip / mncNNN_pgw_fqdn). Returns 1
 * and points *out_ip / *out_fqdn at the matched route's strings (either may be
 * empty) when a route with a configured PGW matches; 0 otherwise. Out pointers
 * may be NULL. Always compiled (no GSUP/MAP dependency). */
int  iwf_config_roam_pgw(const iwf_config_t *cfg, const char *imsi,
                         const char **out_ip, const char **out_fqdn);

/* Effective PGW source order for this IMSI (partner override or global).
 * Writes up to IWF_PGW_SELECT_MAX tokens into out[]; returns count (>= 1). */
int  iwf_config_pgw_select(const iwf_config_t *cfg, const char *imsi,
                           uint8_t out[IWF_PGW_SELECT_MAX]);

#endif /* IWF_CONFIG_H */
