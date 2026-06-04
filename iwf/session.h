/*
 * session.h - per-(IMSI, NSAPI) session state for the IWF.
 *
 * State machine:
 *   IDLE --Create PDP--> CREATING --CSReq sent--> WAIT_CS_RESP
 *      ^-- CSResp arrives, send Create PDP Resp --> ACTIVE
 *
 *   ACTIVE --Update PDP--> MODIFYING --MBReq sent--> WAIT_MB_RESP
 *      ^-- MBResp arrives (matching seq), send Update PDP Resp --> ACTIVE
 *
 *   After CSResp we may send an activation Modify Bearer before GTPv1 Update PDP.
 *   If Update PDP arrives before that activation MBResp returns, two MB sequences
 *   are outstanding — correlate MBResp by mb_pending_*_seq, not only state.
 *
 *   ACTIVE --Delete PDP--> DELETING --DSReq sent--> WAIT_DS_RESP
 *      ^-- DSResp arrives, send Delete PDP Resp --> IDLE (and free)
 */

#ifndef IWF_SESSION_H
#define IWF_SESSION_H

#include "iwf.h"
#include "uthash.h"

typedef enum {
    SESS_IDLE = 0,
    SESS_CREATING,
    SESS_WAIT_CS_RESP,
    SESS_ACTIVE,
    SESS_MODIFYING,
    SESS_WAIT_MB_RESP,
    /* Bearer activation MBReq sent right after CSResp (no preceding Update PDP
     * from osmo-sgsn). MBResp must NOT generate a GTPv1 Update PDP Response. */
    SESS_WAIT_MB_RESP_INIT,
    SESS_DELETING,
    SESS_WAIT_DS_RESP,
} sess_state_t;

#define IWF_IMSI_MAX 20       /* 15-digit IMSI + NUL; 8 BCD octets can hold up to 16 digits */
#define IWF_APN_MAX  64
#define IWF_MSISDN_MAX 24     /* E.164 BCD in IE can be long; + NUL */

typedef struct {
    char     imsi[IWF_IMSI_MAX];      /* 5-15 digits, NUL-terminated */
    uint8_t  nsapi;
} sess_key_t;

typedef struct sess_s {
    sess_key_t  key;

    /* Identifiers passed between peers. */
    char        msisdn[IWF_MSISDN_MAX];
    char        apn[IWF_APN_MAX];

    /* GTPv1 (Gn / S4-SGSN side) */
    uint32_t    sgsn_addr_ipv4;       /* SGSN GTP-U IPv4 (user-traffic GSN IE / peer) */
    uint32_t    sgsn_ctrl_teid;       /* SGSN's control-plane TEID (we send to it) */
    uint32_t    sgsn_data_teid;       /* SGSN/RNC user-plane TEID (DT: RNC TEID after Update) */
    uint16_t    sgsn_seq;             /* last GTPv1 request seq we answer with */
    iwf_endpoint_t sgsn_ep;           /* where the request came from */

    /* IWF-allocated TEIDs we advertise to peers. */
    uint32_t    iwf_ctrl_teid;        /* TEID we tell osmo-sgsn (GGSN ctrl) */

    /* GTPv2 (S4 / SGW-C side) */
    uint32_t    sgwc_addr_ipv4;       /* SGW-C control IP */
    uint32_t    sgwc_ctrl_teid;       /* SGW-C control-plane TEID for this session */
    uint32_t    iwf_s4_c_teid;        /* TEID we present as S4-SGSN GTP-C F-TEID */
    uint32_t    sgwu_addr_ipv4;       /* SGW-U IP returned in CSResp F-TEID */
    uint32_t    sgwu_teid;            /* SGW-U TEID -> given back to osmo-sgsn */

    /* UE assigned address */
    uint32_t    ue_ipv4;

    /* Charging ID returned by SMF (GTPv2 IE 94 in Bearer Context). 0 means SMF
     * did not include one and we fall back to iwf_ctrl_teid. CDR correlation
     * across SGW/PGW relies on this matching what SMF sees. */
    uint32_t    charging_id;

    /* Outstanding transaction (Gn-side seq we'll answer with on SGW response) */
    uint32_t    gtpv2_seq;            /* sequence used toward SGW-C */

    /* Outstanding Modify Bearer toward SGW-C (24-bit seq match on MBResp).
     * Activation MB after CSResp vs Update PDP MB may overlap — never attach the
     * wrong MBResp to GTPv1 Update PDP Response. */
    uint32_t    mb_pending_init_seq;
    uint32_t    mb_pending_update_seq;

    /* QoS we received from osmo-sgsn (3GPP TS 24.008 §10.5.6.5), kept verbatim
     * to echo back in the Create PDP Response. */
    uint8_t     qos_blob[64];
    size_t      qos_len;

    /* Protocol Configuration Options captured from CSResp (GTPv2 IE 78) and
     * forwarded verbatim as GTPv1 IE 132 in Create PDP Response. EPS PCO wire
     * format is identical between TS 29.060 §7.7.31 and TS 29.274 §8.13:
     * Ext|CfgProto byte + container TLVs (DNS=0x000D, MTU=0x0010, IMCN=0x0008,
     * BCM=0x0005, IPCP=0x8021), so a verbatim copy is correct. */
    uint8_t     pco_blob[252];
    size_t      pco_len;

    /* User Location Information cached from Create PDP, replayed in MBReq.
     * uli_kind: 0 = none, 1 = real RAI (uli_rai6 holds the 6 octets),
     *           2 = synthetic from IMSI PLMN (uli_mcc/uli_mnc used). */
    uint8_t     uli_kind;
    uint8_t     uli_rai6[6];
    uint16_t    uli_mcc;
    uint16_t    uli_mnc;

    /* State + timestamps */
    sess_state_t state;
    time_t       created_at;
    time_t       last_activity;

    UT_hash_handle hh;
} sess_t;

void  sess_init(void);
void  sess_shutdown(void);

sess_t *sess_find(const char *imsi, uint8_t nsapi);
sess_t *sess_find_by_iwf_ctrl_teid(uint32_t teid);
sess_t *sess_find_by_iwf_s4_c_teid(uint32_t teid);
/* When SGW sends header TEID 0 (T=0) or wrong TEID, correlate by our last seq. */
sess_t *sess_find_by_pending_v2_seq(uint32_t seq24, sess_state_t expect_state);
/* Retransmitted Create PDP may omit NSAPI IE — match only IMSI + GTPv1 seq. */
sess_t *sess_find_pending_create_by_imsi_gnseq(const char *imsi, uint16_t gn_seq);
/* Open5GS SMF enforces one PDN session per (IMSI, APN); a second Create-Session
 * for the same pair triggers `OLD Session Will Release` and silently kills the
 * first PDN. Returns the *active* session (ACTIVE / WAIT_MB_RESP / MODIFYING /
 * WAIT_MB_RESP_INIT) for an IMSI on the given APN at a *different* NSAPI, so
 * the caller can reject the duplicate before sending CSReq. APN compare is
 * case-insensitive (TS 23.003 says APN labels are case-insensitive). */
sess_t *sess_find_active_by_imsi_apn_other_nsapi(const char *imsi,
                                                 const char *apn,
                                                 uint8_t exclude_nsapi);
sess_t *sess_create(const char *imsi, uint8_t nsapi);
void    sess_remove(sess_t *s);

/* Mint new locally-unique TEIDs. */
uint32_t sess_new_teid(void);

void sess_touch(sess_t *s);
const char *sess_state_str(sess_state_t st);

/* Periodic sweep: remove sessions older than timeout_s without activity. */
void sess_sweep(time_t now, int timeout_s);

/* Iterate over all sessions (for stats / shutdown). */
typedef void (*sess_iter_fn)(sess_t *s, void *ctx);
void sess_iterate(sess_iter_fn fn, void *ctx);

#endif /* IWF_SESSION_H */
