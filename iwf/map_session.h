/*
 * map_session.h - per-MAP-dialogue state for the MAP <-> Diameter IWF.
 *
 * One struct map_session exists for every outstanding MAP dialogue we are
 * acting as an agent for. The dialogue lifetime spans:
 *
 *   SGSN --MAP Begin (e.g. SAI)--> IWF
 *      [IDLE -> WAIT_DIAMETER]
 *   IWF  --Diameter AIR----------> PyHSS
 *   IWF  <--Diameter AIA---------- PyHSS
 *      [WAIT_DIAMETER -> WAIT_MAP_TX]
 *   IWF  --MAP End (SAI Resp)----> SGSN
 *      [WAIT_MAP_TX -> DONE -> freed by sweep]
 *
 * Hash table keyed by tcap_dialogue_id (Origin Transaction ID we allocate
 * locally, which becomes the Destination Transaction ID on the wire we
 * receive back from the SGSN).  Secondary index keyed on the textual
 * Diameter Session-Id we put into the AIR/ULR/CLR/PUR.
 */

#ifndef IWF_MAP_SESSION_H
#define IWF_MAP_SESSION_H

#include "iwf.h"
#include "uthash.h"

#include <netinet/in.h>
#include <time.h>

/* Logical MAP operation classes - drives the dispatch table in map_iwf.c. */
typedef enum {
    MAP_OP_NONE             = 0,
    MAP_OP_SAI              = 1,   /* sendAuthenticationInfo  - 3GPP TS 29.002 op 56 */
    MAP_OP_UGL              = 2,   /* updateGprsLocation      - op 23                */
    MAP_OP_ISD              = 3,   /* insertSubscriberData    - op 7  (we INVOKE)    */
    MAP_OP_CL               = 4,   /* cancelLocation          - op 3                 */
    MAP_OP_PURGE_MS         = 5,   /* purgeMS                 - op 67                */
} map_op_t;

typedef enum {
    MAP_SESS_IDLE           = 0,
    MAP_SESS_WAIT_DIAMETER  = 1,   /* MAP Begin received, Diameter Req in flight */
    MAP_SESS_WAIT_MAP_TX    = 2,   /* Diameter Resp received, MAP Resp to send   */
    MAP_SESS_WAIT_MAP_ACK   = 3,   /* IWF-originated ISD invoke awaiting SGSN ack*/
    MAP_SESS_DONE           = 4,
    MAP_SESS_ABORTED        = 5,
} map_sess_state_t;

#define MAP_IMSI_BCD_MAX        8
#define MAP_IMSI_STR_MAX        16     /* 15 digits + NUL */
#define MAP_MSISDN_STR_MAX      24
#define DIAMETER_SESSION_ID_MAX 128
#define MAP_APN_MAX             64
#define MAP_MAX_ULA_APN         8      /* PyHSS apn_list practical max */
#define MAP_AUTH_VECTOR_MAX     5      /* TS 29.272 max for AIA */

/* One subscribed APN extracted from ULA Subscription-Data. */
typedef struct {
    char        apn[MAP_APN_MAX];
    uint8_t     context_id;             /* 1..255, matches PyHSS context-Id */
    uint8_t     pdn_type_nr;            /* 0x21 v4, 0x57 v6, 0x8d v4v6; 0=default v4 */
    uint32_t    ambr_ul_kbps;
    uint32_t    ambr_dl_kbps;
    bool        has_ue_ipv4;            /* static IPv4 from ULA Served-Party-IP-Address */
    uint8_t     ue_ipv4[4];
    bool        has_ue_ipv6;
    uint8_t     ue_ipv6[16];
} map_ula_apn_entry_t;

/* One authentication vector parsed out of AIA, kept verbatim for repacking
 * into the MAP SAI response. Sizes are fixed by 3GPP. */
typedef struct {
    uint8_t  rand[16];
    uint8_t  autn[16];
    uint8_t  xres[16];
    uint8_t  xres_len;      /* 4..16 */
    uint8_t  ck[16];
    uint8_t  ik[16];
    /* For GSM triplets only: */
    uint8_t  sres[4];
    uint8_t  kc[8];
    bool     have_quintuplet;
    bool     have_triplet;
} map_auth_vector_t;

typedef struct map_session {
    uint32_t            tcap_dialogue_id;       /* our originating TID         */
    uint32_t            peer_tcap_dialogue_id;  /* SGSN-allocated peer TID     */
    bool                have_peer_tid;

    uint8_t             imsi_bcd[MAP_IMSI_BCD_MAX];
    uint8_t             imsi_bcd_len;
    char                imsi_str[MAP_IMSI_STR_MAX];

    char                msisdn_str[MAP_MSISDN_STR_MAX];

    char                diameter_session_id[DIAMETER_SESSION_ID_MAX];
    uint32_t            diameter_hop_by_hop;
    uint32_t            diameter_end_to_end;

    map_op_t            map_op;
    map_sess_state_t    state;

    /* Originating SGSN identity (only IP/SCCP today; SS7 PC tracked in ss7_link). */
    struct in_addr      sgsn_ip;
    uint32_t            sccp_conn_id;

    /* PLMN of the SGSN, used to populate Visited-PLMN-Id AVP. BCD encoded
     * (TS 24.008 §10.5.1.3) - 3 octets [MCC2|MCC1, MNC3|MCC3, MNC2|MNC1]. */
    uint8_t             visited_plmn_bcd[3];
    bool                have_visited_plmn;

    /* Authentication vectors returned by HSS, ready to repack into SAI Resp. */
    map_auth_vector_t   av[MAP_AUTH_VECTOR_MAX];
    uint8_t             n_av;

    /* For UGL: subscription data extracted from ULA - copied into the
     * subsequent MAP InsertSubscriberData invoke toward the SGSN. */
    map_ula_apn_entry_t ula_apns[MAP_MAX_ULA_APN];
    uint8_t             n_ula_apns;
    uint8_t             ula_default_context_id; /* profile defaultContext */
    char                ula_apn[MAP_APN_MAX];   /* default/first APN (logs) */
    uint64_t            ula_ambr_ul_bps;        /* default APN AMBR (logs) */
    uint64_t            ula_ambr_dl_bps;
    bool                have_ula_subdata;

    /* Last Result-Code from PyHSS for diagnostic logging.  0 = none yet. */
    uint32_t            diameter_result_code;

    time_t              created_at;
    time_t              last_activity;
    int                 t_dialogue_ms;          /* deadline knob, see tcap.h */

    /* Optional: UNIX command-triggered "test sai" session (Diameter AIR only).
     * When cmd_test_reply_fd >= 0, AIA replies with OK/ERR on that FD then close.
     * When cmd_test is true and fd < 0 (e.g. SIGUSR1), only log vectors. */
    bool                cmd_test;
    int                 cmd_test_reply_fd;

    /* GSUP proxy: osmo-sgsn/msc originated auth/UL via TCP GSUP (not MAP). */
    bool                gsup_originated;
    int                 gsup_conn_id;           /* gsup_server connection slot  */
    uint8_t             gsup_req_type;          /* original GSUP message type   */
    uint8_t             gsup_cn_domain;         /* GSUP_CN_DOMAIN_PS or _CS      */
    bool                gsup_isd_sent;          /* ISD_REQ sent; UL_RES skips PDP IEs */
    uint8_t             gsup_num_vectors;       /* SAI: vectors requested       */
    uint8_t             resync_rand[16];        /* SAI resync: MS RAND          */
    uint8_t             resync_auts[14];        /* SAI resync: AUTS (3GPP)      */
    bool                have_resync;            /* forward Re-Synchronization-Info */
    UT_hash_handle      hh_tid;                 /* indexed by tcap_dialogue_id */
    UT_hash_handle      hh_sid;                 /* indexed by diameter_session_id */
} map_session_t;

void            map_sess_init(void);
void            map_sess_shutdown(void);

map_session_t  *map_sess_create(uint32_t tid);
void            map_sess_remove(map_session_t *s);

map_session_t  *map_sess_find_by_tid(uint32_t tid);
map_session_t  *map_sess_find_by_diameter_sid(const char *sid);

/* GSUP proxy: pending UL/SAI session awaiting SGSN ISD ack (by IMSI). */
map_session_t  *map_sess_find_gsup_pending(const char *imsi, map_op_t op);

/* Insert into the Session-Id index. Caller must populate
 * s->diameter_session_id (NUL-terminated) before invoking. */
void            map_sess_index_by_sid(map_session_t *s);

void            map_sess_touch(map_session_t *s);

const char     *map_sess_state_str(map_sess_state_t st);
const char     *map_op_str(map_op_t op);

/* Optional hook invoked immediately before tearing down each timed-out session. */
typedef void (*map_sess_timeout_hook_t)(map_session_t *s, void *hook_ctx);

/* Periodic sweep: TCAP T-timeout fires per-dialogue.  Returns the number
 * of dialogues that were timed out and torn down.
 * If hook is non-NULL it is called (s valid) before map_sess_remove. */
int             map_sess_sweep(time_t now, map_sess_timeout_hook_t hook,
                             void *hook_ctx);

/* Iteration (for stats / shutdown). */
typedef void (*map_sess_iter_fn)(map_session_t *s, void *ctx);
void            map_sess_iterate(map_sess_iter_fn fn, void *ctx);

/* Allocate the next monotonically-increasing TCAP transaction id. */
uint32_t        map_sess_new_tid(void);

#endif /* IWF_MAP_SESSION_H */
