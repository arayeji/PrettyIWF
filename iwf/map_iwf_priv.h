/*
 * map_iwf_priv.h - internal shared state for the MAP-Diameter IWF.
 *
 * This header is included only by the MAP-IWF translation units
 * (map_iwf.c, diameter.c, ss7_link.c, map_session.c).  Do NOT include
 * it from main.c / config.c / GTP modules.
 *
 * runtime.h forward-declares `struct map_iwf_state` and the runtime
 * holds a pointer to it - this lets the GTP modules be built without
 * dragging libosmo-sigtran headers in.
 */

#ifndef IWF_MAP_IWF_PRIV_H
#define IWF_MAP_IWF_PRIV_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>

#include "ss7_link.h"

/* ----- Diameter peer connection state ------------------------------ */

typedef enum {
    DIAM_CONN_CLOSED        = 0,
    DIAM_CONN_CONNECTING    = 1,    /* TCP connect() pending     */
    DIAM_CONN_CER_SENT      = 2,    /* awaiting CEA              */
    DIAM_CONN_OPEN          = 3,    /* CEA received, app traffic */
    DIAM_CONN_DPR_SENT      = 4,    /* shutting down             */
} diameter_conn_state_t;

#define DIAM_RX_BUF_CAP         8192
#define DIAM_TX_BUF_CAP         8192
#define DIAM_MAX_PEERS          8

typedef struct {
    char                 peer_ip[64];
    uint16_t             peer_port;
    int                  fd;                       /* TCP socket; -1 closed     */
    diameter_conn_state_t state;
    struct sockaddr_in   peer;                     /* resolved peer address   */
    time_t               last_rx_at;
    time_t               last_dwr_at;
    time_t               cer_sent_at;              /* CER sent, awaiting CEA    */
    time_t               reconnect_not_before;     /* earliest retry after fail */
    uint32_t             reconnect_backoff_s;      /* doubles on failure        */

    /* Stream reassembly: partial Diameter message head/body. */
    uint8_t              rx[DIAM_RX_BUF_CAP];
    size_t               rx_used;

    /* Buffered tx for short writes. */
    uint8_t              tx[DIAM_TX_BUF_CAP];
    size_t               tx_used;
} diameter_peer_t;

typedef struct {
    int                  n_peers;
    diameter_peer_t      peer[DIAM_MAX_PEERS];
    int                  rr_next;                  /* round-robin load share    */
    int                  watchdog_timerfd;         /* periodic DWR (all peers)  */
    uint32_t             origin_state_id;
    uint32_t             hop_by_hop_seed;
    uint32_t             end_to_end_seed;
} diameter_pool_t;

/* ----- SS7 (M3UA/SCCP) side state ---------------------------------- */

typedef struct {
    int                  fd;                       /* libosmo-sigtran fd or -1 */
    bool                 active;                   /* ASP-ACTIVE achieved     */
    ss7_recv_cb_t        recv_cb;
    /* The libosmo-sigtran specifics (osmo_ss7_instance, osmo_sccp_user, ASP
     * pointers) are opaque to this header so we don't pull in libosmocore.
     * They are stored in a void* and managed by ss7_link.c. */
    void                *opaque;
} ss7_state_t;

/* ----- Top-level MAP-IWF state ------------------------------------- */

typedef struct map_iwf_state {
    bool                 enabled;
    diameter_pool_t      diam;
    ss7_state_t          ss7;

    /* epoll fd of the main event loop, set by main.c before init.  The
     * diameter and ss7 layers use this to (de)register their own sockets
     * as they (re)connect, so main.c does not need to track fd churn. */
    int                  epoll_fd;

    /* TCAP T-timeout sweep fd (per-dialogue check, fires every 1s). */
    int                  t_timer_fd;

    /* Stats - exposed for /sigil/stats hook in the future. */
    uint64_t             stat_map_rx;
    uint64_t             stat_map_tx;
    uint64_t             stat_diam_rx;
    uint64_t             stat_diam_tx;
    uint64_t             stat_timeouts;
    uint64_t             stat_systemfailures_sent;
} map_iwf_state_t;

#endif /* IWF_MAP_IWF_PRIV_H */
