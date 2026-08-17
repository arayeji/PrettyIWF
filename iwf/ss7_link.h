/*
 * ss7_link.h - SS7 (M3UA/SCCP) connectivity to osmo-stp via libosmo-sigtran.
 *
 * The IWF talks SCCP-N-UNITDATA primitives to osmo-stp over a single SCTP
 * association. M3UA is the underlying transport; we run as an ASP (Application
 * Server Process) in IPSP-client mode, ASP-UP -> ACTIVE.
 *
 * Outbound MAP SCCP addressing includes GT digits (when configured) plus
 * SSN/PC.  Routing indicator is configurable via [map_iwf].sccp_ri:
 *   gt  (default) — RI=GT when a GT is present (osmo-stp GTT)
 *   ssn           — RI=SSN+PC even when GT digits are present
 * Called-party DPC is [stp] remote_pc so MTP delivers to the STP.
 *
 * Build-time switch
 * -----------------
 * The MAP-IWF module compiles unconditionally, but the libosmo-sigtran-
 * backed implementation is only linked in when MAP_IWF_ENABLED=1 is set
 * (see Makefile). With MAP_IWF_ENABLED=0 the implementation is a stub
 * that returns -1 from ss7_link_init() so the module remains disabled.
 *
 * This split keeps the rest of the IWF buildable on systems that lack
 * libosmo-sigtran (e.g. CI containers without osmocom packages).
 */

#ifndef IWF_SS7_LINK_H
#define IWF_SS7_LINK_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

struct iwf_runtime;

#define SS7_SSN_HLR                     6
#define SS7_SSN_VLR                     7
#define SS7_SSN_MSC                     8
#define SS7_SSN_GMLC                    145
#define SS7_SSN_SGSN                    149     /* default for [map_iwf].local_ssn */
#define SS7_SSN_GGSN                    150

/* Maximum SCCP UNITDATA payload we are prepared to handle (well above a
 * typical MAP message of <1 KB). */
#define SS7_MAX_PDU                     4096

/* SCCP Called/Calling Party Address - a compact wire-ready handle. */
typedef struct {
    uint8_t  ssn;
    uint32_t point_code;     /* ITU 14-bit or ANSI 24-bit, low bits */
    /* Optional Global Title: ASCII E.164 digits for osmo_sccp_gt.digits[]. */
    char     gt_digits[32];
    bool     have_gt;
} ss7_sccp_addr_t;

/* Module bring-up. Reads [stp] config from rt->cfg, opens the SCTP
 * association, negotiates M3UA ASP-UP / ACTIVE, and binds the configured
 * SSN. Returns 0 on success; -1 on configuration error or transport
 * setup failure. */
int  ss7_link_init(struct iwf_runtime *rt);
void ss7_link_shutdown(struct iwf_runtime *rt);

/* Epoll fd exposed by libosmo-sigtran's IO loop, drained by main.c on
 * EPOLLIN. Returns -1 if MAP-IWF is disabled. */
int  ss7_link_get_fd(const struct iwf_runtime *rt);

/* Drain readable bytes from the SS7 link; dispatches any complete SCCP
 * UNITDATA primitives to map_iwf via ss7_link_dispatch_sccp(). */
void ss7_link_on_readable(struct iwf_runtime *rt);

bool ss7_link_is_active(const struct iwf_runtime *rt);

/* Send one TCAP message via SCCP N-UNITDATA toward the SGSN at `called`,
 * sourcing from our local SCCP address.  Returns 0 / -1.  Non-blocking. */
int  ss7_link_send_tcap(struct iwf_runtime *rt,
                        const ss7_sccp_addr_t *called,
                        const uint8_t *tcap, size_t tcap_len);

/* Receive callback installed by map_iwf.c at startup. The implementation
 * is plain function-pointer dispatch to keep ss7_link.c agnostic of MAP. */
typedef void (*ss7_recv_cb_t)(struct iwf_runtime *rt,
                              const ss7_sccp_addr_t *calling,
                              const uint8_t *tcap, size_t tcap_len);

void ss7_link_set_recv_cb(struct iwf_runtime *rt, ss7_recv_cb_t cb);

#ifdef SMS_IWF_ENABLED
void ss7_link_set_hlr_recv_cb(struct iwf_runtime *rt, ss7_recv_cb_t cb);
int  ss7_link_bind_hlr_ssn(struct iwf_runtime *rt, uint8_t ssn);
#endif

/* Bind an extra SCCP SSN that shares the main MAP recv callback (e.g. VLR=7
 * for MAP-C CSFB replies when [gsup_server] cs_backend=map). */
int  ss7_link_bind_extra_ssn(struct iwf_runtime *rt, uint8_t ssn, const char *name);

/* Outbound MAP with explicit CallingParty (e.g. per-route src GT).
 * If `calling` is NULL, uses [map_iwf] local address. */
int  ss7_link_send_tcap_ex(struct iwf_runtime *rt,
                           const ss7_sccp_addr_t *called,
                           const ss7_sccp_addr_t *calling,
                           const uint8_t *tcap, size_t tcap_len);

/* Build ss7_sccp_addr_t from E.164 digit string (international 0x91 prefix). */
void ss7_gt_from_digits(const char *digits, uint8_t ssn, ss7_sccp_addr_t *out);

/* Build a local SCCP address out of [map_iwf] config (local_pc + local_ssn,
 * optional local_gt). */
void ss7_link_make_local_addr(const struct iwf_runtime *rt,
                              ss7_sccp_addr_t *out);

#endif /* IWF_SS7_LINK_H */
