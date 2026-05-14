/*
 * map_iwf.h - MAP <-> Diameter S6d Interworking Function.
 *
 * Architecture (companion to the existing GTPv1<->GTPv2 module):
 *
 *   Foreign SGSN (roaming)
 *       |  MAP / Gr  (SS7 over SCTP via GRX)
 *       v
 *   osmo-stp (SS7 STP)                         <-- external
 *       |  SCCP / M3UA
 *       v
 *   MAP-IWF  (this module)
 *       |  Diameter S6d
 *       v
 *   PyHSS (Diameter server)                    <-- external
 *
 * Five MAP operations are translated (TS 29.002 / TS 29.272):
 *   - sendAuthenticationInfo    <-> Authentication-Information-Request   (AIR/AIA)
 *   - updateGprsLocation        <-> Update-Location-Request              (ULR/ULA)
 *   - cancelLocation            <-> Cancel-Location-Request              (CLR/CLA)
 *   - purgeMS                   <-> Purge-UE-Request                     (PUR/PUA)
 *   - insertSubscriberData      <-  (pushed during UGL after ULA arrives)
 *
 * This header is the single integration point used by main.c. All other MAP
 * IWF sources are private to the module.
 */

#ifndef IWF_MAP_IWF_H
#define IWF_MAP_IWF_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

struct iwf_runtime;
struct map_session;

/* Module bring-up.  `epfd` is the main event loop's epoll fd; the module
 * uses it to (de)register its own sockets on reconnect.  Returns 0 on
 * success; -1 on failure (and the caller is expected to log + exit).
 * When [map_iwf].enabled == 0 this is a no-op. */
int  map_iwf_init(struct iwf_runtime *rt, int epfd);

/* Register module file descriptors with the main epoll set.  The epoll role
 * tags below are reserved exclusively for MAP-IWF and live alongside the
 * existing SOCK_GTP / SOCK_TIMER roles used by main.c. */
enum map_iwf_epoll_role {
    MAP_EPOLL_ROLE_BASE     = 0x100,
    MAP_EPOLL_ROLE_SS7      = 0x101, /* SCTP fd to osmo-stp (M3UA)        */
    MAP_EPOLL_ROLE_DIAMETER = 0x102, /* TCP fd to PyHSS                   */
    MAP_EPOLL_ROLE_T_TIMER  = 0x103, /* TCAP dialogue T-timeout sweep     */
    MAP_EPOLL_ROLE_DWA_TIMER= 0x104, /* Diameter watchdog (DWR every Tw)  */
    MAP_EPOLL_ROLE_TEST_CMD = 0x105, /* UNIX /tmp/iwf_cmd.sock listener   */
};

/* Tell main.c which fds to add to the loop.  Each fd value is < 0 when the
 * subsystem is disabled in config; main.c MUST skip those. */
int  map_iwf_get_ss7_fd(const struct iwf_runtime *rt);
int  map_iwf_get_diameter_fd(const struct iwf_runtime *rt);
int  map_iwf_get_ttimer_fd(const struct iwf_runtime *rt);
int  map_iwf_get_dwa_timer_fd(const struct iwf_runtime *rt);

/* Per-epoll-event entry points.  Drain everything pending; never block. */
void map_iwf_on_ss7_readable(struct iwf_runtime *rt);
void map_iwf_on_diameter_readable(struct iwf_runtime *rt);
void map_iwf_on_ttimer_tick(struct iwf_runtime *rt);
void map_iwf_on_dwa_timer_tick(struct iwf_runtime *rt);

/* Graceful teardown: DPR toward PyHSS, ASP-DOWN to osmo-stp, drop dialogues. */
void map_iwf_shutdown(struct iwf_runtime *rt);

bool map_iwf_enabled(const struct iwf_runtime *rt);

/* Local test trigger: Diameter AIR for IMSI digits (no TCAP toward SS7).
 * reply_unix_fd < 0 means log only (e.g. SIGUSR1). On validation error the FD
 * remains owned by the caller. Otherwise the FD is owned until AIA, error,
 * or timeout. Returns 0 when the caller must not close reply_unix_fd; -1
 * when the caller still owns reply_unix_fd (validation errors only). */
int  map_iwf_cmd_test_sai(struct iwf_runtime *rt,
                          const char *imsi_digits,
                          int reply_unix_fd);
void map_iwf_sigusr1_test_sai(struct iwf_runtime *rt);

/* ------------------------------------------------------------------- */
/* Cross-module callbacks invoked by the Diameter layer when a response */
/* (AIA/ULA/CLA/PUA) arrives, keyed by Diameter Session-Id back to the  */
/* originating MAP dialogue. Implemented in map_iwf.c.                  */
/* ------------------------------------------------------------------- */
void map_iwf_on_aia(struct iwf_runtime *rt, struct map_session *s,
                    const uint8_t *raw, size_t raw_len);
void map_iwf_on_ula(struct iwf_runtime *rt, struct map_session *s,
                    const uint8_t *raw, size_t raw_len);
void map_iwf_on_cla(struct iwf_runtime *rt, struct map_session *s,
                    const uint8_t *raw, size_t raw_len);
void map_iwf_on_pua(struct iwf_runtime *rt, struct map_session *s,
                    const uint8_t *raw, size_t raw_len);

/* Diameter error path: dialogue dies with MAP SystemFailure toward SGSN. */
void map_iwf_diameter_error(struct iwf_runtime *rt, struct map_session *s,
                            uint32_t diameter_result_code);

#endif /* IWF_MAP_IWF_H */
