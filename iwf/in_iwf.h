/*
 * in_iwf.h — choosable IN query per call (CAMEL / INAP / SIP AS / none).
 *
 * Default mode=none: skip. One query, one failure, no retry.
 */

#ifndef IWF_IN_IWF_H
#define IWF_IN_IWF_H

#include <stdint.h>
#include <stddef.h>

#include "ss7_link.h"
#include "tcap.h"

struct iwf_runtime;

#define IWF_IN_NONE    0
#define IWF_IN_CAMEL   1
#define IWF_IN_INAP    2
#define IWF_IN_SIP_AS  3

#define IWF_IN_CONT     0   /* continue with original dest */
#define IWF_IN_CONNECT  1   /* replace dest */
#define IWF_IN_FAIL    -1

typedef void (*in_iwf_cb_t)(void *user, int result, const char *connect_dest);

int  in_iwf_mode_from_str(const char *s);
const char *in_iwf_mode_name(int mode);

int  in_iwf_effective_mode(const struct iwf_runtime *rt, int route_override);

/* Start one IN query. If mode is none or unconfigured, cb is invoked
 * immediately with CONT (none) or FAIL (mode set but peer empty). */
int  in_iwf_query(struct iwf_runtime *rt, uint32_t sip_id,
                   const char *called, const char *calling,
                   int mode_override, in_iwf_cb_t cb, void *user);

int  in_iwf_on_tcap(struct iwf_runtime *rt, const ss7_sccp_addr_t *calling,
                    const tcap_msg_t *tmsg);
int  in_iwf_on_sip(const char *callid, int status, const char *contact);

void in_iwf_on_timer(struct iwf_runtime *rt);
void in_iwf_cancel(uint32_t sip_id);

#endif /* IWF_IN_IWF_H */
