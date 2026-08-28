/*
 * isup_call.h — BICC/ISUP call control mapped onto sip_call_t ids.
 *
 * Originate once. Fail cleanly. No PRN/IAM retry storm.
 */

#ifndef IWF_ISUP_CALL_H
#define IWF_ISUP_CALL_H

#include <stdint.h>
#include <stddef.h>

struct iwf_runtime;

int  isup_call_init(struct iwf_runtime *rt);
void isup_call_shutdown(void);
int  isup_call_reconfigure(struct iwf_runtime *rt);

/* 0 = southbound is SIP, 1 = BICC. Lookup uses called/MSRN digits. */
int  isup_call_south_is_bicc(const struct iwf_runtime *rt, const char *digits);

/* Originate IAM on a new CIC. Returns 0, or -1 (caller fails north once). */
int  isup_call_originate(struct iwf_runtime *rt, uint32_t sip_id,
                         const char *called, const char *calling,
                         int pres_restricted);

/* REL toward the far end (north BYE / CANCEL / fail). */
void isup_call_release(uint32_t sip_id, uint8_t cause);

/* Drop CIC without REL (already released / RLC). */
void isup_call_detach(uint32_t sip_id);

void isup_call_rx(struct iwf_runtime *rt, uint32_t opc, uint32_t dpc,
                   uint8_t si, const uint8_t *msu, size_t len);
void isup_call_on_timer(struct iwf_runtime *rt);

#endif /* IWF_ISUP_CALL_H */
