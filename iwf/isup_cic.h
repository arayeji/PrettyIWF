/*
 * isup_cic.h — CIC allocation, state, and circuit supervision.
 *
 * Even/odd selection is agreed with the far end. We only originate on the
 * configured parity; the far end is controlling for the other parity.
 */

#ifndef IWF_ISUP_CIC_H
#define IWF_ISUP_CIC_H

#include <stdint.h>
#include <stddef.h>

struct iwf_runtime;

#define IWF_CIC_MAX 256

typedef enum {
    CIC_IDLE = 0,
    CIC_OUTGOING,
    CIC_INCOMING,
    CIC_WAIT_RLC,
    CIC_CONNECTED,
    CIC_BLOCKED_LOC,
    CIC_BLOCKED_REM,
    CIC_BLOCKED_BOTH,
} isup_cic_state_t;

int  isup_cic_init(struct iwf_runtime *rt);
void isup_cic_shutdown(void);
int  isup_cic_reconfigure(struct iwf_runtime *rt);

/* Allocate a CIC for an originating IAM. Returns CIC or -1. */
int  isup_cic_alloc(uint32_t sip_id);
void isup_cic_set_state(uint16_t cic, isup_cic_state_t st);
isup_cic_state_t isup_cic_state(uint16_t cic);
uint32_t isup_cic_sip_id(uint16_t cic);
void isup_cic_bind(uint16_t cic, uint32_t sip_id);
void isup_cic_release(uint16_t cic);

int  isup_cic_in_range(uint16_t cic);
int  isup_cic_is_ours(uint16_t cic); /* 1 if this CIC matches our even/odd */

/* Bearer map: CIC -> RTP ip:port. 0 if unset. */
int  isup_cic_rtp(uint16_t cic, char *ip, size_t ip_cap, uint16_t *port);

void isup_cic_block_local(uint16_t cic);
void isup_cic_unblock_local(uint16_t cic);
void isup_cic_block_remote(uint16_t cic);
void isup_cic_unblock_remote(uint16_t cic);
void isup_cic_reset(uint16_t cic);
void isup_cic_reset_range(uint16_t first, uint8_t range);

uint16_t isup_cic_first(void);
uint16_t isup_cic_last(void);

#endif /* IWF_ISUP_CIC_H */
