/*
 * trace_frame.h - rebuilt IPv4 frames for IMSI-trace PACKET lines.
 *
 * The kernel owns IP, UDP and SCTP, so the IWF never sees those headers.
 * These helpers rebuild them around the bytes the IWF did see:
 *
 *   GTP-C        IPv4 / UDP / GTP
 *   MAP, ISUP    IPv4 / SCTP DATA (PPID 3) / M3UA DATA / SCCP or ISUP
 *
 * Addresses, ports, point codes, SIO, SLS, routing context and payload are
 * the real values. IP identification and TTL, the SCTP verification tag,
 * TSN and stream sequence number are not taken from the wire.
 */

#ifndef IWF_TRACE_FRAME_H
#define IWF_TRACE_FRAME_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t src_ip;     /* network byte order */
    uint32_t dst_ip;     /* network byte order */
    uint16_t src_port;   /* host byte order */
    uint16_t dst_port;   /* host byte order */
} iwf_trace_ep_t;

typedef struct {
    uint32_t opc;
    uint32_t dpc;
    uint8_t  sio;        /* MTP SIO as libosmo packs it: NI<<6 | MP<<4 | SI */
    uint8_t  sls;
    uint32_t rctx;       /* 0 = omit the Routing Context parameter */
} iwf_trace_mtp_t;

/* Each returns the frame length, or 0 if it does not fit in cap. */
size_t iwf_trace_frame_udp(const iwf_trace_ep_t *ep,
                           const uint8_t *payload, size_t len,
                           uint8_t *out, size_t cap);

/* *payload_off (may be NULL) receives the offset of payload inside out. */
size_t iwf_trace_frame_m3ua(const iwf_trace_ep_t *ep,
                            const iwf_trace_mtp_t *mtp,
                            const uint8_t *payload, size_t len,
                            uint8_t *out, size_t cap, size_t *payload_off);

uint32_t iwf_trace_crc32c(const uint8_t *p, size_t n);

#endif /* IWF_TRACE_FRAME_H */
