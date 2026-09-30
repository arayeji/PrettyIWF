/*
 * trace_frame.c - rebuilt IPv4/UDP and IPv4/SCTP/M3UA frames for PACKET logs.
 */

#include "trace_frame.h"

#include <string.h>

#define IPV4_HDR_LEN      20
#define UDP_HDR_LEN       8
#define SCTP_COMMON_LEN   12
#define SCTP_DATA_HDR_LEN 16
#define M3UA_HDR_LEN      8
#define M3UA_RCTX_LEN     8
#define M3UA_PDATA_HDR    16   /* tag, length, OPC, DPC, SI, NI, MP, SLS */

#define IPPROTO_UDP_NUM   17
#define IPPROTO_SCTP_NUM  132
#define M3UA_PPID_NUM     3
#define M3UA_STREAM_DATA  1    /* libosmo sends M3UA DATA on stream 1 */

static uint16_t g_ip_id;
static uint32_t g_sctp_tsn = 1;
static uint16_t g_sctp_ssn;

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t sum16(uint32_t acc, const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i + 1 < n; i += 2)
        acc += (uint32_t)((p[i] << 8) | p[i + 1]);
    if (n & 1)
        acc += (uint32_t)(p[n - 1] << 8);
    return acc;
}

static uint16_t fold16(uint32_t acc)
{
    while (acc >> 16)
        acc = (acc & 0xffff) + (acc >> 16);
    return (uint16_t)~acc;
}

static void put_ipv4(uint8_t *ip, size_t total, uint8_t proto,
                     uint32_t src_be, uint32_t dst_be)
{
    memset(ip, 0, IPV4_HDR_LEN);
    ip[0] = 0x45;
    put16(ip + 2, (uint16_t)total);
    put16(ip + 4, ++g_ip_id);
    put16(ip + 6, 0x4000);                   /* DF */
    ip[8] = 64;
    ip[9] = proto;
    memcpy(ip + 12, &src_be, 4);
    memcpy(ip + 16, &dst_be, 4);
    put16(ip + 10, fold16(sum16(0, ip, IPV4_HDR_LEN)));
}

uint32_t iwf_trace_crc32c(const uint8_t *p, size_t n)
{
    static uint32_t tab[256];
    static int ready;
    uint32_t crc = 0xffffffffu;
    size_t i;

    if (!ready) {
        for (uint32_t b = 0; b < 256; b++) {
            uint32_t c = b;
            for (int k = 0; k < 8; k++)
                c = (c & 1) ? (c >> 1) ^ 0x82f63b78u : c >> 1;
            tab[b] = c;
        }
        ready = 1;
    }
    for (i = 0; i < n; i++)
        crc = tab[(crc ^ p[i]) & 0xff] ^ (crc >> 8);
    return ~crc;
}

size_t iwf_trace_frame_udp(const iwf_trace_ep_t *ep,
                           const uint8_t *payload, size_t len,
                           uint8_t *out, size_t cap)
{
    size_t total = IPV4_HDR_LEN + UDP_HDR_LEN + len;
    uint8_t *udp;
    uint8_t pseudo[12];
    uint32_t acc;
    uint16_t ck;

    if (!ep || !out || (!payload && len) || total > cap || total > 0xffff)
        return 0;

    put_ipv4(out, total, IPPROTO_UDP_NUM, ep->src_ip, ep->dst_ip);
    udp = out + IPV4_HDR_LEN;
    put16(udp, ep->src_port);
    put16(udp + 2, ep->dst_port);
    put16(udp + 4, (uint16_t)(UDP_HDR_LEN + len));
    put16(udp + 6, 0);
    if (len)
        memcpy(udp + UDP_HDR_LEN, payload, len);

    memcpy(pseudo, &ep->src_ip, 4);
    memcpy(pseudo + 4, &ep->dst_ip, 4);
    pseudo[8] = 0;
    pseudo[9] = IPPROTO_UDP_NUM;
    put16(pseudo + 10, (uint16_t)(UDP_HDR_LEN + len));
    acc = sum16(0, pseudo, sizeof(pseudo));
    acc = sum16(acc, udp, UDP_HDR_LEN + len);
    ck = fold16(acc);
    put16(udp + 6, ck ? ck : 0xffff);
    return total;
}

size_t iwf_trace_frame_m3ua(const iwf_trace_ep_t *ep,
                            const iwf_trace_mtp_t *mtp,
                            const uint8_t *payload, size_t len,
                            uint8_t *out, size_t cap, size_t *payload_off)
{
    size_t pdata_len = M3UA_PDATA_HDR + len;
    size_t pad = (4 - (pdata_len & 3)) & 3;
    size_t m3ua_len = M3UA_HDR_LEN + (mtp && mtp->rctx ? M3UA_RCTX_LEN : 0)
                      + pdata_len + pad;
    size_t chunk_len = SCTP_DATA_HDR_LEN + m3ua_len;
    size_t sctp_len = SCTP_COMMON_LEN + chunk_len;
    size_t total = IPV4_HDR_LEN + sctp_len;
    uint8_t *sctp, *chunk, *m, *pd;
    uint32_t crc;

    if (!ep || !mtp || !out || (!payload && len) ||
        total > cap || total > 0xffff || pdata_len > 0xffff)
        return 0;

    put_ipv4(out, total, IPPROTO_SCTP_NUM, ep->src_ip, ep->dst_ip);

    sctp = out + IPV4_HDR_LEN;
    put16(sctp, ep->src_port);
    put16(sctp + 2, ep->dst_port);
    put32(sctp + 4, 0);                      /* verification tag */
    put32(sctp + 8, 0);                      /* checksum, filled below */

    chunk = sctp + SCTP_COMMON_LEN;
    chunk[0] = 0;                            /* DATA */
    chunk[1] = 0x03;                         /* B + E: unfragmented */
    put16(chunk + 2, (uint16_t)chunk_len);
    put32(chunk + 4, g_sctp_tsn++);
    put16(chunk + 8, M3UA_STREAM_DATA);
    put16(chunk + 10, g_sctp_ssn++);
    put32(chunk + 12, M3UA_PPID_NUM);

    m = chunk + SCTP_DATA_HDR_LEN;
    m[0] = 1;                                /* version */
    m[1] = 0;
    m[2] = 1;                                /* class: transfer */
    m[3] = 1;                                /* type: DATA */
    put32(m + 4, (uint32_t)m3ua_len);
    pd = m + M3UA_HDR_LEN;
    if (mtp->rctx) {
        put16(pd, 0x0006);
        put16(pd + 2, M3UA_RCTX_LEN);
        put32(pd + 4, mtp->rctx);
        pd += M3UA_RCTX_LEN;
    }
    put16(pd, 0x0210);
    put16(pd + 2, (uint16_t)pdata_len);
    put32(pd + 4, mtp->opc);
    put32(pd + 8, mtp->dpc);
    pd[12] = (uint8_t)(mtp->sio & 0x0f);
    pd[13] = (uint8_t)((mtp->sio >> 6) & 0x03);
    pd[14] = (uint8_t)((mtp->sio >> 4) & 0x03);
    pd[15] = mtp->sls;
    if (len)
        memcpy(pd + M3UA_PDATA_HDR, payload, len);
    if (pad)
        memset(pd + M3UA_PDATA_HDR + len, 0, pad);
    if (payload_off)
        *payload_off = (size_t)(pd + M3UA_PDATA_HDR - out);

    /* RFC 4960 appendix B: CRC32c stored least significant byte first. */
    crc = iwf_trace_crc32c(sctp, sctp_len);
    sctp[8]  = (uint8_t)crc;
    sctp[9]  = (uint8_t)(crc >> 8);
    sctp[10] = (uint8_t)(crc >> 16);
    sctp[11] = (uint8_t)(crc >> 24);
    return total;
}
