/*
 * isup_codec.h — ITU-T Q.763 ISUP / Q.1901 BICC message codec.
 *
 * BICC reuses ISUP parameter encoding. MTP SI is chosen at send time
 * (SI=5 ISUP or SI=13 BICC); this codec is SI-agnostic.
 *
 * Number digits use the same TBCD packing as map_str_to_bcd (low nibble
 * first, 0xF filler on odd length). The number header adds odd/even, NAI,
 * numbering plan, and (for calling) presentation/screening.
 */

#ifndef IWF_ISUP_CODEC_H
#define IWF_ISUP_CODEC_H

#include <stdint.h>
#include <stddef.h>

/* Q.763 message types (minimum viable + circuit supervision). */
#define ISUP_MT_IAM     0x01
#define ISUP_MT_ANM     0x09
#define ISUP_MT_REL     0x0C
#define ISUP_MT_RLC     0x10
#define ISUP_MT_RSC     0x12
#define ISUP_MT_BLO     0x13
#define ISUP_MT_UBL     0x14
#define ISUP_MT_BLA     0x15
#define ISUP_MT_UBA     0x16
#define ISUP_MT_GRS     0x17
#define ISUP_MT_CGB     0x18
#define ISUP_MT_GRA     0x19
#define ISUP_MT_CGU     0x1A
#define ISUP_MT_CGBA    0x1B
#define ISUP_MT_CGUA    0x1C
#define ISUP_MT_ACM     0x06
#define ISUP_MT_CPG     0x2C
#define ISUP_MT_APM     0x41

/* Optional parameter names (Q.763). */
#define ISUP_P_CALLING_PARTY_NUM    0x0A
#define ISUP_P_BACKWARD_CALL_IND    0x11
#define ISUP_P_CAUSE_INDICATORS     0x12
#define ISUP_P_RANGE_AND_STATUS    0x16
#define ISUP_P_EVENT_INFO          0x24
#define ISUP_P_APP_TRANSPORT       0x78

/* Nature of address (Q.763 3.9 / 3.10). */
#define ISUP_NAI_SUBSCRIBER     1
#define ISUP_NAI_NATIONAL        3
#define ISUP_NAI_INTERNATIONAL  4

#define ISUP_NPI_ISDN           1

/* Presentation (calling party number). */
#define ISUP_PRES_ALLOWED        0
#define ISUP_PRES_RESTRICTED   1
#define ISUP_PRES_NOT_AVAILABLE 2

#define ISUP_SCREEN_USER_PROVIDED_PASSED  1
#define ISUP_SCREEN_NETWORK_PROVIDED      3

#define ISUP_NUM_DIGITS_MAX 32
#define ISUP_MSU_MAX        512
#define ISUP_IPBCP_MAX      256

typedef struct {
    uint8_t  nai;
    uint8_t  npi;
    uint8_t  inn;               /* 1 = internal network number not allowed */
    uint8_t  presentation;      /* calling only */
    uint8_t  screening;          /* calling only */
    char     digits[ISUP_NUM_DIGITS_MAX];
    int      odd;               /* 1 = odd digit count */
} isup_number_t;

typedef struct {
    uint16_t        cic;
    uint8_t         type;
    uint8_t         nci;                /* nature of connection */
    uint16_t        fci;               /* forward call indicators */
    uint8_t         cpc;               /* calling party category */
    uint8_t         tmr;               /* transmission medium requirement */
    uint16_t        bci;               /* backward call indicators */
    uint8_t         event_info;
    uint8_t         cause;              /* Q.850 cause value */
    uint8_t         cause_location;
    int             have_called;
    int             have_calling;
    int             have_cause;
    int             have_bci;
    int             have_range;
    uint8_t         range;              /* GRS/CGB: number of additional CICs */
    isup_number_t   called;
    isup_number_t   calling;
    char            ipbcp_ip[64];
    uint16_t        ipbcp_port;
    int             have_ipbcp;
    uint8_t         raw[ISUP_MSU_MAX];
    size_t          raw_len;
} isup_msg_t;

const char *isup_msg_name(uint8_t type);

/* CIC: ITU 12-bit, octet 1 = bits 0-7, octet 2 low nibble = bits 8-11. */
void     isup_put_cic(uint8_t out[2], uint16_t cic);
uint16_t isup_get_cic(const uint8_t in[2]);

/* Number header + TBCD (same nibble order as map_str_to_bcd). */
int isup_enc_number(uint8_t *out, size_t cap, const isup_number_t *n,
                     int with_pres);
int isup_dec_number(const uint8_t *in, size_t len, isup_number_t *n,
                     int with_pres);

void isup_number_from_digits(isup_number_t *n, const char *digits,
                             uint8_t nai, int pres_restricted);

int isup_encode(const isup_msg_t *m, uint8_t *out, size_t cap);
int isup_decode(const uint8_t *in, size_t len, isup_msg_t *out);

/* Convenience builders. Return encoded length or -1. */
int isup_enc_iam(uint8_t *out, size_t cap, uint16_t cic,
                  const isup_number_t *called, const isup_number_t *calling,
                  const char *rtp_ip, uint16_t rtp_port);
int isup_enc_acm(uint8_t *out, size_t cap, uint16_t cic, uint16_t bci);
int isup_enc_cpg(uint8_t *out, size_t cap, uint16_t cic, uint8_t event);
int isup_enc_anm(uint8_t *out, size_t cap, uint16_t cic);
int isup_enc_rel(uint8_t *out, size_t cap, uint16_t cic, uint8_t cause);
int isup_enc_rlc(uint8_t *out, size_t cap, uint16_t cic);
int isup_enc_blo(uint8_t *out, size_t cap, uint16_t cic);
int isup_enc_bla(uint8_t *out, size_t cap, uint16_t cic);
int isup_enc_ubl(uint8_t *out, size_t cap, uint16_t cic);
int isup_enc_uba(uint8_t *out, size_t cap, uint16_t cic);
int isup_enc_rsc(uint8_t *out, size_t cap, uint16_t cic);
int isup_enc_grs(uint8_t *out, size_t cap, uint16_t cic, uint8_t range);
int isup_enc_gra(uint8_t *out, size_t cap, uint16_t cic, uint8_t range);
int isup_enc_empty(uint8_t *out, size_t cap, uint16_t cic, uint8_t type);

/* Q.850 cause -> SIP status (16 BYE/200, 17 486, 18/19 480, 34 503, 1 404). */
int isup_cause_to_sip(uint8_t cause);

/* IPBCP (Q.1970) inside APM Application Transport (ACI=2). */
int isup_enc_ipbcp(char *out, size_t cap, const char *ip, uint16_t port);
int isup_dec_ipbcp(const char *sdp, size_t len, char *ip, size_t ip_cap,
                   uint16_t *port);

#endif /* IWF_ISUP_CODEC_H */
