/*
 * isup_codec_test.c — Q.763 round-trip and number-encoding edge cases.
 * Build: make -C iwf test-isup
 */

#include "isup_codec.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int g_fail;

static void expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        g_fail++;
    }
}

static void test_cic(void)
{
    uint8_t b[2];
    isup_put_cic(b, 1);
    expect(b[0] == 0x01 && b[1] == 0x00, "CIC 1 encoding");
    expect(isup_get_cic(b) == 1, "CIC 1 decode");
    isup_put_cic(b, 0x0abc);
    expect(isup_get_cic(b) == 0x0abc, "CIC 12-bit roundtrip");
}

static void test_number_even_odd(void)
{
    isup_number_t n, d;
    uint8_t buf[40];

    isup_number_from_digits(&n, "989350186565", ISUP_NAI_INTERNATIONAL, 0);
    expect(n.odd == 0, "even digit count");
    int l = isup_enc_number(buf, sizeof(buf), &n, 0);
    expect(l > 2, "enc even number");
    expect((buf[0] & 0x80) == 0, "even indicator bit clear");
    expect((buf[0] & 0x7f) == ISUP_NAI_INTERNATIONAL, "NAI international");
    expect(isup_dec_number(buf, (size_t)l, &d, 0) == 0, "dec even");
    expect(!strcmp(d.digits, "989350186565"), "even digits roundtrip");

    isup_number_from_digits(&n, "98935018656", ISUP_NAI_NATIONAL, 0);
    expect(n.odd == 1, "odd digit count");
    l = isup_enc_number(buf, sizeof(buf), &n, 0);
    expect(l > 2, "enc odd number");
    expect((buf[0] & 0x80) != 0, "odd indicator bit set");
    expect((buf[0] & 0x7f) == ISUP_NAI_NATIONAL, "NAI national");
    expect(isup_dec_number(buf, (size_t)l, &d, 0) == 0, "dec odd");
    expect(!strcmp(d.digits, "98935018656"), "odd digits roundtrip");
}

static void test_pres_restricted(void)
{
    isup_number_t n, d;
    uint8_t buf[40];
    isup_number_from_digits(&n, "98211234567", ISUP_NAI_INTERNATIONAL, 1);
    expect(n.presentation == ISUP_PRES_RESTRICTED, "pres restricted flag");
    int l = isup_enc_number(buf, sizeof(buf), &n, 1);
    expect(l > 2, "enc calling");
    expect(isup_dec_number(buf, (size_t)l, &d, 1) == 0, "dec calling");
    expect(d.presentation == ISUP_PRES_RESTRICTED, "pres restricted roundtrip");
    expect(!strcmp(d.digits, "98211234567"), "calling digits");

    isup_number_from_digits(&n, "21", ISUP_NAI_SUBSCRIBER, 0);
    l = isup_enc_number(buf, sizeof(buf), &n, 1);
    expect(isup_dec_number(buf, (size_t)l, &d, 1) == 0, "dec subscriber");
    expect(d.nai == ISUP_NAI_SUBSCRIBER, "NAI subscriber");
    expect(d.presentation == ISUP_PRES_ALLOWED, "pres allowed");
}

static void test_iam_roundtrip(void)
{
    isup_number_t cd, cg;
    isup_number_from_digits(&cd, "989350186565", ISUP_NAI_INTERNATIONAL, 0);
    isup_number_from_digits(&cg, "98210000001", ISUP_NAI_INTERNATIONAL, 0);
    uint8_t msu[512];
    int n = isup_enc_iam(msu, sizeof(msu), 7, &cd, &cg, "10.0.0.1", 40000);
    expect(n > 10, "IAM encode");
    isup_msg_t m;
    expect(isup_decode(msu, (size_t)n, &m) == 0, "IAM decode");
    expect(m.type == ISUP_MT_IAM, "IAM type");
    expect(m.cic == 7, "IAM CIC");
    expect(m.have_called, "IAM called present");
    expect(!strcmp(m.called.digits, "989350186565"), "IAM called digits");
    expect(m.have_calling, "IAM calling present");
    expect(!strcmp(m.calling.digits, "98210000001"), "IAM calling digits");
    expect(m.have_ipbcp, "IAM IPBCP present");
    expect(!strcmp(m.ipbcp_ip, "10.0.0.1"), "IAM RTP IP");
    expect(m.ipbcp_port == 40000, "IAM RTP port");
}

static void test_rel_cause(void)
{
    uint8_t msu[64];
    int n = isup_enc_rel(msu, sizeof(msu), 3, 17);
    expect(n > 5, "REL encode");
    isup_msg_t m;
    expect(isup_decode(msu, (size_t)n, &m) == 0, "REL decode");
    expect(m.type == ISUP_MT_REL, "REL type");
    expect(m.have_cause, "REL cause present");
    expect(m.cause == 17, "REL cause 17");
    expect(isup_cause_to_sip(16) == 200, "cause 16 -> 200");
    expect(isup_cause_to_sip(17) == 486, "cause 17 -> 486");
    expect(isup_cause_to_sip(18) == 480, "cause 18 -> 480");
    expect(isup_cause_to_sip(19) == 480, "cause 19 -> 480");
    expect(isup_cause_to_sip(34) == 503, "cause 34 -> 503");
    expect(isup_cause_to_sip(1) == 404, "cause 1 -> 404");
}

static void test_empty_msgs(void)
{
    uint8_t msu[16];
    isup_msg_t m;
    int n = isup_enc_acm(msu, sizeof(msu), 4, 0x0004);
    expect(n > 3 && isup_decode(msu, (size_t)n, &m) == 0 && m.type == ISUP_MT_ACM,
           "ACM");
    n = isup_enc_anm(msu, sizeof(msu), 4);
    expect(n == 3 && isup_decode(msu, (size_t)n, &m) == 0 && m.type == ISUP_MT_ANM,
           "ANM");
    n = isup_enc_rlc(msu, sizeof(msu), 4);
    expect(n == 3 && isup_decode(msu, (size_t)n, &m) == 0 && m.type == ISUP_MT_RLC,
           "RLC");
    n = isup_enc_blo(msu, sizeof(msu), 4);
    expect(isup_decode(msu, (size_t)n, &m) == 0 && m.type == ISUP_MT_BLO, "BLO");
    n = isup_enc_cpg(msu, sizeof(msu), 4, 0x01);
    expect(isup_decode(msu, (size_t)n, &m) == 0 && m.type == ISUP_MT_CPG, "CPG");
}

static void test_hand_built_iam(void)
{
    /* CIC=1, IAM, NCI=0, FCI=0x20 0x01, CPC=0x0A, TMR=0, called 123 (odd, NAI=4). */
    uint8_t msu[] = {
        0x01, 0x00,             /* CIC 1 */
        0x01,                   /* IAM */
        0x00,                   /* NCI */
        0x20, 0x01,             /* FCI */
        0x0A,                   /* CPC */
        0x00,                   /* TMR speech */
        0x02,                   /* ptr called */
        0x00,                   /* no optional */
        0x04,                   /* called len */
        0x84,                   /* odd | NAI=4 */
        0x80 | (1 << 4),        /* INN + E.164 */
        0x21, 0xF3              /* digits 1,2,3 + filler */
    };
    isup_msg_t m;
    expect(isup_decode(msu, sizeof(msu), &m) == 0, "hand-built IAM decode");
    expect(m.cic == 1, "hand CIC");
    expect(m.have_called, "hand called");
    expect(!strcmp(m.called.digits, "123"), "hand called 123");
    expect(m.called.odd == 1, "hand odd");
    expect(m.called.nai == 4, "hand NAI");
}

int main(void)
{
    test_cic();
    test_number_even_odd();
    test_pres_restricted();
    test_iam_roundtrip();
    test_rel_cause();
    test_empty_msgs();
    test_hand_built_iam();
    if (g_fail) {
        fprintf(stderr, "%d test(s) failed\n", g_fail);
        return 1;
    }
    printf("isup_codec_test: all passed\n");
    return 0;
}
