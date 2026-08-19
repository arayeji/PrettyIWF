/*
 * gtp_trace.c - GTPv1/v2-C IMSI trace with TEID/seq/context correlation.
 */

#include "gtp_trace.h"
#include "imsi_trace.h"
#include "gtpv1.h"
#include "gtpv2.h"
#include "session.h"
#include "translate.h"
#include "iwf.h"

#include <stdio.h>

#include <string.h>

static int imsi_from_v1_ies(const iwf_msg_t *msg, char *imsi, size_t cap)
{
    for (size_t i = 0; i < msg->n_ies; i++) {
        if (msg->ies[i].type != GTPV1_IE_IMSI)
            continue;
        if (gtpv1_decode_imsi(&msg->ies[i], imsi, cap) == 0 && imsi[0])
            return 0;
    }
    return -1;
}

static int imsi_from_v2_ies(const iwf_msg_t *msg, char *imsi, size_t cap)
{
    for (size_t i = 0; i < msg->n_ies; i++) {
        if (msg->ies[i].type != GTPV2_IE_IMSI)
            continue;
        if (gtpv2_decode_imsi(&msg->ies[i], imsi, cap) == 0 && imsi[0])
            return 0;
    }
    return -1;
}

static int imsi_from_sess_ctrl_teid(uint32_t teid, char *imsi, size_t cap)
{
    sess_t *s;

    if (!teid)
        return -1;
    s = sess_find_by_iwf_ctrl_teid(teid);
    if (!s)
        return -1;
    snprintf(imsi, cap, "%s", s->key.imsi);
    return imsi[0] ? 0 : -1;
}

static int imsi_from_sess_s4_teid(uint32_t teid, char *imsi, size_t cap)
{
    sess_t *s;

    if (!teid)
        return -1;
    s = sess_find_by_iwf_s4_c_teid(teid);
    if (!s)
        return -1;
    snprintf(imsi, cap, "%s", s->key.imsi);
    return imsi[0] ? 0 : -1;
}

static int imsi_from_pending_v2_seq(uint32_t seq24, char *imsi, size_t cap)
{
    sess_t *s;

    if (!seq24)
        return -1;
    s = sess_find_by_pending_v2_seq_any(seq24);
    if (!s)
        return -1;
    snprintf(imsi, cap, "%s", s->key.imsi);
    return imsi[0] ? 0 : -1;
}

static int resolve_imsi_v1(const iwf_msg_t *msg, char *imsi, size_t cap)
{
    if (!msg || !imsi || cap == 0)
        return -1;
    imsi[0] = '\0';

    if (imsi_from_v1_ies(msg, imsi, cap) == 0)
        return 0;
    if (translate_ctx_trace_imsi_by_gn_seq((uint16_t)msg->seq, imsi, cap) == 0)
        return 0;
    if (imsi_from_sess_ctrl_teid(msg->teid, imsi, cap) == 0)
        return 0;
    return -1;
}

static int resolve_imsi_v2(const iwf_msg_t *msg, char *imsi, size_t cap)
{
    if (!msg || !imsi || cap == 0)
        return -1;
    imsi[0] = '\0';

    if (imsi_from_v2_ies(msg, imsi, cap) == 0)
        return 0;
    if (translate_ctx_trace_imsi_by_v2_seq(msg->seq, imsi, cap) == 0)
        return 0;
    if (imsi_from_sess_s4_teid(msg->teid, imsi, cap) == 0)
        return 0;
    if (imsi_from_pending_v2_seq(msg->seq, imsi, cap) == 0)
        return 0;
    return -1;
}

static void trace_v1(const char *dir, const uint8_t *buf, size_t len,
                     const iwf_msg_t *msg_in)
{
    iwf_msg_t local;
    const iwf_msg_t *msg = msg_in;
    char imsi[IWF_IMSI_MAX];

    if (!buf || !len)
        return;

    if (!msg) {
        memset(&local, 0, sizeof(local));
        if (gtpv1_parse(buf, len, &local) < 0)
            return;
        msg = &local;
    }

    if (resolve_imsi_v1(msg, imsi, sizeof(imsi)) != 0)
        return;
    iwf_imsi_trace_packet(imsi, "gtp", dir, buf, len);
}

static void trace_v2(const char *dir, const uint8_t *buf, size_t len,
                     const iwf_msg_t *msg_in)
{
    iwf_msg_t local;
    const iwf_msg_t *msg = msg_in;
    char imsi[IWF_IMSI_MAX];

    if (!buf || !len)
        return;

    if (!msg) {
        memset(&local, 0, sizeof(local));
        if (gtpv2_parse(buf, len, &local) < 0)
            return;
        msg = &local;
    }

    if (resolve_imsi_v2(msg, imsi, sizeof(imsi)) != 0)
        return;
    iwf_imsi_trace_packet(imsi, "gtp", dir, buf, len);
}

void iwf_gtp_trace_rx_v1(const uint8_t *buf, size_t len, const iwf_msg_t *msg)
{
    trace_v1("rx", buf, len, msg);
}

void iwf_gtp_trace_rx_v2(const uint8_t *buf, size_t len, const iwf_msg_t *msg)
{
    trace_v2("rx", buf, len, msg);
}

void iwf_gtp_trace_tx_v1(const uint8_t *buf, size_t len)
{
    trace_v1("tx", buf, len, NULL);
}

void iwf_gtp_trace_tx_v2(const uint8_t *buf, size_t len)
{
    trace_v2("tx", buf, len, NULL);
}
