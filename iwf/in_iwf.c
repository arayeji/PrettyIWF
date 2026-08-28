/*
 * in_iwf.c — CAMEL CAP / INAP CS-1 / SIP-AS / none. One query per call.
 */

#include "in_iwf.h"
#include "isup_codec.h"
#include "sip_iwf.h"
#include "config.h"
#include "runtime.h"
#include "logging.h"
#include "tcap.h"
#include "map_codec.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <arpa/inet.h>

#define IN_PEND_MAX 32

/* CAP v2 gsmSSF-to-gsmSCF  0.4.0.0.1.0.50.1 */
static const uint8_t CAP_AC[]  = { 0x04, 0x00, 0x00, 0x01, 0x00, 0x32, 0x01 };
/* INAP CS-1 ssp-to-scp     0.4.0.1.1.1.1 */
static const uint8_t INAP_AC[] = { 0x04, 0x00, 0x01, 0x01, 0x01, 0x01 };

#define CAP_OP_INITIAL_DP   0
#define CAP_OP_CONNECT      20
#define CAP_OP_RELEASE_CALL 22
#define CAP_OP_CONTINUE      31

typedef struct {
    int             used;
    uint32_t        sip_id;
    uint32_t        otid;
    int             mode;
    in_iwf_cb_t     cb;
    void           *user;
    time_t          t0;
    char            sip_callid[80];
    char            called[32];
} in_pend_t;

static in_pend_t g_pend[IN_PEND_MAX];
static uint32_t  g_otid_seed = 0x494e0001;

int in_iwf_mode_from_str(const char *s)
{
    if (!s || !*s || !strcasecmp(s, "none") || !strcasecmp(s, "off"))
        return IWF_IN_NONE;
    if (!strcasecmp(s, "camel") || !strcasecmp(s, "cap") ||
        !strcasecmp(s, "cap2"))
        return IWF_IN_CAMEL;
    if (!strcasecmp(s, "inap") || !strcasecmp(s, "cs1"))
        return IWF_IN_INAP;
    if (!strcasecmp(s, "sip") || !strcasecmp(s, "sip_as") ||
        !strcasecmp(s, "sip-as"))
        return IWF_IN_SIP_AS;
    return -1;
}

const char *in_iwf_mode_name(int mode)
{
    switch (mode) {
    case IWF_IN_CAMEL:  return "camel";
    case IWF_IN_INAP:   return "inap";
    case IWF_IN_SIP_AS: return "sip_as";
    default:            return "none";
    }
}

int in_iwf_effective_mode(const struct iwf_runtime *rt, int route_override)
{
    if (route_override >= 0) return route_override;
    return rt ? rt->cfg.in_mode : IWF_IN_NONE;
}

static in_pend_t *pend_new(uint32_t sip_id, int mode, in_iwf_cb_t cb, void *user)
{
    for (int i = 0; i < IN_PEND_MAX; i++) {
        if (g_pend[i].used) continue;
        memset(&g_pend[i], 0, sizeof(g_pend[i]));
        g_pend[i].used = 1;
        g_pend[i].sip_id = sip_id;
        g_pend[i].mode = mode;
        g_pend[i].cb = cb;
        g_pend[i].user = user;
        g_pend[i].t0 = time(NULL);
        g_pend[i].otid = g_otid_seed++;
        if (!g_otid_seed) g_otid_seed = 1;
        return &g_pend[i];
    }
    return NULL;
}

static void pend_done(in_pend_t *p, int result, const char *dest)
{
    if (!p) return;
    in_iwf_cb_t cb = p->cb;
    void *user = p->user;
    uint32_t id = p->sip_id;
    memset(p, 0, sizeof(*p));
    if (cb) {
        LOGI("in", "id=%u result=%s dest=%s",
             id,
             result == IWF_IN_CONT ? "continue" :
             result == IWF_IN_CONNECT ? "connect" : "fail",
             dest && dest[0] ? dest : "-");
        cb(user, result, dest);
    }
}

static in_pend_t *pend_by_otid(uint32_t otid)
{
    for (int i = 0; i < IN_PEND_MAX; i++)
        if (g_pend[i].used && g_pend[i].otid == otid)
            return &g_pend[i];
    return NULL;
}

static in_pend_t *pend_by_sip(uint32_t sip_id)
{
    for (int i = 0; i < IN_PEND_MAX; i++)
        if (g_pend[i].used && g_pend[i].sip_id == sip_id)
            return &g_pend[i];
    return NULL;
}

static in_pend_t *pend_by_callid(const char *cid)
{
    if (!cid || !cid[0]) return NULL;
    for (int i = 0; i < IN_PEND_MAX; i++)
        if (g_pend[i].used && g_pend[i].sip_callid[0] &&
            !strcmp(g_pend[i].sip_callid, cid))
            return &g_pend[i];
    return NULL;
}

static int enc_idp(uint8_t *out, size_t cap,
                   const char *called, const char *calling)
{
    uint8_t inner[256];
    size_t io = 0;
    uint8_t sk[4];
    size_t so = 0;
    if (ber_enc_integer_u32(sk, sizeof(sk), &so, 0x02, 0) < 0)
        return -1;
    /* serviceKey [0] IMPLICIT INTEGER — put INTEGER value without tag wrap
     * as primitive [0]: 0x80 + length + integer bytes (skip INTEGER tag). */
    if (so >= 2) {
        if (ber_enc_tlv(inner, sizeof(inner), &io, 0x80,
                        sk + so - 1, 1) < 0)
            return -1;
    }
    isup_number_t cd, cg;
    isup_number_from_digits(&cd, called, ISUP_NAI_INTERNATIONAL, 0);
    isup_number_from_digits(&cg, calling, ISUP_NAI_INTERNATIONAL, 0);
    uint8_t nb[40];
    int nl = isup_enc_number(nb, sizeof(nb), &cd, 0);
    if (nl > 0 && ber_enc_tlv(inner, sizeof(inner), &io, 0x82,
                               nb, (size_t)nl) < 0)
        return -1;
    nl = isup_enc_number(nb, sizeof(nb), &cg, 1);
    if (nl > 0 && ber_enc_tlv(inner, sizeof(inner), &io, 0x83,
                               nb, (size_t)nl) < 0)
        return -1;
    uint8_t ev = 12; /* termAttemptAuthorized */
    if (ber_enc_tlv(inner, sizeof(inner), &io, 0x88, &ev, 1) < 0)
        return -1;
    size_t off = 0;
    if (ber_enc_tlv(out, cap, &off, 0x30, inner, io) < 0)
        return -1;
    return (int)off;
}

static int send_idp(struct iwf_runtime *rt, in_pend_t *p,
                    const char *called, const char *calling)
{
    if (!rt->cfg.in_scp_gt[0]) {
        LOGW("in", "id=%u mode=%s but [in] scp_gt unset",
             p->sip_id, in_iwf_mode_name(p->mode));
        return -1;
    }
    uint8_t params[256];
    int pl = enc_idp(params, sizeof(params), called, calling);
    if (pl < 0) return -1;
    uint8_t cmp[512];
    size_t co = 0;
    if (tcap_enc_invoke(cmp, sizeof(cmp), &co, 1, CAP_OP_INITIAL_DP,
                        params, (size_t)pl) < 0)
        return -1;
    uint8_t dlg[160];
    const uint8_t *oid = (p->mode == IWF_IN_INAP) ? INAP_AC : CAP_AC;
    size_t oid_len = (p->mode == IWF_IN_INAP) ? sizeof(INAP_AC)
                                              : sizeof(CAP_AC);
    int dn = map_encode_aarq_oid(oid, oid_len, dlg, sizeof(dlg));
    if (dn < 0) return -1;
    uint8_t tcap[1024];
    int n = tcap_encode_message(TCAP_MSG_BEGIN, p->otid, true, 0, false,
                               dlg, (size_t)dn, cmp, co, tcap, sizeof(tcap));
    if (n < 0) return -1;

    uint8_t ssn = rt->cfg.in_scp_ssn;
    if (!ssn)
        ssn = (p->mode == IWF_IN_INAP) ? 12 : 146;
    ss7_sccp_addr_t called_a, calling_a;
    ss7_gt_from_digits(rt->cfg.in_scp_gt, ssn, &called_a);
    ss7_link_make_local_addr(rt, &calling_a);
    calling_a.ssn = SS7_SSN_MSC;
    if (ss7_link_send_tcap_ex(rt, &called_a, &calling_a,
                               tcap, (size_t)n) < 0)
        return -1;
    LOGI("in", "id=%u TX InitialDP mode=%s scp=%s ssn=%u otid=%u called=%s",
         p->sip_id, in_iwf_mode_name(p->mode), rt->cfg.in_scp_gt,
         (unsigned)ssn, p->otid, called ? called : "-");
    return 0;
}

static int send_sip_as(struct iwf_runtime *rt, in_pend_t *p,
                        const char *called)
{
    if (!rt->cfg.in_sip_as[0]) {
        LOGW("in", "id=%u mode=sip_as but [in] sip_as unset", p->sip_id);
        return -1;
    }
    struct sockaddr_in to;
    if (sip_iwf_parse_peer(rt->cfg.in_sip_as, &to) < 0) {
        LOGW("in", "id=%u [in] sip_as unparseable", p->sip_id);
        return -1;
    }
    char host[32];
    inet_ntop(AF_INET, &to.sin_addr, host, sizeof(host));
    uint16_t port = ntohs(to.sin_port);
    snprintf(p->sip_callid, sizeof(p->sip_callid), "in%u@iwf", p->sip_id);
    char dst[32];
    snprintf(dst, sizeof(dst), "%s", called ? called : "unknown");
    char msg[1024];
    int n = snprintf(msg, sizeof(msg),
        "INVITE sip:%s@%s:%u SIP/2.0\r\n"
        "Via: SIP/2.0/UDP iwf;branch=z9hG4bKin%u;rport\r\n"
        "From: <sip:iwf@localhost>;tag=in%u\r\n"
        "To: <sip:%s@%s:%u>\r\n"
        "Call-ID: %s\r\n"
        "CSeq: 1 INVITE\r\n"
        "Max-Forwards: 70\r\n"
        "User-Agent: PrettyIWF\r\n"
        "Content-Length: 0\r\n"
        "\r\n",
        dst, host, (unsigned)port,
        p->sip_id, p->sip_id, dst, host, (unsigned)port,
        p->sip_callid);
    if (n < 0 || sip_iwf_send_raw(&to, msg, (size_t)n) < 0)
        return -1;
    LOGI("in", "id=%u TX INVITE sip_as=%s callid=%s",
         p->sip_id, rt->cfg.in_sip_as, p->sip_callid);
    return 0;
}

int in_iwf_query(struct iwf_runtime *rt, uint32_t sip_id,
                   const char *called, const char *calling,
                   int mode_override, in_iwf_cb_t cb, void *user)
{
    int mode = in_iwf_effective_mode(rt, mode_override);
    if (mode == IWF_IN_NONE) {
        if (cb) cb(user, IWF_IN_CONT, NULL);
        return 0;
    }
    if (!rt) {
        if (cb) cb(user, IWF_IN_FAIL, NULL);
        return -1;
    }
    in_pend_t *p = pend_new(sip_id, mode, cb, user);
    if (!p) {
        LOGW("in", "id=%u no IN slot", sip_id);
        if (cb) cb(user, IWF_IN_FAIL, NULL);
        return -1;
    }
    snprintf(p->called, sizeof(p->called), "%s", called ? called : "");
    int rc = -1;
    if (mode == IWF_IN_SIP_AS)
        rc = send_sip_as(rt, p, called);
    else
        rc = send_idp(rt, p, called, calling);
    if (rc < 0) {
        pend_done(p, IWF_IN_FAIL, NULL);
        return -1;
    }
    return 0;
}

static void extract_connect_dest(const tcap_msg_t *tmsg, char *out, size_t cap)
{
    if (out && cap) out[0] = '\0';
    if (!tmsg) return;
    for (size_t i = 0; i < tmsg->n_components; i++) {
        const tcap_component_t *c = &tmsg->components[i];
        if (c->kind != TCAP_CMP_KIND_INVOKE) continue;
        if (c->opcode != CAP_OP_CONNECT) continue;
        if (!c->parameters || c->parameters_len < 4) continue;
        /* Scan for called party number [0] / ISUP digits. */
        const uint8_t *p = c->parameters;
        size_t n = c->parameters_len;
        for (size_t off = 0; off + 4 < n; off++) {
            if (p[off] == 0x80 || p[off] == 0x04 || p[off] == 0x82) {
                size_t ln = p[off + 1];
                if (off + 2 + ln > n || ln < 2) continue;
                isup_number_t num;
                if (isup_dec_number(p + off + 2, ln, &num, 0) == 0 &&
                    num.digits[0] && out && cap) {
                    snprintf(out, cap, "%s", num.digits);
                    return;
                }
            }
        }
    }
}

int in_iwf_on_tcap(struct iwf_runtime *rt, const ss7_sccp_addr_t *calling,
                    const tcap_msg_t *tmsg)
{
    (void)rt;
    (void)calling;
    if (!tmsg) return 0;
    uint32_t tid = 0;
    if (tmsg->have_dtid) tid = tmsg->dtid;
    else if (tmsg->have_otid) tid = tmsg->otid;
    in_pend_t *p = pend_by_otid(tid);
    if (!p && tmsg->have_otid)
        p = pend_by_otid(tmsg->otid);
    if (!p) return 0;

    int result = IWF_IN_FAIL;
    char dest[32] = "";
    int op = -1;
    for (size_t i = 0; i < tmsg->n_components; i++) {
        const tcap_component_t *c = &tmsg->components[i];
        if (c->kind == TCAP_CMP_KIND_ERR || c->kind == TCAP_CMP_KIND_REJECT) {
            result = IWF_IN_FAIL;
            op = c->error_code;
            break;
        }
        if (c->kind != TCAP_CMP_KIND_INVOKE) continue;
        op = c->opcode;
        if (c->opcode == CAP_OP_CONTINUE) {
            result = IWF_IN_CONT;
            break;
        }
        if (c->opcode == CAP_OP_CONNECT) {
            extract_connect_dest(tmsg, dest, sizeof(dest));
            result = dest[0] ? IWF_IN_CONNECT : IWF_IN_CONT;
            break;
        }
        if (c->opcode == CAP_OP_RELEASE_CALL) {
            result = IWF_IN_FAIL;
            break;
        }
    }
    LOGI("in", "id=%u RX TCAP op=%d result=%d dest=%s",
         p->sip_id, op, result, dest[0] ? dest : "-");
    pend_done(p, result, dest[0] ? dest : NULL);
    return 1;
}

int in_iwf_on_sip(const char *callid, int status, const char *contact)
{
    in_pend_t *p = pend_by_callid(callid);
    if (!p) return 0;
    char dest[32] = "";
    int result = IWF_IN_FAIL;
    if (status >= 200 && status < 300)
        result = IWF_IN_CONT;
    else if (status >= 300 && status < 400) {
        if (contact && contact[0]) {
            const char *s = contact;
            if (!strncmp(s, "sip:", 4)) s += 4;
            size_t n = 0;
            for (; *s && *s != '@' && *s != '>' && *s != ';' && n + 1 < sizeof(dest); s++) {
                if (*s == '+' || (*s >= '0' && *s <= '9'))
                    dest[n++] = *s;
            }
            dest[n] = '\0';
        }
        result = dest[0] ? IWF_IN_CONNECT : IWF_IN_CONT;
    } else if (status >= 180 && status < 200) {
        return 1; /* wait for final */
    }
    LOGI("in", "id=%u RX SIP %d dest=%s", p->sip_id, status,
         dest[0] ? dest : "-");
    pend_done(p, result, dest[0] ? dest : NULL);
    return 1;
}

void in_iwf_on_timer(struct iwf_runtime *rt)
{
    if (!rt) return;
    int tmo = rt->cfg.in_timeout_ms > 0 ? (rt->cfg.in_timeout_ms + 999) / 1000
                                          : 5;
    if (tmo < 1) tmo = 5;
    time_t now = time(NULL);
    for (int i = 0; i < IN_PEND_MAX; i++) {
        if (!g_pend[i].used) continue;
        if (now - g_pend[i].t0 < tmo) continue;
        LOGW("in", "id=%u IN timeout (one attempt, fail)", g_pend[i].sip_id);
        pend_done(&g_pend[i], IWF_IN_FAIL, NULL);
    }
}

void in_iwf_cancel(uint32_t sip_id)
{
    in_pend_t *p = pend_by_sip(sip_id);
    if (!p) return;
    p->cb = NULL;
    memset(p, 0, sizeof(*p));
}
