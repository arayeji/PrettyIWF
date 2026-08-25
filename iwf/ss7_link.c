/*
 * ss7_link.c - SS7 (M3UA/SCCP) connectivity via libosmo-sigtran.
 *
 * Build-time switch
 * -----------------
 *   make MAP_IWF_ENABLED=1   -> compile the real libosmo-sigtran path
 *   make                      -> compile the stub (init returns -1, module
 *                                stays disabled even if [map_iwf].enabled=1)
 *
 * Why a stub?
 *   - libosmo-sigtran is a substantial dependency.  CI containers and small
 *     dev boxes often don't have it.  Splitting the implementation keeps
 *     the GTP-only build (the original IWF use case) trivially portable.
 *   - The stub path still validates that the rest of MAP-IWF code paths
 *     compile and link cleanly on every host.
 *
 * The real path
 * -------------
 * libosmo-sigtran exposes an SCCP user API:
 *
 *   - osmo_ss7_init() once at process start
 *   - osmo_sccp_simple_client(..., default_pc, ...) creates SS7 instance #0 with
 *     that primary point code (M3UA RKM / STP routing keys match on this OPC).
 *     Args: ctx, name, default_pc, prot=M3UA, local_port, local_ip,
 *     remote_port, remote_ip — yields default ASP + SCCP instance.
 *   - osmo_sccp_user_bind(sccp, name, &prim_cb, ssn) yields an SCCP user
 *     that delivers SCCP primitives to prim_cb.
 *   - osmo_sccp_tx_unitdata_msg(sccp_user, calling_addr, called_addr, msgb)
 *     sends one N-UNITDATA.
 *
 * Indication delivery is via the libosmo event loop (osmo_select_main()).
 * To plug into our epoll loop we run osmo_select_main_ctx() in a small
 * helper thread.  The thread writes a 1-byte eventfd token whenever a
 * complete SCCP primitive has been queued; the main thread drains the
 * queue from its own epoll dispatch.  This keeps libosmo's pthread/talloc
 * usage off the GTP fast path.
 *
 * The full integration is dependency-heavy enough that we abstract it
 * behind ss7_link_impl_*() helpers that are no-ops in the stub build.
 */

#include "ss7_link.h"
#include "runtime.h"
#include "logging.h"
#include "map_iwf_priv.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>

#ifndef MAP_IWF_WITH_OSMO_SIGTRAN
#  define OSMO_SS7_PC_INVALID 0xffffffffu
#endif

#ifdef MAP_IWF_WITH_OSMO_SIGTRAN
#  include <osmocom/core/talloc.h>
#  include <osmocom/core/select.h>
#  include <osmocom/core/msgb.h>
#  include <osmocom/core/prim.h>
#  include <osmocom/sigtran/osmo_ss7.h>
#  include <osmocom/sigtran/mtp_sap.h>
#  include <osmocom/sigtran/sigtran_sap.h>
#  include <osmocom/sigtran/protocol/mtp.h>
#  include <osmocom/sigtran/sccp_sap.h>
#  include <osmocom/sigtran/sccp_helpers.h>
#  include <osmocom/sccp/sccp_types.h>
/* Exported by libosmo-sigtran; not always declared in public headers. */
int osmo_sccp_addr_encode(struct msgb *msg, const struct osmo_sccp_addr *in);
#endif

#ifdef MAP_IWF_WITH_OSMO_SIGTRAN
#define IWF_SIMPLE_CLIENT_AS_NAME  "as-clnt-iwf"
#endif

/* ====================================================================== */
/* Common helpers (built either way)                                      */
/* ====================================================================== */

/* Parses ITU dotted point code "a.b.c"; avoids sscanf (glibc __isoc23_* on
 * some mixed toolchain setups). Returns 1 on success with *a,*b,*c set. */
static int parse_pc_triplet(const char *pcs, unsigned *a,
                            unsigned *b, unsigned *c)
{
    unsigned x = 0, y = 0, z = 0;
    const char *p = pcs;
    if (!pcs || !a || !b || !c)
        return 0;
    while (*p >= '0' && *p <= '9')
        x = x * 10u + (unsigned)(*p++ - '0');
    if (*p != '.')
        return 0;
    p++;
    while (*p >= '0' && *p <= '9')
        y = y * 10u + (unsigned)(*p++ - '0');
    if (*p != '.')
        return 0;
    p++;
    while (*p >= '0' && *p <= '9')
        z = z * 10u + (unsigned)(*p++ - '0');
    if (*p != '\0')
        return 0;
    *a = x;
    *b = y;
    *c = z;
    return 1;
}

/* ITU 3-8-3 packing for dotted point code "a.b.c". */
static uint32_t pack_dotted_pc(const char *pcs)
{
    unsigned a = 0, b = 0, c = 0;
    if (!pcs || !pcs[0] || !parse_pc_triplet(pcs, &a, &b, &c))
        return OSMO_SS7_PC_INVALID;
    return ((a & 0x7u) << 11) | ((b & 0xffu) << 3) | (c & 0x7u);
}

static uint32_t pack_map_local_pc(const struct iwf_runtime *rt)
{
    return pack_dotted_pc(rt ? rt->cfg.map_local_pc : NULL);
}

void ss7_link_set_recv_cb(struct iwf_runtime *rt, ss7_recv_cb_t cb)
{
    if (!rt || !rt->map) return;
    rt->map->ss7.recv_cb = cb;
}

void ss7_gt_from_digits(const char *digits, uint8_t ssn, ss7_sccp_addr_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!digits || !out) return;
    out->ssn = ssn;
    /* libosmo osmo_sccp_gt.digits[] is a NUL-terminated ASCII digit string
     * (not packed TBCD). Copying TBCD here truncated GTs at embedded 0x00
     * (e.g. ...00... in 1234567890123) → wire digits like "0900"/"00". */
    size_t di = 0;
    for (size_t i = 0; digits[i] && di + 1 < sizeof(out->gt_digits); i++) {
        if (digits[i] < '0' || digits[i] > '9') continue;
        out->gt_digits[di++] = digits[i];
    }
    out->gt_digits[di] = '\0';
    out->have_gt = (di > 0);
}

void ss7_link_make_local_addr(const struct iwf_runtime *rt,
                              ss7_sccp_addr_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!rt) return;
    out->ssn = rt->cfg.map_local_ssn ? rt->cfg.map_local_ssn : SS7_SSN_SGSN;

    /* Point code: dotted "a.b.c" -> ITU 14-bit packed (3-8-3).  Anything
     * unparseable becomes 0; the STP usually has a configured route by GT
     * regardless. */
    const char *pcs = rt->cfg.map_local_pc;
    unsigned a = 0, b = 0, c = 0;
    if (pcs && parse_pc_triplet(pcs, &a, &b, &c))
        out->point_code =
            ((a & 0x7u) << 11) | ((b & 0xffu) << 3) | (c & 0x7u);

    if (rt->cfg.map_local_gt[0]) {
        ss7_sccp_addr_t tmp;
        ss7_gt_from_digits(rt->cfg.map_local_gt, out->ssn, &tmp);
        memcpy(out->gt_digits, tmp.gt_digits, sizeof(out->gt_digits));
        out->have_gt = tmp.have_gt;
    }
}

int ss7_link_get_fd(const struct iwf_runtime *rt)
{
    return rt && rt->map ? rt->map->ss7.fd : -1;
}

#ifdef MAP_IWF_WITH_OSMO_SIGTRAN
/* ss7_link_is_active() defined after ss7_impl_ctx below. */
#else
bool ss7_link_is_active(const struct iwf_runtime *rt)
{
    return rt && rt->map && rt->map->ss7.active;
}
#endif

#ifdef MAP_IWF_WITH_OSMO_SIGTRAN
/* ====================================================================== */
/* Real libosmo-sigtran implementation                                    */
/* ====================================================================== */

struct ss7_impl_ctx {
    void                  *tall_ctx;
    struct osmo_ss7_instance *ss7;
    struct osmo_sccp_instance *sccp;
    struct osmo_sccp_user *user;
    struct osmo_sccp_user *user_extra[4]; /* VLR/MSC/etc. same recv_cb */
    int                    n_user_extra;
#ifdef SMS_IWF_ENABLED
    struct osmo_sccp_user *user_hlr;
    ss7_recv_cb_t          recv_cb_hlr;
#endif
    int                    eventfd_to_main;       /* main thread polls this */
    uint32_t               local_pc;              /* packed [map_iwf] local_pc */
    uint32_t               stp_dpc;               /* packed [stp] remote_pc (MTP routes) */
    uint8_t                network_indicator;    /* [stp] network_indicator for MTP SIO */
    int                    sccp_ri;               /* IWF_SCCP_RI_GT or IWF_SCCP_RI_SSN */
};

bool ss7_link_is_active(const struct iwf_runtime *rt)
{
    if (!rt || !rt->map || !rt->map->ss7.active || !rt->map->ss7.opaque)
        return false;
    struct ss7_impl_ctx *ctx = rt->map->ss7.opaque;
    struct osmo_ss7_as *as =
        osmo_ss7_as_find_by_name(ctx->ss7, IWF_SIMPLE_CLIENT_AS_NAME);
    if (!as)
        as = osmo_ss7_as_find_by_proto(ctx->ss7, OSMO_SS7_ASP_PROT_M3UA);
    if (!as || !osmo_ss7_as_active(as))
        return false;
    struct osmo_ss7_asp *asp =
        osmo_ss7_asp_find_by_proto(as, OSMO_SS7_ASP_PROT_M3UA);
    return asp && osmo_ss7_asp_active(asp);
}

static void osmo_addr_to_ss7(const struct osmo_sccp_addr *in, ss7_sccp_addr_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!in || !out) return;
    out->ssn = in->ssn;
    out->point_code = in->pc;
    if (in->presence & OSMO_SCCP_ADDR_T_GT && in->gt.digits[0]) {
        strncpy(out->gt_digits, in->gt.digits, sizeof(out->gt_digits) - 1);
        out->gt_digits[sizeof(out->gt_digits) - 1] = '\0';
        out->have_gt = true;
    }
}

static void ss7_put_gt_in_osmo_addr(const ss7_sccp_addr_t *in, struct osmo_sccp_addr *out)
{
    out->presence |= OSMO_SCCP_ADDR_T_GT;
    out->gt.gti = OSMO_SCCP_GTI_TT_NPL_ENC_NAI;
    out->gt.tt  = 0;
    out->gt.npi = OSMO_SCCP_NPI_E164_ISDN;
    out->gt.nai = OSMO_SCCP_NAI_INTL;
    strncpy(out->gt.digits, in->gt_digits, sizeof(out->gt.digits) - 1);
    out->gt.digits[sizeof(out->gt.digits) - 1] = '\0';
}

static void ss7_to_osmo_addr(const ss7_sccp_addr_t *in, struct osmo_sccp_addr *out,
                             int sccp_ri)
{
    memset(out, 0, sizeof(*out));
    if (!in || !out) return;
    out->ssn = in->ssn;
    out->presence = OSMO_SCCP_ADDR_T_SSN;
    /* Always omit PC from SCCP addresses toward STP (PCI=0).  The STP
     * forwards with its own PC; embedding remote_pc in CdPA/CgPA is wrong.
     * M3UA DPC is set separately via MTP-TRANSFER (ss7_tx_unitdata_mtp). */
    out->pc = 0;
    if (in->have_gt) {
        ss7_put_gt_in_osmo_addr(in, out);
        out->ri = (sccp_ri == IWF_SCCP_RI_SSN) ? OSMO_SCCP_RI_SSN_PC
                                              : OSMO_SCCP_RI_GT;
    } else {
        out->ri = OSMO_SCCP_RI_SSN_PC;
    }
}

static void ss7_encode_outbound_called(const ss7_sccp_addr_t *in,
                                       struct osmo_sccp_addr *out,
                                       uint32_t stp_dpc,
                                       int sccp_ri)
{
    /* RI follows [map_iwf].sccp_ri (gt → RI=GT, ssn → RI=SSN).
     * Never put PC in CdPA (PCI=0) for either mode — STP replaces routing PC.
     * M3UA DPC=[stp] remote_pc is applied in ss7_tx_unitdata_mtp(), not here.
     * stp_dpc is unused for SCCP encoding; kept for call-site clarity. */
    (void)stp_dpc;
    ss7_to_osmo_addr(in, out, sccp_ri);
    out->pc = 0;
    out->presence &= ~OSMO_SCCP_ADDR_T_PC;
    if (in && in->have_gt) {
        out->presence |= OSMO_SCCP_ADDR_T_GT;
        out->ri = (sccp_ri == IWF_SCCP_RI_SSN) ? OSMO_SCCP_RI_SSN_PC
                                              : OSMO_SCCP_RI_GT;
    }
}

/* libosmo keeps struct osmo_ss7_instance opaque; cfg layout varies between
 * releases (e.g. secondary_pc added in 2.x).  Locate cfg.network_indicator
 * relative to cfg.primary_pc using osmo_ss7_instance_get_*(). */
static int iwf_ss7_set_network_indicator(struct osmo_ss7_instance *inst, uint8_t ni)
{
    if (!inst)
        return -1;

    size_t maxb = talloc_get_size(inst);
    if (maxb == (size_t)-1 || maxb == 0 || maxb > 65536u)
        maxb = 16384u;
    uint8_t *base = (uint8_t *)inst;

    uint32_t pc_orig = osmo_ss7_instance_get_primary_pc(inst);
    ptrdiff_t pc_off = -1;

    for (size_t off = 0; off + sizeof(uint32_t) <= maxb; off++) {
        uint32_t saved;
        memcpy(&saved, base + off, sizeof(saved));
        uint32_t probe = saved ^ 0x01010101u;
        memcpy(base + off, &probe, sizeof(probe));
        if (osmo_ss7_instance_get_primary_pc(inst) == probe) {
            memcpy(base + off, &saved, sizeof(saved));
            pc_off = (ptrdiff_t)off;
            break;
        }
        memcpy(base + off, &saved, sizeof(saved));
    }
    if (pc_off < 0) {
        LOGE("ss7", "could not locate cfg.primary_pc (pc=0x%x) for NI setup",
             (unsigned)pc_orig);
        return -1;
    }

    static const ptrdiff_t ni_rel[] = { 4, 5, 8, 12, 16 };
    for (size_t i = 0; i < sizeof(ni_rel) / sizeof(ni_rel[0]); i++) {
        ptrdiff_t noff = pc_off + ni_rel[i];
        if (noff < 0 || (size_t)noff >= maxb)
            continue;
        uint8_t saved = base[noff];
        base[noff] = ni;
        if (osmo_ss7_instance_get_network_indicator(inst) == ni) {
            LOGI("ss7", "network-indicator=%u (cfg offset primary_pc+%td)",
                 (unsigned)ni, ni_rel[i]);
            return 0;
        }
        base[noff] = saved;
    }

    LOGE("ss7", "could not locate cfg.network_indicator near primary_pc");
    return -1;
}

/* libosmo keeps struct osmo_ss7_as opaque; cfg offset varies (e.g. WITH_TCAP_LOADSHARING).
 * Find cfg by simple-client AS name prefix, then validate proto (see osmo ss7_as.h). */
struct iwf_as_cfg_prefix {
    char *name;
    char *description;
    enum osmo_ss7_asp_protocol proto;
    struct osmo_ss7_routing_key routing_key;
};

static struct osmo_ss7_routing_key *
iwf_find_as_routing_key(struct osmo_ss7_as *as, enum osmo_ss7_asp_protocol want_proto)
{
    const uint8_t *base = (const uint8_t *)as;
    size_t maxb = talloc_get_size(as);

    if (maxb == (size_t)-1 || maxb == 0 || maxb > 65536u)
        maxb = 8192u;

    const size_t need = offsetof(struct iwf_as_cfg_prefix, routing_key)
        + sizeof(struct osmo_ss7_routing_key);

    for (size_t off = 0; off + need <= maxb; off += sizeof(void *)) {
        const char *nm = *(const char *const *)(base + off);
        if (!nm || (uintptr_t)nm < 0x1000u)
            continue;
        if (strncmp(nm, "as-clnt-", 8) != 0)
            continue;
        struct iwf_as_cfg_prefix *cfg = (struct iwf_as_cfg_prefix *)(void *)(base + off);
        if (cfg->proto != want_proto)
            continue;
        return &cfg->routing_key;
    }
    return NULL;
}

static void deliver_unitdata(struct iwf_runtime *rt, ss7_recv_cb_t cb,
                             const struct osmo_sccp_addr *calling_osmo,
                             struct msgb *msg)
{
    if (!cb || !msg) {
        if (msg) msgb_free(msg);
        return;
    }
    ss7_sccp_addr_t calling;
    osmo_addr_to_ss7(calling_osmo, &calling);
    cb(rt, &calling, msgb_l2(msg), msgb_l2len(msg));
    msgb_free(msg);
}

static void log_sccp_notice(const char *tag, struct osmo_prim_hdr *oph)
{
    /* UDTS/XUDTS → N-NOTICE; cause is Q.713 return cause (enum sccp_return_cause). */
    struct osmo_scu_prim *scu = (struct osmo_scu_prim *)oph;
    LOGW("ss7", "%s SCCP N-NOTICE (UDTS/XUDTS return) cause=%u",
         tag ? tag : "ss7", (unsigned)scu->u.notice.cause);
}

static int sccp_prim_cb(struct osmo_prim_hdr *oph, void *priv)
{
    /* libosmo passes the osmo_sccp_user* as priv — NOT set_priv(). */
    struct osmo_sccp_user *scu_user = (struct osmo_sccp_user *)priv;
    struct iwf_runtime *rt = scu_user ? osmo_sccp_user_get_priv(scu_user) : NULL;
    if (!oph || !rt || !rt->map) {
        if (oph && oph->msg) msgb_free(oph->msg);
        return 0;
    }

    if (oph->sap == SCCP_SAP_USER &&
        oph->primitive == (unsigned int)OSMO_SCU_PRIM_N_UNITDATA &&
        oph->operation == PRIM_OP_INDICATION) {
        struct osmo_scu_prim *scu = (struct osmo_scu_prim *)oph;
        deliver_unitdata(rt, rt->map->ss7.recv_cb,
                         &scu->u.unitdata.calling_addr, oph->msg);
        return 0;
    }
    if (oph->sap == SCCP_SAP_USER &&
        oph->primitive == (unsigned int)OSMO_SCU_PRIM_N_NOTICE &&
        oph->operation == PRIM_OP_INDICATION) {
        log_sccp_notice("map", oph);
        if (oph->msg) msgb_free(oph->msg);
        return 0;
    }
    if (oph->msg) msgb_free(oph->msg);
    return 0;
}

#ifdef SMS_IWF_ENABLED
static int sccp_prim_cb_hlr(struct osmo_prim_hdr *oph, void *priv)
{
    /* libosmo passes osmo_sccp_user*; set_priv() holds iwf_runtime.
     * Casting priv to iwf_runtime* silently dropped all inbound HLR MAP. */
    struct osmo_sccp_user *scu_user = (struct osmo_sccp_user *)priv;
    struct iwf_runtime *rt = scu_user ? osmo_sccp_user_get_priv(scu_user) : NULL;
    if (!oph || !rt || !rt->map) {
        if (oph && oph->msg) msgb_free(oph->msg);
        return 0;
    }

    if (oph->sap == SCCP_SAP_USER &&
        oph->primitive == (unsigned int)OSMO_SCU_PRIM_N_UNITDATA &&
        oph->operation == PRIM_OP_INDICATION) {
        struct ss7_impl_ctx *ctx = rt->map->ss7.opaque;
        if (!ctx) {
            msgb_free(oph->msg);
            return 0;
        }
        struct osmo_scu_prim *scu = (struct osmo_scu_prim *)oph;
        deliver_unitdata(rt, ctx->recv_cb_hlr,
                         &scu->u.unitdata.calling_addr, oph->msg);
        return 0;
    }
    if (oph->sap == SCCP_SAP_USER &&
        oph->primitive == (unsigned int)OSMO_SCU_PRIM_N_NOTICE &&
        oph->operation == PRIM_OP_INDICATION) {
        log_sccp_notice("hlr", oph);
        if (oph->msg) msgb_free(oph->msg);
        return 0;
    }
    if (oph->msg) msgb_free(oph->msg);
    return 0;
}

void ss7_link_set_hlr_recv_cb(struct iwf_runtime *rt, ss7_recv_cb_t cb)
{
    if (!rt || !rt->map || !rt->map->ss7.opaque) return;
    struct ss7_impl_ctx *ctx = rt->map->ss7.opaque;
    ctx->recv_cb_hlr = cb;
}

int ss7_link_bind_hlr_ssn(struct iwf_runtime *rt, uint8_t ssn)
{
    if (!rt || !rt->map || !rt->map->ss7.opaque) return -1;
    struct ss7_impl_ctx *ctx = rt->map->ss7.opaque;
    if (ctx->user_hlr) return 0;
    ctx->user_hlr = osmo_sccp_user_bind(ctx->sccp, "iwf-hlr",
                                        sccp_prim_cb_hlr, ssn);
    if (!ctx->user_hlr) {
        LOGE("ss7", "sccp_user_bind failed for HLR ssn=%u", (unsigned)ssn);
        return -1;
    }
    osmo_sccp_user_set_priv(ctx->user_hlr, rt);
    LOGI("ss7", "bound SCCP user for HLR SSN %u (MAP SMS + MAP-IWF demux)",
         (unsigned)ssn);
    return 0;
}
#endif /* SMS_IWF_ENABLED */

int ss7_link_bind_extra_ssn(struct iwf_runtime *rt, uint8_t ssn, const char *name)
{
    if (!rt || !rt->map || !rt->map->ss7.opaque || !ssn) return -1;
    struct ss7_impl_ctx *ctx = rt->map->ss7.opaque;
    if (ssn == rt->cfg.map_local_ssn)
        return 0; /* already bound as primary user */
    for (int i = 0; i < ctx->n_user_extra; i++) {
        /* Dedup by slot occupancy only; libosmo rejects duplicate SSN binds. */
        (void)i;
    }
    if (ctx->n_user_extra >= (int)(sizeof(ctx->user_extra) / sizeof(ctx->user_extra[0]))) {
        LOGE("ss7", "extra SSN bind table full (ssn=%u)", (unsigned)ssn);
        return -1;
    }
    char uname[32];
    snprintf(uname, sizeof(uname), "%s", name && name[0] ? name : "iwf-extra");
    struct osmo_sccp_user *u = osmo_sccp_user_bind(ctx->sccp, uname,
                                                   sccp_prim_cb, ssn);
    if (!u) {
        LOGE("ss7", "sccp_user_bind failed for extra ssn=%u name=%s",
             (unsigned)ssn, uname);
        return -1;
    }
    osmo_sccp_user_set_priv(u, rt);
    ctx->user_extra[ctx->n_user_extra++] = u;
    LOGI("ss7", "bound SCCP user %s for SSN %u (MAP-C CSFB)", uname, (unsigned)ssn);
    return 0;
}

int ss7_link_init(struct iwf_runtime *rt)
{
    if (!rt || !rt->cfg.map_iwf_enabled) return -1;

    struct ss7_impl_ctx *ctx = (struct ss7_impl_ctx *)calloc(1, sizeof(*ctx));
    if (!ctx) return -1;
    ctx->tall_ctx = talloc_named_const(NULL, 0, "iwf_map");

    osmo_ss7_init();

    uint32_t default_pc = pack_map_local_pc(rt);
    if (!osmo_ss7_pc_is_valid(default_pc)) {
        LOGE("ss7", "[map_iwf] local_pc is required (dotted ITU code a.b.c, e.g. 1.2.3)");
        talloc_free(ctx->tall_ctx);
        free(ctx);
        return -1;
    }

    const char *m3ua_local = "0.0.0.0";
    struct in_addr bind_chk;
    if (rt->cfg.stp_local_ip[0]) {
        if (inet_pton(AF_INET, rt->cfg.stp_local_ip, &bind_chk) != 1) {
            LOGE("ss7", "[stp] local_ip %s is not a valid IPv4 address",
                 rt->cfg.stp_local_ip);
            talloc_free(ctx->tall_ctx);
            free(ctx);
            return -1;
        }
        m3ua_local = rt->cfg.stp_local_ip;
    }

    /* Drop stale inst-0; NI is applied after simple_client once primary_pc is set. */
    {
        struct osmo_ss7_instance *stale = osmo_ss7_instance_find(0);
        if (stale) {
            LOGW("ss7", "destroying pre-existing SS7 instance 0 before M3UA client");
            osmo_ss7_instance_destroy(stale);
        }
    }

    ctx->sccp = osmo_sccp_simple_client_on_ss7_id(
        ctx->tall_ctx, 0, "iwf",
        default_pc,
        OSMO_SS7_ASP_PROT_M3UA,
        /* default_local_port */  (int)rt->cfg.stp_local_port,
        /* default_local_ip */    m3ua_local,
        /* default_remote_port */ (int)rt->cfg.stp_port,
        /* default_remote_ip */   rt->cfg.stp_ip);
    if (!ctx->sccp) {
        LOGE("ss7", "sccp client setup failed");
        talloc_free(ctx->tall_ctx);
        free(ctx);
        return -1;
    }

    ctx->ss7 = osmo_sccp_get_ss7(ctx->sccp);
    if (!ctx->ss7) {
        LOGE("ss7", "osmo_sccp_get_ss7 failed after simple_client");
        osmo_sccp_instance_destroy(ctx->sccp);
        talloc_free(ctx->tall_ctx);
        free(ctx);
        return -1;
    }

    if (iwf_ss7_set_network_indicator(ctx->ss7, rt->cfg.stp_network_indicator) < 0) {
        LOGE("ss7", "failed to set network-indicator=%u — STP may reject M3UA DATA",
             (unsigned)rt->cfg.stp_network_indicator);
    } else if (osmo_ss7_instance_get_network_indicator(ctx->ss7)
               != rt->cfg.stp_network_indicator) {
        LOGE("ss7", "network-indicator readback %u != config %u",
             (unsigned)osmo_ss7_instance_get_network_indicator(ctx->ss7),
             (unsigned)rt->cfg.stp_network_indicator);
    }

    /* RKM: xua_rkm_send_reg_req() omits ROUTE_CTX when routing_key.context==0, so the
     * SG allocates a free RCTX (often 1) and may reject if permit_dyn_rkm_alloc=0.
     * Otherwise use [stp] routing_context (default 1) — must be unique per ASP; value 3
     * often clashes with osmo-sgsn on the same STP.
     * Set context+pc on the simple-client AS; locate cfg without a fragile struct mirror. */
    {
        struct osmo_ss7_as *as =
            osmo_ss7_as_find_by_name(ctx->ss7, IWF_SIMPLE_CLIENT_AS_NAME);
        if (!as)
            as = osmo_ss7_as_find_by_proto(ctx->ss7, OSMO_SS7_ASP_PROT_M3UA);
        if (as) {
            struct osmo_ss7_routing_key *rk = iwf_find_as_routing_key(
                as, OSMO_SS7_ASP_PROT_M3UA);
            if (rk) {
                rk->context = rt->cfg.stp_routing_context;
                rk->pc      = default_pc;
                LOGI("ss7", "AS routing_key RCTX=%u OPC=0x%x readback ctx=%u pc=0x%x",
                     (unsigned)rk->context, (unsigned)default_pc,
                     (unsigned)rk->context, (unsigned)rk->pc);
            } else {
                LOGW("ss7", "could not locate AS cfg.routing_key (libosmo layout?)");
            }
            struct osmo_ss7_asp *asp =
                osmo_ss7_asp_find_by_proto(as, OSMO_SS7_ASP_PROT_M3UA);
            /* simple_client may ASP-UP before we patch RKM; restart so STP
             * sees RCTX/OPC from [stp] routing_context + [map_iwf] local_pc. */
            if (asp) {
                LOGI("ss7", "restarting M3UA ASP after RKM patch RCTX=%u OPC=0x%x",
                     (unsigned)rt->cfg.stp_routing_context, (unsigned)default_pc);
                osmo_ss7_asp_restart(asp);
            }
            iwf_ss7_set_network_indicator(ctx->ss7, rt->cfg.stp_network_indicator);
        } else {
            LOGW("ss7", "could not find M3UA AS for RKM");
        }
    }

    ctx->user = osmo_sccp_user_bind(ctx->sccp, "iwf-sgsn",
                                    sccp_prim_cb,
                                    rt->cfg.map_local_ssn);
    if (!ctx->user) {
        LOGE("ss7", "sccp_user_bind failed for ssn=%u", rt->cfg.map_local_ssn);
        osmo_sccp_instance_destroy(ctx->sccp);
        osmo_ss7_instance_destroy(ctx->ss7);
        talloc_free(ctx->tall_ctx);
        free(ctx);
        return -1;
    }
    /* osmo_sccp_user has its own priv pointer for the prim cb. */
    osmo_sccp_user_set_priv(ctx->user, rt);

    LOGI("ss7", "SS7 primary OPC packed 0x%x (config %s)",
         (unsigned)default_pc,
         rt->cfg.map_local_pc[0] ? rt->cfg.map_local_pc : "?");

    ctx->local_pc = default_pc;
    ctx->stp_dpc  = pack_dotted_pc(rt->cfg.stp_remote_pc);
    ctx->network_indicator = rt->cfg.stp_network_indicator;
    ctx->sccp_ri  = rt->cfg.map_sccp_ri;
    LOGI("ss7", "outbound MAP: CdPA/CgPA sccp_ri=%s RI=%s, CgPA GT kept "
         "(PCI=0); M3UA DPC via MTP-TRANSFER to STP PC=%s",
         ctx->sccp_ri == IWF_SCCP_RI_SSN ? "ssn" : "gt",
         ctx->sccp_ri == IWF_SCCP_RI_SSN ? "SSN" : "GT (when GT present)",
         osmo_ss7_pc_is_valid(ctx->stp_dpc) ? rt->cfg.stp_remote_pc : "0");

    rt->map->ss7.opaque = ctx;
    rt->map->ss7.active = true;
    rt->map->ss7.fd     = -1;        /* libosmo manages its own select set */
    if (rt->cfg.stp_local_port)
        LOGI("ss7", "libosmo-sigtran M3UA %s:%u -> %s:%u (SSN=%u local_pc=%s)",
             m3ua_local, (unsigned)rt->cfg.stp_local_port,
             rt->cfg.stp_ip, rt->cfg.stp_port, rt->cfg.map_local_ssn,
             rt->cfg.map_local_pc[0] ? rt->cfg.map_local_pc : "0");
    else
        LOGI("ss7", "libosmo-sigtran M3UA %s:ephemeral -> %s:%u (SSN=%u local_pc=%s)",
             m3ua_local,
             rt->cfg.stp_ip, rt->cfg.stp_port, rt->cfg.map_local_ssn,
             rt->cfg.map_local_pc[0] ? rt->cfg.map_local_pc : "0");
    return 0;
}

void ss7_link_on_readable(struct iwf_runtime *rt)
{
    /* libosmo-sigtran drives its own select loop; the main epoll-side
     * trigger is the eventfd posted by the helper thread.  The real glue
     * implementation lives in a deployment-specific patch (it has to fit
     * the host's libosmocore version).  This entrypoint exists so main.c
     * can wire it identically across builds. */
    (void)rt;
    osmo_select_main_ctx(1);
}

/* Encode a classic SCCP UDT (class 0) into msg.  Addresses must already have
 * the desired PCI/SSNI/GTI (PCI=0: no OSMO_SCCP_ADDR_T_PC when STP-routed). */
static int ss7_encode_sccp_udt(struct msgb *msg,
                               const struct osmo_sccp_addr *called,
                               const struct osmo_sccp_addr *calling,
                               const uint8_t *data, size_t data_len)
{
    if (!msg || !called || !calling || (!data && data_len))
        return -1;
    if (data_len > 255u)
        return -EMSGSIZE; /* would need XUDT/LUDT; MAP PDUs are smaller */

    /* Snapshot header offset so later msgb_put cannot invalidate local ptrs. */
    const unsigned hdr_off = (unsigned)msgb_length(msg);
    uint8_t *hdr = msgb_put(msg, 5);
    hdr[0] = SCCP_MSG_TYPE_UDT;
    /* Q.713 §3.6 / Osmocom sccp_types.h: low nibble = class 0,
     * high nibble = message handling "return message on error" (0x8 → 0x80).
     * Wireshark: Protocol Class 0, Message handling = return on error. */
    hdr[1] = (uint8_t)((SCCP_PROTOCOL_RETURN_MESSAGE << 4) |
                       SCCP_PROTOCOL_CLASS_0);

    unsigned len_cd_off = (unsigned)msgb_length(msg);
    msgb_put(msg, 1);
    msg->data[hdr_off + 2] =
        (uint8_t)((msg->data + len_cd_off) - (msg->data + hdr_off + 2));
    int rc = osmo_sccp_addr_encode(msg, called);
    if (rc < 0)
        return rc;
    if (rc > 255)
        return -EMSGSIZE;
    msg->data[len_cd_off] = (uint8_t)rc;

    unsigned len_cg_off = (unsigned)msgb_length(msg);
    msgb_put(msg, 1);
    msg->data[hdr_off + 3] =
        (uint8_t)((msg->data + len_cg_off) - (msg->data + hdr_off + 3));
    rc = osmo_sccp_addr_encode(msg, calling);
    if (rc < 0)
        return rc;
    if (rc > 255)
        return -EMSGSIZE;
    msg->data[len_cg_off] = (uint8_t)rc;

    unsigned len_d_off = (unsigned)msgb_length(msg);
    msgb_put(msg, 1);
    msg->data[hdr_off + 4] =
        (uint8_t)((msg->data + len_d_off) - (msg->data + hdr_off + 4));
    if (data_len) {
        uint8_t *p = msgb_put(msg, data_len);
        memcpy(p, data, data_len);
    }
    msg->data[len_d_off] = (uint8_t)data_len;
    return 0;
}

/* libosmo-sigtran copies CdPA PC → M3UA DPC (sccp_scrc gen_mtp_transfer_req_xua).
 * Omitting OSMO_SCCP_ADDR_T_PC (SCCP PCI=0 toward STP) therefore yields M3UA
 * DPC=0 and the STP cannot route.  Always encode SCCP UDT without PC, then
 * issue MTP-TRANSFER.req with DPC=[stp] remote_pc so M3UA DPC and SCCP PCI
 * stay independent (both sccp_ri=gt and sccp_ri=ssn). */
static int ss7_tx_unitdata_mtp(struct ss7_impl_ctx *ctx,
                               const struct osmo_sccp_addr *calling_addr,
                               const struct osmo_sccp_addr *called_addr,
                               const uint8_t *tcap, size_t tcap_len)
{
    if (!ctx || !ctx->ss7 || !tcap)
        return -1;
    if (!osmo_ss7_pc_is_valid(ctx->stp_dpc)) {
        LOGE("ss7", "[stp] remote_pc unset — refusing TX (M3UA DPC would be 0)");
        return -1;
    }
    if (!osmo_ss7_pc_is_valid(ctx->local_pc)) {
        LOGE("ss7", "local_pc unset — refusing TX");
        return -1;
    }

    struct osmo_ss7_user *mtp_user =
        osmo_ss7_user_find_by_si(ctx->ss7, MTP_SI_SCCP);
    if (!mtp_user) {
        LOGE("ss7", "no MTP user for SI=SCCP on ss7 instance");
        return -1;
    }

    /* Headroom for osmo_mtp_prim; room for UDT + addresses + TCAP. */
    struct msgb *msg = msgb_alloc_headroom(tcap_len + 512, 128, "iwf-sccp-udt");
    if (!msg)
        return -1;

    int rc = ss7_encode_sccp_udt(msg, called_addr, calling_addr, tcap, tcap_len);
    if (rc < 0) {
        LOGE("ss7", "SCCP UDT encode failed rc=%d (MTP-TRANSFER path)", rc);
        msgb_free(msg);
        return rc;
    }

    /* Match osmo_mtp_prim_xfer_req_prepend: l2h = SCCP before pushing prim. */
    msg->l2h = msg->data;
    if (msgb_headroom(msg) < (int)sizeof(struct osmo_mtp_prim)) {
        LOGE("ss7", "SCCP msgb headroom too small for MTP prim");
        msgb_free(msg);
        return -1;
    }
    struct osmo_mtp_prim *omp =
        (struct osmo_mtp_prim *)msgb_push(msg, sizeof(*omp));
    osmo_prim_init(&omp->oph, MTP_SAP_USER,
                   OSMO_MTP_PRIM_TRANSFER, PRIM_OP_REQUEST, msg);
    omp->u.transfer.opc = ctx->local_pc;
    omp->u.transfer.dpc = ctx->stp_dpc;
    omp->u.transfer.sls = 0;
    omp->u.transfer.sio = MTP_SIO(MTP_SI_SCCP, ctx->network_indicator);

    /* Takes ownership of msg. */
    return osmo_ss7_user_mtp_sap_prim_down(mtp_user, omp);
}

static int ss7_tx_unitdata(struct ss7_impl_ctx *ctx,
                           struct osmo_sccp_user *user,
                           const ss7_sccp_addr_t *called,
                           const ss7_sccp_addr_t *calling,
                           const uint8_t *tcap, size_t tcap_len)
{
    struct osmo_sccp_addr called_addr = {0};
    struct osmo_sccp_addr calling_addr = {0};
    (void)user;
    ss7_encode_outbound_called(called, &called_addr, ctx->stp_dpc, ctx->sccp_ri);
    ss7_to_osmo_addr(calling, &calling_addr, ctx->sccp_ri);
    /* Never embed PC in CgPA (PCI=0). Partners copy CgPA → answer CdPA.
     *
     * CgPA MUST keep our GT and RI follows [map_iwf].sccp_ri (usually GT):
     *   - Stripping GT (allstp1245): 19 ISD Cont out, 0 acks back — peers
     *     cannot GTT the reply without our GT.
     *   - Forcing RI=SSN (allstp1248): a roaming partner HLR never answered our
     *     outbound UL — with route-on-SSN and PCI=0 their STP has no route
     *     back to us; inter-operator replies need GTT on our GT (RI=GT).
     *   - Inbound replies whose CdPA is our GT with RI=GT ARE delivered to
     *     the bound SSN user (allstp1247: ISD ack RI=GT → UL End sent), so
     *     no RI trickery is needed on the calling side. */
    calling_addr.pc = 0;
    calling_addr.presence &= ~OSMO_SCCP_ADDR_T_PC;
    if (calling && calling->have_gt)
        calling_addr.presence |= OSMO_SCCP_ADDR_T_GT;

    return ss7_tx_unitdata_mtp(ctx, &calling_addr, &called_addr,
                               tcap, tcap_len);
}

int ss7_link_send_tcap(struct iwf_runtime *rt,
                       const ss7_sccp_addr_t *called,
                       const uint8_t *tcap, size_t tcap_len)
{
    if (!rt || !rt->map || !rt->map->ss7.opaque) return -1;
    struct ss7_impl_ctx *ctx = rt->map->ss7.opaque;
    ss7_sccp_addr_t loc;
    ss7_link_make_local_addr(rt, &loc);
    return ss7_tx_unitdata(ctx, ctx->user, called, &loc, tcap, tcap_len);
}

int ss7_link_send_tcap_ex(struct iwf_runtime *rt,
                          const ss7_sccp_addr_t *called,
                          const ss7_sccp_addr_t *calling,
                          const uint8_t *tcap, size_t tcap_len)
{
    if (!rt || !rt->map || !rt->map->ss7.opaque) return -1;
    struct ss7_impl_ctx *ctx = rt->map->ss7.opaque;
    ss7_sccp_addr_t loc;
    const ss7_sccp_addr_t *cp = calling;
    if (!cp) {
        ss7_link_make_local_addr(rt, &loc);
        cp = &loc;
    }
    return ss7_tx_unitdata(ctx, ctx->user, called, cp, tcap, tcap_len);
}

void ss7_link_shutdown(struct iwf_runtime *rt)
{
    if (!rt || !rt->map) return;
    struct ss7_impl_ctx *ctx = (struct ss7_impl_ctx *)rt->map->ss7.opaque;
    if (!ctx) return;
    if (ctx->user)  osmo_sccp_user_unbind(ctx->user);
    for (int i = 0; i < ctx->n_user_extra; i++) {
        if (ctx->user_extra[i])
            osmo_sccp_user_unbind(ctx->user_extra[i]);
    }
#ifdef SMS_IWF_ENABLED
    if (ctx->user_hlr) osmo_sccp_user_unbind(ctx->user_hlr);
#endif
    if (ctx->sccp)  osmo_sccp_instance_destroy(ctx->sccp);
    if (ctx->ss7)   osmo_ss7_instance_destroy(ctx->ss7);
    if (ctx->tall_ctx) talloc_free(ctx->tall_ctx);
    free(ctx);
    rt->map->ss7.opaque = NULL;
    rt->map->ss7.active = false;
}

#else /* !MAP_IWF_WITH_OSMO_SIGTRAN */
/* ====================================================================== */
/* Stub implementation (no libosmo-sigtran linked)                        */
/* ====================================================================== */

int ss7_link_init(struct iwf_runtime *rt)
{
    if (!rt || !rt->cfg.map_iwf_enabled) return -1;
    LOGE("ss7", "MAP-IWF requested but build did not include libosmo-sigtran. "
                "Rebuild with: make MAP_IWF_ENABLED=1   (requires libosmo-sigtran + "
                "libosmo-sccp + libosmocore -dev packages).");
    rt->map->ss7.fd     = -1;
    rt->map->ss7.active = false;
    rt->map->ss7.opaque = NULL;
    return -1;
}

void ss7_link_on_readable(struct iwf_runtime *rt) { (void)rt; }

int  ss7_link_send_tcap(struct iwf_runtime *rt,
                        const ss7_sccp_addr_t *called,
                        const uint8_t *tcap, size_t tcap_len)
{
    (void)rt; (void)called; (void)tcap; (void)tcap_len;
    return -1;
}

int ss7_link_send_tcap_ex(struct iwf_runtime *rt,
                          const ss7_sccp_addr_t *called,
                          const ss7_sccp_addr_t *calling,
                          const uint8_t *tcap, size_t tcap_len)
{
    (void)rt; (void)called; (void)calling; (void)tcap; (void)tcap_len;
    return -1;
}

int ss7_link_bind_extra_ssn(struct iwf_runtime *rt, uint8_t ssn, const char *name)
{
    (void)rt; (void)ssn; (void)name;
    return -1;
}

#ifdef SMS_IWF_ENABLED
void ss7_link_set_hlr_recv_cb(struct iwf_runtime *rt, ss7_recv_cb_t cb)
{
    (void)rt; (void)cb;
}

int ss7_link_bind_hlr_ssn(struct iwf_runtime *rt, uint8_t ssn)
{
    (void)rt; (void)ssn;
    return -1;
}
#endif

void ss7_link_shutdown(struct iwf_runtime *rt) { (void)rt; }

#endif /* MAP_IWF_WITH_OSMO_SIGTRAN */
