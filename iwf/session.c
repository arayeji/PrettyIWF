#include "session.h"
#include "logging.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>      /* strcasecmp */
#include <unistd.h>
#include <time.h>

static sess_t *g_by_key = NULL;       /* keyed on sess_key_t */
static sess_t *g_by_iwf_c = NULL;     /* keyed on iwf_ctrl_teid */
static sess_t *g_by_iwf_s4 = NULL;    /* keyed on iwf_s4_c_teid */
static uint32_t g_teid_counter = 0x10000001;

/* Secondary indices implemented with uthash require their own hh; for
 * simplicity we keep them as separate maps with intrusive node copies. We
 * use 3 different hh-handles on the same struct via uthash macros below. */

/* uthash requires distinct UT_hash_handle members per index. To keep the
 * implementation simple we keep two side dictionaries that only store
 * (teid -> sess_t*) pairs. */
typedef struct teid_idx_s {
    uint32_t       teid;
    sess_t        *sess;
    UT_hash_handle hh;
} teid_idx_t;

static teid_idx_t *g_iwf_c_idx  = NULL;
static teid_idx_t *g_iwf_s4_idx = NULL;

void sess_init(void)
{
    g_by_key = NULL;
    g_iwf_c_idx = NULL;
    g_iwf_s4_idx = NULL;
    /* Mix PID into the seed so two iwf processes started in the same second
     * cannot hand out the same TEIDs. Makes duplicate-process bugs obvious. */
    uint32_t t_part   = (uint32_t)(time(NULL) & 0x00ffff);
    uint32_t pid_part = (uint32_t)(getpid() & 0xff);
    g_teid_counter = 0x10000000u | (pid_part << 16) | t_part;
}

void sess_shutdown(void)
{
    sess_t *s, *tmp;
    HASH_ITER(hh, g_by_key, s, tmp) {
        HASH_DEL(g_by_key, s);
        free(s);
    }
    teid_idx_t *t, *t2;
    HASH_ITER(hh, g_iwf_c_idx, t, t2)  { HASH_DEL(g_iwf_c_idx,  t); free(t); }
    HASH_ITER(hh, g_iwf_s4_idx, t, t2) { HASH_DEL(g_iwf_s4_idx, t); free(t); }
    (void)g_by_iwf_c; (void)g_by_iwf_s4;
}

uint32_t sess_new_teid(void)
{
    if (++g_teid_counter == 0) g_teid_counter = 1;
    return g_teid_counter;
}

sess_t *sess_find(const char *imsi, uint8_t nsapi)
{
    sess_key_t k;
    memset(&k, 0, sizeof(k));
    strncpy(k.imsi, imsi, sizeof(k.imsi) - 1);
    k.nsapi = nsapi;

    sess_t *s = NULL;
    HASH_FIND(hh, g_by_key, &k, sizeof(k), s);
    return s;
}

static sess_t *teid_lookup(teid_idx_t *idx, uint32_t teid)
{
    teid_idx_t *e = NULL;
    HASH_FIND(hh, idx, &teid, sizeof(teid), e);
    return e ? e->sess : NULL;
}

sess_t *sess_find_by_iwf_ctrl_teid(uint32_t teid)
{
    return teid_lookup(g_iwf_c_idx, teid);
}

sess_t *sess_find_by_iwf_s4_c_teid(uint32_t teid)
{
    return teid_lookup(g_iwf_s4_idx, teid);
}

sess_t *sess_find_by_pending_v2_seq(uint32_t seq24, sess_state_t expect_state)
{
    uint32_t want = seq24 & 0xffffffu;
    sess_t *s, *tmp;
    HASH_ITER(hh, g_by_key, s, tmp) {
        if (s->state == expect_state && (s->gtpv2_seq & 0xffffffu) == want)
            return s;
    }
    return NULL;
}

sess_t *sess_find_pending_create_by_imsi_gnseq(const char *imsi, uint16_t gn_seq)
{
    sess_t *s, *tmp;
    HASH_ITER(hh, g_by_key, s, tmp) {
        if (strcmp(s->key.imsi, imsi) != 0)
            continue;
        if (s->state != SESS_WAIT_CS_RESP && s->state != SESS_CREATING)
            continue;
        if (s->sgsn_seq == gn_seq)
            return s;
    }
    return NULL;
}

sess_t *sess_find_active_by_imsi_apn_other_nsapi(const char *imsi,
                                                 const char *apn,
                                                 uint8_t exclude_nsapi)
{
    if (!imsi || !apn || !apn[0])
        return NULL;
    sess_t *s, *tmp;
    HASH_ITER(hh, g_by_key, s, tmp) {
        if (s->key.nsapi == exclude_nsapi)
            continue;
        if (strcmp(s->key.imsi, imsi) != 0)
            continue;
        if (!s->apn[0] || strcasecmp(s->apn, apn) != 0)
            continue;
        /* Only steady / mid-flight sessions count: a session in DELETING /
         * WAIT_DS_RESP is going away; one in CREATING / WAIT_CS_RESP hasn't
         * reached SMF yet so no `OLD Session` collision is possible. */
        switch (s->state) {
        case SESS_ACTIVE:
        case SESS_MODIFYING:
        case SESS_WAIT_MB_RESP:
        case SESS_WAIT_MB_RESP_INIT:
            return s;
        default:
            break;
        }
    }
    return NULL;
}

static void teid_index_insert(teid_idx_t **idx, uint32_t teid, sess_t *s)
{
    teid_idx_t *e = (teid_idx_t *)calloc(1, sizeof(*e));
    if (!e) return;
    e->teid = teid;
    e->sess = s;
    HASH_ADD(hh, *idx, teid, sizeof(uint32_t), e);
}

static void teid_index_remove(teid_idx_t **idx, uint32_t teid)
{
    teid_idx_t *e = NULL;
    HASH_FIND(hh, *idx, &teid, sizeof(uint32_t), e);
    if (e) { HASH_DEL(*idx, e); free(e); }
}

sess_t *sess_create(const char *imsi, uint8_t nsapi)
{
    sess_t *existing = sess_find(imsi, nsapi);
    if (existing) {
        LOGD("session", "reusing existing session imsi=%s nsapi=%u state=%s",
             imsi, nsapi, sess_state_str(existing->state));
        return existing;
    }

    sess_t *s = (sess_t *)calloc(1, sizeof(*s));
    if (!s) return NULL;
    strncpy(s->key.imsi, imsi, sizeof(s->key.imsi) - 1);
    s->key.nsapi = nsapi;
    s->state         = SESS_IDLE;
    s->created_at    = time(NULL);
    s->last_activity = s->created_at;

    s->iwf_ctrl_teid  = sess_new_teid();
    s->iwf_s4_c_teid  = sess_new_teid();

    HASH_ADD(hh, g_by_key, key, sizeof(sess_key_t), s);
    teid_index_insert(&g_iwf_c_idx,  s->iwf_ctrl_teid, s);
    teid_index_insert(&g_iwf_s4_idx, s->iwf_s4_c_teid, s);

    LOGI("session", "created imsi=%s nsapi=%u iwf_c=0x%08x iwf_s4=0x%08x",
         imsi, nsapi, s->iwf_ctrl_teid, s->iwf_s4_c_teid);
    return s;
}

void sess_remove(sess_t *s)
{
    if (!s) return;
    LOGI("session", "removing imsi=%s nsapi=%u state=%s",
         s->key.imsi, s->key.nsapi, sess_state_str(s->state));
    teid_index_remove(&g_iwf_c_idx,  s->iwf_ctrl_teid);
    teid_index_remove(&g_iwf_s4_idx, s->iwf_s4_c_teid);
    HASH_DEL(g_by_key, s);
    free(s);
}

void sess_touch(sess_t *s)
{
    if (s) s->last_activity = time(NULL);
}

const char *sess_state_str(sess_state_t st)
{
    switch (st) {
    case SESS_IDLE:          return "IDLE";
    case SESS_CREATING:      return "CREATING";
    case SESS_WAIT_CS_RESP:  return "WAIT_CS_RESP";
    case SESS_ACTIVE:        return "ACTIVE";
    case SESS_MODIFYING:     return "MODIFYING";
    case SESS_WAIT_MB_RESP:  return "WAIT_MB_RESP";
    case SESS_WAIT_MB_RESP_INIT: return "WAIT_MB_RESP_INIT";
    case SESS_DELETING:      return "DELETING";
    case SESS_WAIT_DS_RESP:  return "WAIT_DS_RESP";
    }
    return "?";
}

void sess_sweep(time_t now, int timeout_s)
{
    sess_t *s, *tmp;
    HASH_ITER(hh, g_by_key, s, tmp) {
        if ((now - s->last_activity) > timeout_s) {
            LOGW("session",
                 "timeout imsi=%s nsapi=%u state=%s idle=%lds",
                 s->key.imsi, s->key.nsapi, sess_state_str(s->state),
                 (long)(now - s->last_activity));
            sess_remove(s);
        }
    }
}

void sess_iterate(sess_iter_fn fn, void *ctx)
{
    sess_t *s, *tmp;
    HASH_ITER(hh, g_by_key, s, tmp) fn(s, ctx);
}
