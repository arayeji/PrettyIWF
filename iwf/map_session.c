/*
 * map_session.c - dialogue table for the MAP-Diameter IWF.
 *
 * Two indices over the same struct:
 *
 *   hh_tid  - keyed on (uint32_t tcap_dialogue_id)
 *             primary lookup; populated at create time, never changes.
 *   hh_sid  - keyed on Diameter Session-Id (textual, NUL-terminated)
 *             populated when we emit AIR/ULR/CLR/PUR and need to route
 *             the answer back.
 *
 * uthash requires distinct UT_hash_handle members on the struct for each
 * index, so we use hh_tid and hh_sid - this is the same pattern as the
 * GTP session table.
 */

#include "map_session.h"
#include "map_codec.h"
#include "logging.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

static map_session_t *g_by_tid = NULL;
static map_session_t *g_by_sid = NULL;
static uint32_t       g_tid_counter = 0;

/* Last UpdateGprsLocation GSN-Address per IMSI. Not tied to a dialogue:
 * SendRoutingInfoForGPRS arrives later, after the UGL session is gone. */
#define SGSN_GSN_SLOTS 128
typedef struct {
    char     imsi[MAP_IMSI_STR_MAX];
    uint8_t  gsn[17];
    uint8_t  len;
    time_t   updated;
} sgsn_gsn_slot_t;
static sgsn_gsn_slot_t g_sgsn_gsn[SGSN_GSN_SLOTS];

void map_sess_init(void)
{
    g_by_tid = NULL;
    g_by_sid = NULL;
    memset(g_sgsn_gsn, 0, sizeof(g_sgsn_gsn));
    /* Mix PID + clock into the high bits so concurrent IWF instances
     * minting TIDs to the same STP don't collide on restart. */
    uint32_t t_part   = (uint32_t)(time(NULL) & 0x0000ffff);
    uint32_t pid_part = (uint32_t)(getpid()   & 0x000000ff);
    g_tid_counter = (pid_part << 24) | (t_part << 8) | 1;
}

void map_sess_shutdown(void)
{
    map_session_t *s, *tmp;
    memset(g_sgsn_gsn, 0, sizeof(g_sgsn_gsn));
    HASH_ITER(hh_tid, g_by_tid, s, tmp) {
        if (s->diameter_session_id[0])
            HASH_DELETE(hh_sid, g_by_sid, s);
        HASH_DELETE(hh_tid, g_by_tid, s);
        free(s);
    }
}

uint32_t map_sess_new_tid(void)
{
    /* Avoid the all-zero TID; some peers reject it. */
    if (++g_tid_counter == 0) g_tid_counter = 1;
    return g_tid_counter;
}

map_session_t *map_sess_create(uint32_t tid)
{
    map_session_t *s = (map_session_t *)calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->tcap_dialogue_id = tid;
    s->state            = MAP_SESS_IDLE;
    s->created_at       = time(NULL);
    s->last_activity    = s->created_at;
    s->t_dialogue_ms    = 10000;       /* tcap.h default; map_iwf overrides */
    s->cmd_test         = false;
    s->cmd_test_reply_fd = -1;
    HASH_ADD(hh_tid, g_by_tid, tcap_dialogue_id,
             sizeof(s->tcap_dialogue_id), s);
    return s;
}

void map_sess_remove(map_session_t *s)
{
    if (!s) return;
    LOGD("map_sess",
         "[%s] remove tid=0x%08x state=%s op=%s",
         s->imsi_str[0] ? s->imsi_str : "?",
         s->tcap_dialogue_id,
         map_sess_state_str(s->state),
         map_op_str(s->map_op));
    if (s->diameter_session_id[0])
        HASH_DELETE(hh_sid, g_by_sid, s);
    HASH_DELETE(hh_tid, g_by_tid, s);
    free(s);
}

map_session_t *map_sess_find_by_tid(uint32_t tid)
{
    map_session_t *s = NULL;
    HASH_FIND(hh_tid, g_by_tid, &tid, sizeof(tid), s);
    return s;
}

map_session_t *map_sess_find_by_peer_tid(uint32_t peer_tid)
{
    map_session_t *s, *tmp;

    if (!peer_tid)
        return NULL;
    HASH_ITER(hh_tid, g_by_tid, s, tmp) {
        if (s->have_peer_tid && s->peer_tcap_dialogue_id == peer_tid)
            return s;
    }
    return NULL;
}

map_session_t *map_sess_find_by_diameter_sid(const char *sid)
{
    if (!sid || !*sid) return NULL;
    map_session_t *s = NULL;
    HASH_FIND(hh_sid, g_by_sid, sid, strlen(sid), s);
    if (s) return s;
    /* Fall back to linear scan: some HSS implementations may rewrite the
     * Session-Id case or strip optional padding, so we accept a relaxed
     * compare here. Linear scan is fine for tens of in-flight dialogues. */
    map_session_t *tmp;
    HASH_ITER(hh_tid, g_by_tid, s, tmp) {
        if (s->diameter_session_id[0] &&
            strcmp(s->diameter_session_id, sid) == 0)
            return s;
    }
    return NULL;
}

map_session_t *map_sess_find_by_diam_hbh(uint32_t hbh)
{
    map_session_t *s, *tmp;

    if (!hbh)
        return NULL;
    HASH_ITER(hh_tid, g_by_tid, s, tmp) {
        if (s->diameter_hop_by_hop == hbh)
            return s;
    }
    return NULL;
}

map_session_t *map_sess_find_gsup_pending(const char *imsi, map_op_t op)
{
    if (!imsi || !imsi[0]) return NULL;
    map_session_t *s, *tmp;
    HASH_ITER(hh_tid, g_by_tid, s, tmp) {
        if (s->gsup_originated && s->map_op == op &&
            s->state == MAP_SESS_WAIT_MAP_ACK &&
            strcmp(s->imsi_str, imsi) == 0)
            return s;
    }
    return NULL;
}

void map_sess_index_by_sid(map_session_t *s)
{
    if (!s || !s->diameter_session_id[0]) return;
    HASH_ADD_KEYPTR(hh_sid, g_by_sid,
                    s->diameter_session_id,
                    strlen(s->diameter_session_id), s);
}

void map_sess_touch(map_session_t *s)
{
    if (s) s->last_activity = time(NULL);
}

const char *map_sess_state_str(map_sess_state_t st)
{
    switch (st) {
    case MAP_SESS_IDLE:           return "IDLE";
    case MAP_SESS_WAIT_DIAMETER:  return "WAIT_DIAMETER";
    case MAP_SESS_WAIT_MAP_TX:    return "WAIT_MAP_TX";
    case MAP_SESS_WAIT_MAP_ACK:   return "WAIT_MAP_ACK";
    case MAP_SESS_DONE:           return "DONE";
    case MAP_SESS_ABORTED:        return "ABORTED";
    }
    return "?";
}

const char *map_op_str(map_op_t op)
{
    switch (op) {
    case MAP_OP_NONE:     return "NONE";
    case MAP_OP_SAI:      return "SAI";
    case MAP_OP_UGL:      return "UGL";
    case MAP_OP_ISD:      return "ISD";
    case MAP_OP_CL:       return "CL";
    case MAP_OP_PURGE_MS: return "PurgeMS";
    case MAP_OP_UL:       return "UL";
    case MAP_OP_PRN:      return "PRN";
    case MAP_OP_SRI:      return "SRI";
    case MAP_OP_SRI_GPRS: return "SRI-GPRS";
    }
    return "?";
}

void map_sess_note_sgsn_gsn(const char *imsi, const uint8_t *gsn, uint8_t len)
{
    uint8_t norm[17];
    size_t n = 0;
    sgsn_gsn_slot_t *match = NULL;
    sgsn_gsn_slot_t *empty = NULL;
    sgsn_gsn_slot_t *oldest = NULL;
    sgsn_gsn_slot_t *slot;
    int i;

    if (!imsi || !imsi[0] || !gsn)
        return;
    if (map_gsn_normalize(gsn, len, norm, sizeof(norm), &n) < 0)
        return;

    for (i = 0; i < SGSN_GSN_SLOTS; i++) {
        if (g_sgsn_gsn[i].imsi[0] && !strcmp(g_sgsn_gsn[i].imsi, imsi)) {
            match = &g_sgsn_gsn[i];
            break;
        }
        if (!g_sgsn_gsn[i].imsi[0] && !empty)
            empty = &g_sgsn_gsn[i];
        if (!oldest || g_sgsn_gsn[i].updated < oldest->updated)
            oldest = &g_sgsn_gsn[i];
    }
    slot = match ? match : (empty ? empty : oldest);
    if (!slot)
        return;
    memset(slot, 0, sizeof(*slot));
    strncpy(slot->imsi, imsi, sizeof(slot->imsi) - 1);
    memcpy(slot->gsn, norm, n);
    slot->len = (uint8_t)n;
    slot->updated = time(NULL);
}

int map_sess_sgsn_gsn(const char *imsi, uint8_t *out, size_t cap)
{
    int i;
    if (!imsi || !imsi[0] || !out)
        return 0;
    for (i = 0; i < SGSN_GSN_SLOTS; i++) {
        if (!g_sgsn_gsn[i].imsi[0] || strcmp(g_sgsn_gsn[i].imsi, imsi))
            continue;
        if (g_sgsn_gsn[i].len > cap)
            return 0;
        memcpy(out, g_sgsn_gsn[i].gsn, g_sgsn_gsn[i].len);
        return g_sgsn_gsn[i].len;
    }
    return 0;
}

int map_sess_imsi_present(const char *imsi)
{
    map_session_t *s, *tmp;
    if (!imsi || !imsi[0])
        return 0;
    HASH_ITER(hh_tid, g_by_tid, s, tmp) {
        if (s->imsi_str[0] && !strcmp(s->imsi_str, imsi))
            return 1;
    }
    return 0;
}

int map_sess_sweep(time_t now, map_sess_timeout_hook_t hook, void *hook_ctx)
{
    int killed = 0;
    map_session_t *s, *tmp;
    HASH_ITER(hh_tid, g_by_tid, s, tmp) {
        time_t age_ms = (now - s->last_activity) * 1000;
        if (s->t_dialogue_ms > 0 && age_ms > s->t_dialogue_ms) {
            LOGW("map_sess",
         "[%s] timeout tid=0x%08x state=%s op=%s idle=%lds",
         s->imsi_str[0] ? s->imsi_str : "?",
         s->tcap_dialogue_id,
         map_sess_state_str(s->state),
         map_op_str(s->map_op),
         (long)(now - s->last_activity));
            s->state = MAP_SESS_ABORTED;
            if (hook)
                hook(s, hook_ctx);
            map_sess_remove(s);
            killed++;
        }
    }
    return killed;
}

void map_sess_iterate(map_sess_iter_fn fn, void *ctx)
{
    map_session_t *s, *tmp;
    HASH_ITER(hh_tid, g_by_tid, s, tmp) fn(s, ctx);
}
