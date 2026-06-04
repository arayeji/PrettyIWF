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
#include "logging.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

static map_session_t *g_by_tid = NULL;
static map_session_t *g_by_sid = NULL;
static uint32_t       g_tid_counter = 0;

void map_sess_init(void)
{
    g_by_tid = NULL;
    g_by_sid = NULL;
    /* Mix PID + clock into the high bits so concurrent IWF instances
     * minting TIDs to the same STP don't collide on restart. */
    uint32_t t_part   = (uint32_t)(time(NULL) & 0x0000ffff);
    uint32_t pid_part = (uint32_t)(getpid()   & 0x000000ff);
    g_tid_counter = (pid_part << 24) | (t_part << 8) | 1;
}

void map_sess_shutdown(void)
{
    map_session_t *s, *tmp;
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
    LOGD("map_sess", "remove imsi=%s tid=0x%08x state=%s op=%s",
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
    }
    return "?";
}

int map_sess_sweep(time_t now, map_sess_timeout_hook_t hook, void *hook_ctx)
{
    int killed = 0;
    map_session_t *s, *tmp;
    HASH_ITER(hh_tid, g_by_tid, s, tmp) {
        time_t age_ms = (now - s->last_activity) * 1000;
        if (s->t_dialogue_ms > 0 && age_ms > s->t_dialogue_ms) {
            LOGW("map_sess", "timeout imsi=%s tid=0x%08x state=%s op=%s idle=%lds",
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
