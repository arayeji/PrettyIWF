/*
 * msisdn_db.c - MSISDN -> IMSI lookup in the local HSS MongoDB.
 *
 * The query runs synchronously in the event loop, so the connection is
 * kept to the local mongod with aggressive timeouts (a localhost find on
 * an indexed field is sub-millisecond; worst case we stall one loop
 * iteration for ~300 ms if mongod is wedged).
 */

#include "msisdn_db.h"
#include "logging.h"

#include <stdio.h>
#include <string.h>

#ifdef IWF_WITH_MONGOC

#include <mongoc/mongoc.h>

static mongoc_client_t     *g_client;
static mongoc_collection_t *g_coll;

int msisdn_db_init(const char *uri, const char *dbname)
{
    if (!uri || !uri[0]) return -1;
    if (!dbname || !dbname[0]) dbname = "open5gs";

    char full_uri[512];
    if (strchr(uri, '?'))
        snprintf(full_uri, sizeof(full_uri), "%s", uri);
    else
        snprintf(full_uri, sizeof(full_uri),
                 "%s/?serverSelectionTimeoutMS=200&connectTimeoutMS=200"
                 "&socketTimeoutMS=300",
                 uri);

    mongoc_init();
    g_client = mongoc_client_new(full_uri);
    if (!g_client) {
        LOGW("map", "msisdn_db: bad MongoDB uri %s", uri);
        return -1;
    }
    mongoc_client_set_error_api(g_client, MONGOC_ERROR_API_VERSION_2);
    g_coll = mongoc_client_get_collection(g_client, dbname, "subscribers");
    LOGI("map", "msisdn_db: MongoDB lookup enabled uri=%s db=%s", uri, dbname);
    return 0;
}

void msisdn_db_shutdown(void)
{
    if (g_coll)   { mongoc_collection_destroy(g_coll); g_coll = NULL; }
    if (g_client) { mongoc_client_destroy(g_client);   g_client = NULL; }
    mongoc_cleanup();
}

int msisdn_db_lookup(const char *msisdn, char *imsi_out, size_t cap)
{
    if (!g_coll || !msisdn || !msisdn[0] || !imsi_out || !cap) return -1;
    imsi_out[0] = '\0';

    /* subscribers.msisdn is an array of strings; equality matches members. */
    bson_t *filter = BCON_NEW("msisdn", BCON_UTF8(msisdn));
    bson_t *opts = BCON_NEW("projection", "{", "imsi", BCON_INT32(1), "}",
                            "limit", BCON_INT64(1));
    mongoc_cursor_t *cur =
        mongoc_collection_find_with_opts(g_coll, filter, opts, NULL);

    const bson_t *doc = NULL;
    if (mongoc_cursor_next(cur, &doc)) {
        bson_iter_t it;
        if (bson_iter_init_find(&it, doc, "imsi") &&
            BSON_ITER_HOLDS_UTF8(&it)) {
            uint32_t l = 0;
            const char *s = bson_iter_utf8(&it, &l);
            if (s && l)
                snprintf(imsi_out, cap, "%.*s", (int)l, s);
        }
    }
    bson_error_t err;
    if (mongoc_cursor_error(cur, &err))
        LOGW("map", "msisdn_db: query msisdn=%s failed: %s", msisdn,
             err.message);

    mongoc_cursor_destroy(cur);
    bson_destroy(opts);
    bson_destroy(filter);
    return imsi_out[0] ? 0 : -1;
}

#else /* !IWF_WITH_MONGOC */

int msisdn_db_init(const char *uri, const char *dbname)
{
    (void)dbname;
    if (uri && uri[0])
        LOGW("map", "msisdn_db: msisdn_db_uri set but IWF built without "
             "libmongoc (install libmongoc-dev and rebuild)");
    return -1;
}

void msisdn_db_shutdown(void) {}

int msisdn_db_lookup(const char *msisdn, char *imsi_out, size_t cap)
{
    (void)msisdn; (void)imsi_out; (void)cap;
    return -1;
}

#endif /* IWF_WITH_MONGOC */
