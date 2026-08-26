/*
 * msisdn_db.h - MSISDN -> IMSI lookup against the local HSS MongoDB
 * (Open5GS/pretty5gs "subscribers" collection).
 *
 * Used by the SRI (sendRoutingInformation) handler as a fallback when the
 * in-memory map has no entry: each unknown MSISDN is read from the DB at
 * most once, then cached (and file-persisted) by the caller; ISD keeps the
 * mapping current afterwards.
 *
 * CS location (vlr_number / cs_purge_flag) is read from the same Mongo
 * document the HSS updates on CS ULR — no Diameter Sh round-trip needed.
 *
 * Compiled against libmongoc when the Makefile detects it
 * (IWF_WITH_MONGOC); otherwise all calls are inert stubs returning -1.
 */

#ifndef IWF_MSISDN_DB_H
#define IWF_MSISDN_DB_H

#include <stddef.h>
#include <stdbool.h>

/* uri example: mongodb://127.0.0.1:27017  (timeouts are appended
 * automatically unless the uri already carries options).
 * Returns 0 when the client is ready, -1 when disabled/unavailable. */
int  msisdn_db_init(const char *uri, const char *dbname);
void msisdn_db_shutdown(void);

/* Query the subscribers collection for an MSISDN (international digits).
 * Returns 0 and fills imsi_out on a hit, -1 on miss/error/disabled. */
int  msisdn_db_lookup(const char *msisdn, char *imsi_out, size_t cap);

typedef struct {
    char     imsi[16];
    char     vlr_number[24];
    bool     have_vlr;
    bool     cs_purge_flag;
    bool     cs_active;   /* have_vlr && !cs_purge_flag */
} msisdn_db_cs_t;

/* MSISDN -> IMSI + CS registration in HSS Mongo (vlr_number, cs_purge_flag).
 * Returns 0 on hit, -1 on miss/error/disabled. */
int  msisdn_db_lookup_cs(const char *msisdn, msisdn_db_cs_t *out);

#endif /* IWF_MSISDN_DB_H */
