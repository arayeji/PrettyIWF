/*
 * logging.h - structured logging for IWF
 *
 * Each log line is single-line, prefixed with timestamp/level/component,
 * and includes IMSI + sequence number when available so an operator can
 * grep -F "imsi=001010000000001" /var/log/iwf.log and follow a session.
 */

#ifndef IWF_LOGGING_H
#define IWF_LOGGING_H

#include <stdarg.h>
#include <stdio.h>

typedef enum {
    IWF_LOG_ERROR = 0,
    IWF_LOG_WARN  = 1,
    IWF_LOG_INFO  = 2,
    IWF_LOG_DEBUG = 3,
    IWF_LOG_TRACE = 4,
} iwf_log_level_t;

int  iwf_log_init(iwf_log_level_t level, const char *file_path);
void iwf_log_close(void);
void iwf_log_set_level(iwf_log_level_t level);
iwf_log_level_t iwf_log_level_from_str(const char *s);

void iwf_log(iwf_log_level_t level, const char *component,
             const char *fmt, ...) __attribute__((format(printf, 3, 4)));

/* Hex-dump (TRACE only). */
void iwf_log_hex(const char *component, const char *tag,
                 const void *buf, size_t len);

#define LOGE(comp, ...) iwf_log(IWF_LOG_ERROR, comp, __VA_ARGS__)
#define LOGW(comp, ...) iwf_log(IWF_LOG_WARN,  comp, __VA_ARGS__)
#define LOGI(comp, ...) iwf_log(IWF_LOG_INFO,  comp, __VA_ARGS__)
#define LOGD(comp, ...) iwf_log(IWF_LOG_DEBUG, comp, __VA_ARGS__)
#define LOGT(comp, ...) iwf_log(IWF_LOG_TRACE, comp, __VA_ARGS__)

#endif /* IWF_LOGGING_H */
