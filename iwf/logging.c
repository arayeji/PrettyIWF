#include "logging.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <ctype.h>

static iwf_log_level_t g_level = IWF_LOG_INFO;
static FILE           *g_fp    = NULL;
static int             g_owns_fp = 0;

static const char *level_str(iwf_log_level_t l)
{
    switch (l) {
    case IWF_LOG_ERROR: return "ERROR";
    case IWF_LOG_WARN:  return "WARN ";
    case IWF_LOG_INFO:  return "INFO ";
    case IWF_LOG_DEBUG: return "DEBUG";
    case IWF_LOG_TRACE: return "TRACE";
    }
    return "?????";
}

iwf_log_level_t iwf_log_level_from_str(const char *s)
{
    if (!s) return IWF_LOG_INFO;
    if (!strcasecmp(s, "error")) return IWF_LOG_ERROR;
    if (!strcasecmp(s, "warn"))  return IWF_LOG_WARN;
    if (!strcasecmp(s, "info"))  return IWF_LOG_INFO;
    if (!strcasecmp(s, "debug")) return IWF_LOG_DEBUG;
    if (!strcasecmp(s, "trace")) return IWF_LOG_TRACE;
    return IWF_LOG_INFO;
}

int iwf_log_init(iwf_log_level_t level, const char *file_path)
{
    g_level = level;

    if (file_path && *file_path && strcmp(file_path, "-") != 0) {
        g_fp = fopen(file_path, "a");
        if (!g_fp) {
            fprintf(stderr, "iwf: cannot open log file %s, falling back to stderr\n",
                    file_path);
            g_fp = stderr;
            g_owns_fp = 0;
        } else {
            g_owns_fp = 1;
            setvbuf(g_fp, NULL, _IOLBF, 0);
        }
    } else {
        g_fp = stderr;
        g_owns_fp = 0;
    }
    return 0;
}

void iwf_log_close(void)
{
    if (g_fp && g_owns_fp) {
        fclose(g_fp);
    }
    g_fp = NULL;
    g_owns_fp = 0;
}

void iwf_log_set_level(iwf_log_level_t level)
{
    g_level = level;
}

void iwf_log(iwf_log_level_t level, const char *component, const char *fmt, ...)
{
    if (level > g_level) return;
    if (!g_fp) g_fp = stderr;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm_buf;
    localtime_r(&tv.tv_sec, &tm_buf);

    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tm_buf);

    fprintf(g_fp, "%s.%03ld [%s] [%-7s] ",
            ts, (long)(tv.tv_usec / 1000),
            level_str(level), component ? component : "iwf");

    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_fp, fmt, ap);
    va_end(ap);

    fputc('\n', g_fp);
}

void iwf_log_hex(const char *component, const char *tag,
                 const void *buf, size_t len)
{
    if (g_level < IWF_LOG_TRACE) return;
    if (!g_fp) g_fp = stderr;
    const uint8_t *p = (const uint8_t *)buf;

    fprintf(g_fp, "         [TRACE] [%-7s] %s len=%zu\n",
            component ? component : "iwf", tag ? tag : "hex", len);

    for (size_t i = 0; i < len; i += 16) {
        fprintf(g_fp, "                   %04zx  ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) fprintf(g_fp, "%02x ", p[i + j]);
            else             fprintf(g_fp, "   ");
        }
        fprintf(g_fp, " ");
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            uint8_t c = p[i + j];
            fputc(isprint(c) ? c : '.', g_fp);
        }
        fputc('\n', g_fp);
    }
}
