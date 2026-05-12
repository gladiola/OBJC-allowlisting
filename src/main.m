#import <Foundation/Foundation.h>
#import "RequestValidator.h"

#include <signal.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "i18n.h"
#include "security_headers.h"

/* Maximum accepted POST body size (1 MB). */
#define MAX_BODY_SIZE (1024L * 1024L)

/* Seconds to wait for the complete POST body before aborting. */
#define POST_READ_TIMEOUT_SECS 30

/*
 * Directory that is the only permitted location for allowlist plist files.
 * ALLOWLIST_CONFIG is rejected if it does not resolve to a path under here.
 * The trailing '/' is intentional so prefix-matching cannot be fooled by
 * a sibling directory named "/etc/cgi-allowlist-evil".
 */
#define SAFE_CONFIG_DIR     "/etc/cgi-allowlist"
#define SAFE_CONFIG_PREFIX  "/etc/cgi-allowlist/"

/* Default path to the allowlist plist; override with ALLOWLIST_CONFIG env var. */
#define DEFAULT_ALLOWLIST_PATH "/etc/cgi-allowlist/allowlist.plist"

/* ── syslog helpers ────────────────────────────────────────────────────── */

/*
 * Cached copy of REMOTE_ADDR set at the start of each request.
 * Stored in a static buffer so the alarm signal handler (which must only
 * call async-signal-safe functions) can read it without calling getenv().
 */
static char g_remote_addr[64] = "unknown";

/*
 * Pre-built 408 response for the SIGALRM handler.
 * Populated in runValidator() before the alarm is armed, using the locale
 * detected from HTTP_ACCEPT_LANGUAGE.  The signal handler writes this buffer
 * with write(2), which is async-signal-safe.
 */
static char   g_timeout_response[1024];
static size_t g_timeout_response_len;

static void cache_remote_addr(void)
{
    const char *r = getenv("REMOTE_ADDR");
    if (r && r[0] != '\0')
        snprintf(g_remote_addr, sizeof(g_remote_addr), "%s", r);
}

/*
 * Log a security event.  The remote client address is prepended automatically
 * so every log line is self-contained.
 * All attack events are logged at LOG_WARNING; internal failures at LOG_ERR.
 *
 * These messages reach the local syslogd (facility LOG_AUTH) and can be
 * forwarded to a remote syslog collector via /etc/syslog.conf.
 */
static void security_log(int priority, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void security_log(int priority, const char *fmt, ...)
{
    char msg[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    syslog(priority, "client=%s %s", g_remote_addr, msg);
}

/* ── CGI response helpers ──────────────────────────────────────────────── */

static void respond(int status, const char *statusText, const char *body)
{
    printf("Status: %d %s\r\n", status, statusText);
    printf("Content-Type: text/plain; charset=utf-8\r\n");
    fputs(SECURITY_HEADERS_BLOCK, stdout);
    printf("\r\n");
    printf("%s\n", body);
    fflush(stdout);
}

/* ── Slow-POST alarm handler ───────────────────────────────────────────── */

/*
 * Called when SIGALRM fires after POST_READ_TIMEOUT_SECS seconds.
 * Only async-signal-safe functions are used here; g_remote_addr is a static
 * buffer populated before the alarm is armed so getenv() is not needed.
 */
static void alarm_handler(int sig)
{
    (void)sig;
    syslog(LOG_WARNING, "client=%s slow POST timeout, aborting", g_remote_addr);
    /* Write the pre-built localized CGI response (populated before arming the
     * alarm).  Only async-signal-safe functions are used here. */
    {
        ssize_t n = write(STDOUT_FILENO, g_timeout_response,
                          g_timeout_response_len);
        (void)n; /* best-effort in a signal handler; nothing to do on error */
    }
    _exit(1);
}

/* ── Path validation ───────────────────────────────────────────────────── */

/*
 * Returns 1 if path is safe to use as a config file path:
 *   - must start with SAFE_CONFIG_PREFIX (absolute, under the safe directory)
 *   - must not contain any ".." component
 *
 * A 0 return means the path is potentially malicious.
 */
static int isConfigPathSafe(const char *path)
{
    if (!path || path[0] == '\0') return 0;

    /* Reject path traversal sequences anywhere in the string. */
    if (strstr(path, "..")) return 0;

    /* Must be rooted under the safe config directory. */
    if (strncmp(path, SAFE_CONFIG_PREFIX, sizeof(SAFE_CONFIG_PREFIX) - 1) != 0)
        return 0;

    /* Must not be just the directory itself (needs a filename after the '/'). */
    if (path[sizeof(SAFE_CONFIG_PREFIX) - 1] == '\0') return 0;

    return 1;
}

/* ── Core validator logic (returns 0 on success, 1 on rejection/error) ─── */

static int runValidator(void)
{
    openlog("request_validator", LOG_PID | LOG_NDELAY, LOG_AUTH);
    cache_remote_addr(); /* populate g_remote_addr for use in signal handler */

    /* ── Detect locale from the Accept-Language request header ── */
    const LocalizedStrings *ls =
        get_localized_strings(getenv("HTTP_ACCEPT_LANGUAGE"));

    /* ── Pre-build the localized 408 response for the SIGALRM handler ── */
    {
        int n = snprintf(g_timeout_response, sizeof(g_timeout_response),
                         "Status: 408 Request Timeout\r\n"
                         "Content-Type: text/plain; charset=utf-8\r\n"
                         SECURITY_HEADERS_BLOCK
                         "\r\n"
                         "%s\n",
                         ls->request_timeout);
        if (n < 0) {
            /* snprintf error: signal handler will write an empty response. */
            g_timeout_response_len = 0;
        } else if ((size_t)n >= sizeof(g_timeout_response)) {
            /* Buffer was too small; snprintf truncated the output. Write as
             * much as fits (the NUL at position sizeof-1 is not written). */
            g_timeout_response_len = sizeof(g_timeout_response) - 1;
        } else {
            g_timeout_response_len = (size_t)n;
        }
    }

    const char *method = getenv("REQUEST_METHOD");
    if (!method) {
        respond(400, "Bad Request", ls->missing_request_method);
        return 1;
    }

    /* ── Determine and validate config path early ── */
    const char *cfgC = getenv("ALLOWLIST_CONFIG");
    if (cfgC && !isConfigPathSafe(cfgC)) {
        security_log(LOG_WARNING,
                     "path injection attempt via ALLOWLIST_CONFIG='%.256s'", cfgC);
        respond(400, "Bad Request", ls->invalid_config_path);
        return 1;
    }
    /*
     * The default path is a compile-time constant that satisfies
     * isConfigPathSafe() by construction; only the env-var override needs
     * runtime validation.
     */
    NSString *configPath = cfgC ? [NSString stringWithUTF8String:cfgC]
                                : @DEFAULT_ALLOWLIST_PATH;

#ifdef __OpenBSD__
    /*
     * Restrict filesystem access to the allowlist directory only, then drop
     * to the minimal pledge promise set needed for the rest of this request.
     * Both calls must succeed or the process refuses to continue.
     */
    if (unveil(SAFE_CONFIG_DIR, "r") == -1 || unveil(NULL, NULL) == -1) {
        security_log(LOG_ERR, "unveil failed");
        respond(500, "Internal Server Error", ls->internal_server_error);
        return 1;
    }
    if (pledge("stdio rpath", NULL) == -1) {
        security_log(LOG_ERR, "pledge failed");
        respond(500, "Internal Server Error", ls->internal_server_error);
        return 1;
    }
#endif

    NSString *body = nil;

    if (strcasecmp(method, "POST") == 0) {
        /* ── Verify Content-Type ── */
        const char *ct = getenv("CONTENT_TYPE");
        if (!ct ||
            strncasecmp(ct, "application/x-www-form-urlencoded",
                        sizeof("application/x-www-form-urlencoded") - 1) != 0) {
            security_log(LOG_WARNING,
                         "POST with unexpected or missing Content-Type: '%.128s'",
                         ct ? ct : "(none)");
            respond(415, "Unsupported Media Type", ls->invalid_content_type);
            return 1;
        }

        /* ── Read body from stdin up to CONTENT_LENGTH bytes ── */
        const char *clStr = getenv("CONTENT_LENGTH");
        if (!clStr) {
            respond(400, "Bad Request", ls->missing_content_length);
            return 1;
        }

        char *endPtr = NULL;
        long cl = strtol(clStr, &endPtr, 10);
        if (endPtr == clStr || cl < 0 || cl > MAX_BODY_SIZE) {
            security_log(LOG_WARNING,
                         "invalid CONTENT_LENGTH value: '%.64s'", clStr);
            respond(400, "Bad Request", ls->invalid_content_length);
            return 1;
        }

        /* Set a deadline so slow-POST clients cannot tie up the process. */
        signal(SIGALRM, alarm_handler);
        alarm(POST_READ_TIMEOUT_SECS);

        NSData *data = [[NSFileHandle fileHandleWithStandardInput]
                            readDataOfLength:(NSUInteger)cl];

        alarm(0);
        signal(SIGALRM, SIG_DFL);

        body = [[[NSString alloc] initWithData:data
                                      encoding:NSUTF8StringEncoding] autorelease];
        if (!body) {
            respond(400, "Bad Request", ls->body_not_utf8);
            return 1;
        }

    } else if (strcasecmp(method, "GET") == 0) {
        /* ── GET: form data comes from QUERY_STRING ── */
        const char *qs = getenv("QUERY_STRING");
        body = qs ? [NSString stringWithUTF8String:qs] : @"";

    } else {
        security_log(LOG_WARNING, "unsupported HTTP method: '%.32s'", method);
        respond(405, "Method Not Allowed", ls->method_not_allowed);
        return 1;
    }

    /* ── Load allowlist configuration ── */
    RequestValidator *validator = [[[RequestValidator alloc]
                                       initWithAllowlistPath:configPath] autorelease];
    if (!validator) {
        security_log(LOG_ERR, "failed to load allowlist config");
        respond(500, "Internal Server Error", ls->allowlist_load_failed);
        return 1;
    }

    /* ── Parse (with limit enforcement) ── */
    NSString *rejectionReason = nil;
    NSDictionary *params = [validator parseFormBody:body
                                    rejectionReason:&rejectionReason];
    if (!params) {
        security_log(LOG_WARNING, "request rejected during parsing: %s",
                     [rejectionReason UTF8String]);
        respond(400, "Bad Request", ls->request_too_large);
        return 1;
    }

    /* ── Validate against the allowlist ── */
    if ([validator validateParams:params rejectionReason:&rejectionReason]) {
        respond(200, "OK", ls->ok);
        return 0;
    }

    security_log(LOG_WARNING, "request rejected by allowlist: %s",
                 [rejectionReason UTF8String]);
    respond(403, "Forbidden", ls->forbidden);
    return 1;
}

/* ── Entry point ───────────────────────────────────────────────────────── */

int main(int argc, const char *argv[])
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    int rc = runValidator();
    closelog();
    [pool drain];
    return rc;
}
