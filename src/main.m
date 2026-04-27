#import <Foundation/Foundation.h>
#import "RequestValidator.h"

/* Maximum accepted POST body size (1 MB). */
#define MAX_BODY_SIZE (1024L * 1024L)

/* Default path to the allowlist plist; override with ALLOWLIST_CONFIG env var. */
#define DEFAULT_ALLOWLIST_PATH "/etc/cgi-allowlist/allowlist.plist"

/* ── CGI response helpers ──────────────────────────────────────────────── */

static void respond(int status, const char *statusText, const char *body)
{
    printf("Status: %d %s\r\n", status, statusText);
    printf("Content-Type: text/plain\r\n");
    printf("\r\n");
    printf("%s\n", body);
    fflush(stdout);
}

/* ── Core validator logic (returns 0 on success, 1 on rejection/error) ─── */

static int runValidator(void)
{
    const char *method = getenv("REQUEST_METHOD");
    if (!method) {
        respond(400, "Bad Request", "Missing REQUEST_METHOD");
        return 1;
    }

    NSString *body = nil;

    if (strcasecmp(method, "POST") == 0) {
        /* ── POST: read body from stdin up to CONTENT_LENGTH bytes ── */
        const char *clStr = getenv("CONTENT_LENGTH");
        if (!clStr) {
            respond(400, "Bad Request", "Missing CONTENT_LENGTH");
            return 1;
        }

        char *endPtr = NULL;
        long cl = strtol(clStr, &endPtr, 10);
        if (endPtr == clStr || cl < 0 || cl > MAX_BODY_SIZE) {
            respond(400, "Bad Request", "Invalid CONTENT_LENGTH");
            return 1;
        }

        NSData *data = [[NSFileHandle fileHandleWithStandardInput]
                            readDataOfLength:(NSUInteger)cl];
        body = [[[NSString alloc] initWithData:data
                                      encoding:NSUTF8StringEncoding] autorelease];
        if (!body) {
            respond(400, "Bad Request", "Request body is not valid UTF-8");
            return 1;
        }

    } else if (strcasecmp(method, "GET") == 0) {
        /* ── GET: form data comes from QUERY_STRING ── */
        const char *qs = getenv("QUERY_STRING");
        body = qs ? [NSString stringWithUTF8String:qs] : @"";

    } else {
        respond(405, "Method Not Allowed", "Only GET and POST are supported");
        return 1;
    }

    /* ── Load allowlist configuration ── */
    const char *cfgC = getenv("ALLOWLIST_CONFIG");
    NSString *configPath = cfgC ? [NSString stringWithUTF8String:cfgC]
                                : @DEFAULT_ALLOWLIST_PATH;

    RequestValidator *validator = [[[RequestValidator alloc]
                                       initWithAllowlistPath:configPath] autorelease];
    if (!validator) {
        respond(500, "Internal Server Error",
                "Failed to load allowlist configuration");
        return 1;
    }

    /* ── Parse and validate ── */
    NSDictionary *params = [validator parseFormBody:body];

    if ([validator validateParams:params]) {
        respond(200, "OK", "OK");
        return 0;
    }

    respond(403, "Forbidden", "403 Forbidden");
    return 1;
}

/* ── Entry point ───────────────────────────────────────────────────────── */

int main(int argc, const char *argv[])
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    int rc = runValidator();
    [pool drain];
    return rc;
}
