#import <Foundation/Foundation.h>
#import "../src/RequestValidator.h"

/* ── Minimal test framework ────────────────────────────────────────────── */

static int g_passed = 0;
static int g_failed = 0;

#define ASSERT(desc, expr)                                              \
    do {                                                                \
        if (expr) {                                                     \
            g_passed++;                                                 \
            fprintf(stdout, "PASS: %s\n", (desc));                     \
        } else {                                                        \
            g_failed++;                                                 \
            fprintf(stderr, "FAIL: %s  (line %d)\n", (desc), __LINE__);\
        }                                                               \
    } while (0)

/* ── Helpers ───────────────────────────────────────────────────────────── */

/* Build the allowlist used across most tests. */
static NSDictionary *makeTestAllowlist(void)
{
    NSArray *actionValues = [NSArray arrayWithObjects:
                                @"login", @"logout", @"submit", nil];
    NSDictionary *actionRule = [NSDictionary dictionaryWithObjectsAndKeys:
                                    @"values",    @"type",
                                    actionValues, @"allowed",
                                    nil];

    NSDictionary *usernameRule = [NSDictionary dictionaryWithObjectsAndKeys:
                                      @"regex",               @"type",
                                      @"^[a-zA-Z0-9]{1,32}$", @"pattern",
                                      nil];

    NSDictionary *tokenRule = [NSDictionary dictionaryWithObjectsAndKeys:
                                   @"regex",                @"type",
                                   @"^[0-9a-fA-F]{64}$",   @"pattern",
                                   nil];

    return [NSDictionary dictionaryWithObjectsAndKeys:
                actionRule,    @"action",
                usernameRule,  @"username",
                tokenRule,     @"token",
                nil];
}

static RequestValidator *makeValidator(void)
{
    return [[[RequestValidator alloc]
                initWithAllowlist:makeTestAllowlist()] autorelease];
}

/* ── Test groups ───────────────────────────────────────────────────────── */

static void testUrldecode(void)
{
    RequestValidator *v = makeValidator();

    /* parseFormBody exercises urldecodeComponent internally */
    NSDictionary *p;

    /* '+' → space */
    p = [v parseFormBody:@"username=hello+world"];
    ASSERT("urldecode: '+' becomes space",
           [[p objectForKey:@"username"] isEqualToString:@"hello world"]);

    /* %XX decoding */
    p = [v parseFormBody:@"username=log%69n"];
    ASSERT("urldecode: %69 → 'i'",
           [[p objectForKey:@"username"] isEqualToString:@"login"]);

    /* %2B is a literal '+', not a space */
    p = [v parseFormBody:@"username=a%2Bb"];
    ASSERT("urldecode: %2B → '+'",
           [[p objectForKey:@"username"] isEqualToString:@"a+b"]);
}

static void testParseFormBody(void)
{
    RequestValidator *v = makeValidator();
    NSDictionary *p;

    /* Basic key=value pair */
    p = [v parseFormBody:@"action=login"];
    ASSERT("parse: single pair", [p count] == 1);
    ASSERT("parse: single pair value",
           [[p objectForKey:@"action"] isEqualToString:@"login"]);

    /* Multiple pairs */
    p = [v parseFormBody:@"action=login&username=alice"];
    ASSERT("parse: two pairs key count", [p count] == 2);
    ASSERT("parse: two pairs action",
           [[p objectForKey:@"action"] isEqualToString:@"login"]);
    ASSERT("parse: two pairs username",
           [[p objectForKey:@"username"] isEqualToString:@"alice"]);

    /* Value contains '=' (e.g. base64 padding) — only first '=' splits */
    p = [v parseFormBody:@"token=abc=def"];
    ASSERT("parse: value with '=' inside",
           [[p objectForKey:@"token"] isEqualToString:@"abc=def"]);

    /* Key with no value */
    p = [v parseFormBody:@"action="];
    ASSERT("parse: empty value",
           [[p objectForKey:@"action"] isEqualToString:@""]);

    /* Empty body → empty dict */
    p = [v parseFormBody:@""];
    ASSERT("parse: empty body", [p count] == 0);

    /* nil body → empty dict */
    p = [v parseFormBody:nil];
    ASSERT("parse: nil body", [p count] == 0);
}

static void testValuesRule(void)
{
    RequestValidator *v = makeValidator();

    NSDictionary *ok  = [NSDictionary dictionaryWithObjectsAndKeys:
                             @"login", @"action", nil];
    NSDictionary *bad = [NSDictionary dictionaryWithObjectsAndKeys:
                             @"DELETE", @"action", nil];

    ASSERT("values rule: accepted value",  [v validateParams:ok]);
    ASSERT("values rule: rejected value", ![v validateParams:bad]);
}

static void testRegexRule(void)
{
    RequestValidator *v = makeValidator();
    BOOL result;

    /* Valid username */
    result = [v validateParams:[NSDictionary dictionaryWithObject:@"alice123"
                                                           forKey:@"username"]];
    ASSERT("regex rule: valid username", result);

    /* Username too long (33 chars) */
    result = [v validateParams:
                  [NSDictionary dictionaryWithObject:@"abcdefghijklmnopqrstuvwxyz1234567"
                                             forKey:@"username"]];
    ASSERT("regex rule: username too long", !result);

    /* Username contains space — reject */
    result = [v validateParams:[NSDictionary dictionaryWithObject:@"bad user"
                                                           forKey:@"username"]];
    ASSERT("regex rule: username with space", !result);

    /* Valid 64-char hex token */
    NSString *goodToken =
        @"a1b2c3d4e5f60718293a4b5c6d7e8f9001234567890abcdef1234567890abcde";
    result = [v validateParams:[NSDictionary dictionaryWithObject:goodToken
                                                           forKey:@"token"]];
    ASSERT("regex rule: valid token", result);

    /* Token too short */
    result = [v validateParams:[NSDictionary dictionaryWithObject:@"deadbeef"
                                                           forKey:@"token"]];
    ASSERT("regex rule: short token", !result);
}

static void testUnknownKey(void)
{
    RequestValidator *v = makeValidator();
    BOOL result;

    /* Key "evil" not in allowlist */
    result = [v validateParams:[NSDictionary dictionaryWithObject:@"payload"
                                                           forKey:@"evil"]];
    ASSERT("unknown key rejected", !result);

    /* Known key mixed with unknown key */
    NSDictionary *mixed = [NSDictionary dictionaryWithObjectsAndKeys:
                               @"login", @"action",
                               @"x",     @"evil",
                               nil];
    result = [v validateParams:mixed];
    ASSERT("known + unknown key rejected", !result);
}

static void testEmptyParams(void)
{
    RequestValidator *v = makeValidator();

    /* Empty submission is valid — the test allowlist has no required fields. */
    ASSERT("empty params accepted (no required fields)",
           [v validateParams:[NSDictionary dictionary]]);
}

static void testAllParamsValid(void)
{
    RequestValidator *v = makeValidator();

    NSString *token64 =
        @"0000000000000000000000000000000000000000000000000000000000000000";
    NSDictionary *params = [NSDictionary dictionaryWithObjectsAndKeys:
                                @"submit", @"action",
                                @"Bob42",  @"username",
                                token64,   @"token",
                                nil];
    ASSERT("all valid params accepted", [v validateParams:params]);
}

static void testLoadFromFile(void)
{
    /* Derive path to tests/fixtures/test_allowlist.plist relative to argv[0].
       The executable is built in the repo root, so the fixture is at
       tests/fixtures/test_allowlist.plist from there. */
    NSString *exeDir = [[[NSBundle mainBundle] executablePath]
                            stringByDeletingLastPathComponent];
    NSString *fixturePath = [exeDir
        stringByAppendingPathComponent:
            @"tests/fixtures/test_allowlist.plist"];

    RequestValidator *v = [[[RequestValidator alloc]
                               initWithAllowlistPath:fixturePath] autorelease];
    ASSERT("load from file: validator created", v != nil);

    if (v) {
        BOOL r1 = [v validateParams:[NSDictionary dictionaryWithObject:@"login"
                                                                forKey:@"action"]];
        ASSERT("load from file: valid params accepted", r1);

        BOOL r2 = [v validateParams:[NSDictionary dictionaryWithObject:@"HACK"
                                                                forKey:@"action"]];
        ASSERT("load from file: invalid value rejected", !r2);
    }
}

static void testNilAllowlistPath(void)
{
    RequestValidator *v = [[[RequestValidator alloc]
                               initWithAllowlistPath:@"/nonexistent/path.plist"]
                              autorelease];
    ASSERT("bad path returns nil validator", v == nil);
}

/* ── Hardening limit tests ─────────────────────────────────────────────── */

static void testParamCountLimit(void)
{
    RequestValidator *v = makeValidator();

    /* Build a body with MAX_PARAM_COUNT + 1 pairs to trip the limit. */
    NSMutableString *body = [NSMutableString string];
    NSUInteger i;
    for (i = 0; i <= MAX_PARAM_COUNT; i++) {
        if (i > 0) [body appendString:@"&"];
        [body appendFormat:@"k%lu=v", (unsigned long)i];
    }

    NSString *reason = nil;
    NSDictionary *p = [v parseFormBody:body rejectionReason:&reason];
    ASSERT("param count limit: nil returned on overflow", p == nil);
    ASSERT("param count limit: rejection reason set", reason != nil);
}

static void testKeyLengthLimit(void)
{
    RequestValidator *v = makeValidator();

    /* Build a key one byte longer than the allowed maximum. */
    NSMutableString *longKey = [NSMutableString string];
    NSUInteger i;
    for (i = 0; i <= MAX_PARAM_KEY_LEN; i++)
        [longKey appendString:@"a"];

    NSString *body = [NSString stringWithFormat:@"%@=v", longKey];
    NSString *reason = nil;
    NSDictionary *p = [v parseFormBody:body rejectionReason:&reason];
    ASSERT("key length limit: nil returned on oversized key", p == nil);
    ASSERT("key length limit: rejection reason set", reason != nil);
}

static void testValueLengthLimit(void)
{
    RequestValidator *v = makeValidator();

    /* Build a value one byte longer than the allowed maximum. */
    NSMutableString *longVal = [NSMutableString string];
    NSUInteger j;
    for (j = 0; j <= MAX_PARAM_VALUE_LEN; j++)
        [longVal appendString:@"a"];

    NSString *body = [NSString stringWithFormat:@"k=%@", longVal];
    NSString *reason = nil;
    NSDictionary *p = [v parseFormBody:body rejectionReason:&reason];
    ASSERT("value length limit: nil returned on oversized value", p == nil);
    ASSERT("value length limit: rejection reason set", reason != nil);
}

static void testRequiredField(void)
{
    /* Build an allowlist where "action" is required. */
    NSArray *actionValues = [NSArray arrayWithObjects:@"login", @"logout", nil];
    NSDictionary *actionRule = [NSDictionary dictionaryWithObjectsAndKeys:
                                    @"values",                      @"type",
                                    actionValues,                   @"allowed",
                                    [NSNumber numberWithBool:YES],  @"required",
                                    nil];
    NSDictionary *allowlist = [NSDictionary dictionaryWithObject:actionRule
                                                          forKey:@"action"];
    RequestValidator *v = [[[RequestValidator alloc]
                               initWithAllowlist:allowlist] autorelease];

    /* Empty submission — required field absent — must be rejected. */
    NSString *reason = nil;
    BOOL r1 = [v validateParams:[NSDictionary dictionary]
                rejectionReason:&reason];
    ASSERT("required field: empty submission rejected", !r1);
    ASSERT("required field: rejection reason set", reason != nil);

    /* Submission including the required field — must be accepted. */
    BOOL r2 = [v validateParams:
                   [NSDictionary dictionaryWithObject:@"login" forKey:@"action"]
               rejectionReason:NULL];
    ASSERT("required field: present field accepted", r2);

    /* Submission with wrong value for required field — must be rejected. */
    BOOL r3 = [v validateParams:
                   [NSDictionary dictionaryWithObject:@"HACK" forKey:@"action"]
               rejectionReason:NULL];
    ASSERT("required field: bad value for required field rejected", !r3);
}

static void testRejectionReasonPropagation(void)
{
    RequestValidator *v = makeValidator();
    NSString *reason = nil;

    /* Unknown key */
    BOOL r1 = [v validateParams:
                   [NSDictionary dictionaryWithObject:@"x" forKey:@"evil"]
               rejectionReason:&reason];
    ASSERT("rejection reason: unknown key sets reason", !r1 && reason != nil);

    /* Bad value */
    reason = nil;
    BOOL r2 = [v validateParams:
                   [NSDictionary dictionaryWithObject:@"HACK" forKey:@"action"]
               rejectionReason:&reason];
    ASSERT("rejection reason: bad value sets reason", !r2 && reason != nil);
}

/* ── Entry point ───────────────────────────────────────────────────────── */

int main(int argc, const char *argv[])
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];

    testUrldecode();
    testParseFormBody();
    testValuesRule();
    testRegexRule();
    testUnknownKey();
    testEmptyParams();
    testAllParamsValid();
    testLoadFromFile();
    testNilAllowlistPath();
    testParamCountLimit();
    testKeyLengthLimit();
    testValueLengthLimit();
    testRequiredField();
    testRejectionReasonPropagation();

    fprintf(stdout, "\n%d passed, %d failed\n", g_passed, g_failed);

    [pool drain];
    return g_failed > 0 ? 1 : 0;
}
