#import "RequestValidator.h"

@implementation RequestValidator

@synthesize allowlist = _allowlist;

- (void)dealloc
{
    [_allowlist release];
    [_compiledRegexes release];
    [super dealloc];
}

/* ── Private helpers ───────────────────────────────────────────────────── */

/*
 * Iterates the allowlist and pre-compiles every regex pattern, storing the
 * result in _compiledRegexes keyed by pattern string.  Called once from both
 * designated initialisers so the regex engine is never invoked at request time
 * for a pattern that has already been compiled.
 */
- (void)_buildCompiledRegexes
{
    _compiledRegexes = [[NSMutableDictionary alloc] init];
    for (NSString *key in _allowlist) {
        id rule = [_allowlist objectForKey:key];
        if (![rule isKindOfClass:[NSDictionary class]]) continue;
        NSDictionary *ruleDict = (NSDictionary *)rule;
        if (![[ruleDict objectForKey:@"type"] isEqualToString:@"regex"]) continue;
        NSString *pattern = [ruleDict objectForKey:@"pattern"];
        if (![pattern isKindOfClass:[NSString class]]) continue;
        NSError *err = nil;
        NSRegularExpression *regex =
            [NSRegularExpression regularExpressionWithPattern:pattern
                                                      options:0
                                                        error:&err];
        if (regex && !err) {
            [_compiledRegexes setObject:regex forKey:pattern];
        } else {
#ifdef DEBUG
            NSLog(@"RequestValidator: failed to compile regex '%@': %@",
                  pattern, err);
#endif
        }
    }
}

/* ── Initialisers ──────────────────────────────────────────────────────── */

- (instancetype)initWithAllowlistPath:(NSString *)path
{
    self = [super init];
    if (self) {
        NSDictionary *loaded = [NSDictionary dictionaryWithContentsOfFile:path];
        if (!loaded) {
#ifdef DEBUG
            NSLog(@"RequestValidator: failed to load allowlist from '%@'", path);
#endif
            [self release];
            return nil;
        }
        _allowlist = [loaded retain];
        [self _buildCompiledRegexes];
    }
    return self;
}

- (instancetype)initWithAllowlist:(NSDictionary *)allowlist
{
    self = [super init];
    if (self) {
        _allowlist = [allowlist retain];
        [self _buildCompiledRegexes];
    }
    return self;
}

/*
 * Decodes a single URL-encoded component: replaces '+' with space, then
 * decodes percent-encoded sequences (%XX).
 */
- (NSString *)urldecodeComponent:(NSString *)encoded
{
    if (!encoded) return @"";
    NSString *plusReplaced = [encoded stringByReplacingOccurrencesOfString:@"+"
                                                                withString:@" "];
    NSString *decoded = [plusReplaced stringByRemovingPercentEncoding];
    return decoded ? decoded : @"";
}

/*
 * Tests whether value satisfies rule.
 *
 * rule must be an NSDictionary with key "type" == "values" or "regex":
 *   - "values": rule[@"allowed"] is an NSArray of accepted strings.
 *   - "regex":  rule[@"pattern"] is looked up in the pre-compiled cache;
 *               the entire value must match (not just a substring).
 *
 * Returns NO for any malformed or unrecognised rule.
 */
- (BOOL)value:(NSString *)value matchesRule:(id)rule
{
    if (!value || !rule) return NO;

    if (![rule isKindOfClass:[NSDictionary class]]) return NO;

    NSDictionary *ruleDict = (NSDictionary *)rule;
    NSString *type = [ruleDict objectForKey:@"type"];

    if ([type isEqualToString:@"values"]) {
        id allowed = [ruleDict objectForKey:@"allowed"];
        if (![allowed isKindOfClass:[NSArray class]]) return NO;
        return [(NSArray *)allowed containsObject:value];
    }

    if ([type isEqualToString:@"regex"]) {
        NSString *pattern = [ruleDict objectForKey:@"pattern"];
        if (![pattern isKindOfClass:[NSString class]]) return NO;

        /*
         * Use the pre-compiled regex from the cache.  A missing entry means
         * the pattern was invalid at init time and should be treated as a
         * misconfigured rule; reject rather than attempting to recompile at
         * request time (which would negate the ReDoS mitigation).
         */
        NSRegularExpression *regex = [_compiledRegexes objectForKey:pattern];
        if (!regex) return NO;

        NSRange fullRange = NSMakeRange(0, value.length);
        NSRange match = [regex rangeOfFirstMatchInString:value
                                                 options:0
                                                   range:fullRange];
        /* The regex must cover the entire value, not just a substring. */
        return (match.location == 0 && match.length == value.length);
    }

#ifdef DEBUG
    NSLog(@"RequestValidator: unrecognised rule type '%@'", type);
#endif
    return NO;
}

/* ── Public interface ──────────────────────────────────────────────────── */

- (NSDictionary *)parseFormBody:(NSString *)body
                rejectionReason:(NSString **)outReason
{
    NSMutableDictionary *params = [NSMutableDictionary dictionary];

    if (!body || body.length == 0) return params;

    NSArray *pairs = [body componentsSeparatedByString:@"&"];
    NSUInteger pairCount = 0;

    for (NSString *pair in pairs) {
        if (pair.length == 0) continue;

        pairCount++;
        if (pairCount > MAX_PARAM_COUNT) {
            if (outReason)
                *outReason = [NSString stringWithFormat:
                    @"too many parameters (limit %d)", MAX_PARAM_COUNT];
            return nil;
        }

        /* Split on the *first* '=' only so base64/token values work. */
        NSRange eqRange = [pair rangeOfString:@"="];
        NSString *rawKey, *rawValue;

        if (eqRange.location != NSNotFound) {
            rawKey   = [pair substringToIndex:eqRange.location];
            rawValue = [pair substringFromIndex:eqRange.location + 1];
        } else {
            rawKey   = pair;
            rawValue = @"";
        }

        NSString *key   = [self urldecodeComponent:rawKey];
        NSString *value = [self urldecodeComponent:rawValue];

        if (key.length == 0) continue;

        /*
         * Fast-path: each UTF-16 code unit produces at least one UTF-8 byte,
         * so key.length > MAX_PARAM_KEY_LEN implies the byte length also
         * exceeds the limit.  The full byte-length check handles cases where
         * a shorter code-unit count still exceeds the limit in UTF-8.
         */
        if (key.length > MAX_PARAM_KEY_LEN ||
            [key lengthOfBytesUsingEncoding:NSUTF8StringEncoding] > MAX_PARAM_KEY_LEN) {
            if (outReason)
                *outReason = [NSString stringWithFormat:
                    @"parameter key exceeds %d-byte limit", MAX_PARAM_KEY_LEN];
            return nil;
        }

        if (value.length > MAX_PARAM_VALUE_LEN ||
            [value lengthOfBytesUsingEncoding:NSUTF8StringEncoding] > MAX_PARAM_VALUE_LEN) {
            if (outReason)
                *outReason = [NSString stringWithFormat:
                    @"value for key '%@' exceeds %d-byte limit", key, MAX_PARAM_VALUE_LEN];
            return nil;
        }

        [params setObject:value forKey:key];
    }

    return params;
}

- (NSDictionary *)parseFormBody:(NSString *)body
{
    return [self parseFormBody:body rejectionReason:NULL];
}

- (BOOL)validateParams:(NSDictionary *)params
       rejectionReason:(NSString **)outReason
{
    if (!params) {
        if (outReason) *outReason = @"nil params dictionary";
        return NO;
    }

    /* Verify every submitted key is in the allowlist and its value passes. */
    for (NSString *key in params) {
        id rule = [_allowlist objectForKey:key];
        if (!rule) {
            if (outReason)
                *outReason = [NSString stringWithFormat:
                    @"unknown parameter key '%@'", key];
            return NO;
        }
        NSString *value = [params objectForKey:key];
        if (![self value:value matchesRule:rule]) {
            if (outReason)
                *outReason = [NSString stringWithFormat:
                    @"value for key '%@' failed allowlist rule", key];
            return NO;
        }
    }

    /* Verify all required allowlist keys are present in the submission. */
    for (NSString *key in _allowlist) {
        id rule = [_allowlist objectForKey:key];
        if (![rule isKindOfClass:[NSDictionary class]]) continue;
        id requiredVal = [(NSDictionary *)rule objectForKey:@"required"];
        if ([requiredVal isKindOfClass:[NSNumber class]] &&
            [(NSNumber *)requiredVal boolValue]) {
            if (![params objectForKey:key]) {
                if (outReason)
                    *outReason = [NSString stringWithFormat:
                        @"required parameter '%@' is missing", key];
                return NO;
            }
        }
    }

    return YES;
}

- (BOOL)validateParams:(NSDictionary *)params
{
    return [self validateParams:params rejectionReason:NULL];
}

@end
