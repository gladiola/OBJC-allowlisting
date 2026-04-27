#import "RequestValidator.h"

@implementation RequestValidator

@synthesize allowlist = _allowlist;

- (void)dealloc
{
    [_allowlist release];
    [super dealloc];
}

/* ── Initialisers ──────────────────────────────────────────────────────── */

- (instancetype)initWithAllowlistPath:(NSString *)path
{
    self = [super init];
    if (self) {
        NSDictionary *loaded = [NSDictionary dictionaryWithContentsOfFile:path];
        if (!loaded) {
            NSLog(@"RequestValidator: failed to load allowlist from '%@'", path);
            [self release];
            return nil;
        }
        _allowlist = [loaded retain];
    }
    return self;
}

- (instancetype)initWithAllowlist:(NSDictionary *)allowlist
{
    self = [super init];
    if (self) {
        _allowlist = [allowlist retain];
    }
    return self;
}

/* ── Private helpers ───────────────────────────────────────────────────── */

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
 *   - "regex":  rule[@"pattern"] is a regex; the entire value must match.
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

        NSError *error = nil;
        NSRegularExpression *regex =
            [NSRegularExpression regularExpressionWithPattern:pattern
                                                      options:0
                                                        error:&error];
        if (error || !regex) {
            NSLog(@"RequestValidator: invalid regex '%@': %@", pattern, error);
            return NO;
        }

        NSRange fullRange = NSMakeRange(0, value.length);
        NSRange match = [regex rangeOfFirstMatchInString:value
                                                options:0
                                                  range:fullRange];
        /* The regex must cover the entire value, not just a substring. */
        return (match.location == 0 && match.length == value.length);
    }

    NSLog(@"RequestValidator: unrecognised rule type '%@'", type);
    return NO;
}

/* ── Public interface ──────────────────────────────────────────────────── */

- (NSDictionary *)parseFormBody:(NSString *)body
{
    NSMutableDictionary *params = [NSMutableDictionary dictionary];

    if (!body || body.length == 0) return params;

    NSArray *pairs = [body componentsSeparatedByString:@"&"];
    for (NSString *pair in pairs) {
        if (pair.length == 0) continue;

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

        if (key.length > 0) {
            [params setObject:value forKey:key];
        }
    }

    return params;
}

- (BOOL)validateParams:(NSDictionary *)params
{
    if (!params) return NO;

    for (NSString *key in params) {
        id rule = [_allowlist objectForKey:key];
        if (!rule) {
            /* Submitted a key that is not in the allowlist — reject. */
            return NO;
        }
        NSString *value = [params objectForKey:key];
        if (![self value:value matchesRule:rule]) {
            /* Value does not satisfy its rule — reject. */
            return NO;
        }
    }

    return YES;
}

@end
