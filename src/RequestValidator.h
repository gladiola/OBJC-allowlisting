#import <Foundation/Foundation.h>

/* ── Hardening limits ─────────────────────────────────────────────────── */

/** Maximum number of key=value pairs accepted in a single request. */
#define MAX_PARAM_COUNT     64

/** Maximum byte length of a single parameter key after URL-decoding. */
#define MAX_PARAM_KEY_LEN   256

/** Maximum byte length of a single parameter value after URL-decoding. */
#define MAX_PARAM_VALUE_LEN 4096

/*
 * RequestValidator
 *
 * Parses a URL-encoded form body (POST) or query string (GET) and validates
 * every submitted key and value against a per-key allowlist rule loaded from
 * a plist configuration file.
 *
 * Plist rule format (one entry per expected key):
 *
 *   "values" rule — exact match against a fixed list:
 *     <key>action</key>
 *     <dict>
 *       <key>type</key>   <string>values</string>
 *       <key>allowed</key>
 *       <array>
 *         <string>login</string>
 *         <string>logout</string>
 *       </array>
 *       <!-- optional: require this field to be present -->
 *       <key>required</key> <true/>
 *     </dict>
 *
 *   "regex" rule — full-string match against a regular expression:
 *     <key>username</key>
 *     <dict>
 *       <key>type</key>    <string>regex</string>
 *       <key>pattern</key> <string>^[a-zA-Z0-9]{1,32}$</string>
 *       <!-- optional: require this field to be present -->
 *       <key>required</key> <true/>
 *     </dict>
 *
 * Regex patterns are compiled once at initialisation time and cached.
 * Values longer than MAX_PARAM_VALUE_LEN bytes are rejected before the
 * regex engine is invoked, bounding the exposure to catastrophic backtracking.
 */
@interface RequestValidator : NSObject {
    NSDictionary        *_allowlist;
    NSMutableDictionary *_compiledRegexes; /* pattern -> NSRegularExpression */
}

@property (nonatomic, retain) NSDictionary *allowlist;

/* Designated initialiser: loads allowlist from a plist file on disk. */
- (instancetype)initWithAllowlistPath:(NSString *)path;

/* Alternative initialiser: supply an allowlist dictionary directly (useful
   for unit tests). */
- (instancetype)initWithAllowlist:(NSDictionary *)allowlist;

/*
 * Parses a URL-encoded form body ("key=value&key2=value2") into a dictionary.
 * Keys and values are percent-decoded; '+' is treated as a space.
 * If a pair has no '=', the key maps to an empty string.
 * Duplicate keys: last one wins.
 *
 * Returns nil and sets *outReason if any hardening limit is exceeded
 * (too many parameters, key/value too long).  Pass NULL for outReason
 * if the rejection reason is not needed.
 */
- (NSDictionary *)parseFormBody:(NSString *)body
                rejectionReason:(NSString **)outReason;

/* Convenience wrapper (outReason = NULL). */
- (NSDictionary *)parseFormBody:(NSString *)body;

/*
 * Returns YES only if:
 *   - all keys in params exist in the allowlist;
 *   - every value satisfies its corresponding rule; and
 *   - every allowlist key marked "required" is present in params.
 *
 * Sets *outReason on rejection.  Pass NULL if the reason is not needed.
 */
- (BOOL)validateParams:(NSDictionary *)params
       rejectionReason:(NSString **)outReason;

/* Convenience wrapper (outReason = NULL). */
- (BOOL)validateParams:(NSDictionary *)params;

@end
