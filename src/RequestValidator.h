#import <Foundation/Foundation.h>

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
 *     </dict>
 *
 *   "regex" rule — full-string match against a regular expression:
 *     <key>username</key>
 *     <dict>
 *       <key>type</key>    <string>regex</string>
 *       <key>pattern</key> <string>^[a-zA-Z0-9]{1,32}$</string>
 *     </dict>
 */
@interface RequestValidator : NSObject {
    NSDictionary *_allowlist;
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
 */
- (NSDictionary *)parseFormBody:(NSString *)body;

/*
 * Returns YES only if every key in params exists in the allowlist and every
 * value satisfies its corresponding rule.  An empty params dictionary is
 * considered valid (nothing submitted, nothing to reject).
 */
- (BOOL)validateParams:(NSDictionary *)params;

@end
