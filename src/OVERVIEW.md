# Code Overview

This directory contains a **CGI-based HTTP request allowlisting filter** written in Objective-C (manual retain/release, non-ARC). Its job: accept a web request, parse the URL-encoded parameters, and reject any request that contains an unknown key or a value that doesn't match a pre-configured rule. The allowlist is externally configured via a `.plist` file, making it easy to update rules without recompiling. Every detected attack attempt is logged to `syslog(3)` (facility `LOG_AUTH`) so events can be forwarded to a remote syslog collector.

---

## `RequestValidator.h` — Interface

### Hardening constants

| Constant | Value | Meaning |
|---|---|---|
| `MAX_PARAM_COUNT` | 64 | Maximum number of `key=value` pairs per request |
| `MAX_PARAM_KEY_LEN` | 256 | Maximum UTF-8 byte length of any parameter key |
| `MAX_PARAM_VALUE_LEN` | 4096 | Maximum UTF-8 byte length of any parameter value |

Requests that exceed any of these limits are rejected before any allowlist rule is evaluated.

### Rule types

Two allowlist rule types are loaded from a `.plist` file:

- **`values`** — the submitted value must exactly match one entry in a fixed list (e.g., `action` can only be `"login"` or `"logout"`).
- **`regex`** — the submitted value must fully match a regular expression (e.g., `username` must be alphanumeric, 1–32 chars). Patterns are **compiled once at init time** and cached in `_compiledRegexes`; a pattern that fails to compile at init is treated as permanently invalid (not retried at request time), which prevents ReDoS exposure from on-demand compilation.

Both rule types support an optional **`required`** boolean key. When set to `YES` (i.e. `<true/>`), `validateParams:rejectionReason:` rejects any submission that omits the field.

### Instance variables
- `_allowlist` (`NSDictionary *`) — the loaded plist rules.
- `_compiledRegexes` (`NSMutableDictionary *`) — maps each regex pattern string to its pre-compiled `NSRegularExpression`.

### Public methods

- `initWithAllowlistPath:` — loads the allowlist plist from disk. Returns `nil` on failure (file not found or malformed).
- `initWithAllowlist:` — accepts a dictionary directly (useful for unit tests).
- `parseFormBody:rejectionReason:` — parses a URL-encoded string into a key/value dictionary, enforcing `MAX_PARAM_COUNT`, `MAX_PARAM_KEY_LEN`, and `MAX_PARAM_VALUE_LEN`. Returns `nil` and sets `*outReason` on limit violation. Pass `NULL` for `outReason` when the reason string is not needed.
- `parseFormBody:` — convenience wrapper that passes `outReason = NULL`.
- `validateParams:rejectionReason:` — returns `YES` only when (a) every submitted key appears in the allowlist, (b) every value satisfies its rule, and (c) every `required` key is present. Sets `*outReason` on rejection.
- `validateParams:` — convenience wrapper that passes `outReason = NULL`.

---

## `RequestValidator.m` — Implementation

### `_buildCompiledRegexes` (private)
Called once by both initialisers immediately after `_allowlist` is set. Iterates every allowlist rule, and for each `"regex"` rule compiles the pattern with `NSRegularExpression` and stores the result in `_compiledRegexes` keyed by pattern string. Patterns that fail to compile are silently skipped (logged under `#ifdef DEBUG`); `value:matchesRule:` treats a missing cache entry as a permanent rejection so the regex engine is never invoked on an invalid pattern.

### `initWithAllowlistPath:` / `initWithAllowlist:`
After loading or retaining `_allowlist`, both initialisers call `_buildCompiledRegexes`. Verbose `NSLog` output (e.g. failed plist load) is gated behind `#ifdef DEBUG` to avoid leaking config paths in production.

### `urldecodeComponent:` (private)
Decodes a URL-encoded string component: replaces `+` with space, then calls `stringByRemovingPercentEncoding`.

### `value:matchesRule:` (private)
Dispatches on the rule's `"type"` key:
- `"values"` → checks `[allowed containsObject:value]`.
- `"regex"` → looks up the pre-compiled `NSRegularExpression` in `_compiledRegexes`. A missing entry (invalid pattern at init) returns `NO` immediately without attempting recompilation. The match must cover the *entire* value (not just a substring), otherwise `NO` is returned. Any unknown type also returns `NO`.

### `parseFormBody:rejectionReason:`
Splits the body on `&`, then for each `key=value` pair:
1. Increments the pair count and returns `nil` with a reason if it exceeds `MAX_PARAM_COUNT`.
2. Splits on the **first** `=` only (so base64 tokens with `=` padding aren't broken).
3. URL-decodes both key and value.
4. Applies a fast UTF-16-length pre-check followed by an exact UTF-8 byte-length check against `MAX_PARAM_KEY_LEN` and `MAX_PARAM_VALUE_LEN`; returns `nil` with a reason if either limit is exceeded.
5. Stores the key/value in the result dictionary (duplicate keys: last one wins).

### `validateParams:rejectionReason:`
Two-pass validation:
1. **Submitted keys**: for each key in `params`, verifies it exists in the allowlist and its value passes `value:matchesRule:`. Returns `NO` with a reason on the first failure.
2. **Required keys**: for each allowlist key with `required = YES`, verifies the key is present in `params`. Returns `NO` with a reason if any required key is absent.

Returns `YES` only when both passes succeed. An empty `params` dictionary passes unless a required key is defined in the allowlist.

---

## `security_headers.h` — OWASP Security Headers

Defines a single compile-time string macro, `SECURITY_HEADERS_BLOCK`, containing all ten OWASP-recommended HTTP security response headers as `\r\n`-terminated lines. Both `respond()` and the `alarm_handler()` static response string use this macro so the two code paths share one authoritative definition and can never diverge. `tests/test_validator.m` includes this header to assert that every required header line is present.

---

## `main.m` — CGI Entry Point

This is a **CGI binary**. It reads the HTTP request from the environment and stdin (as `httpd`/`slowcgi` set them up), hardens the request, and validates the parameters.

### Constants

| Constant | Value | Meaning |
|---|---|---|
| `MAX_BODY_SIZE` | 1 048 576 | Maximum accepted POST body in bytes (1 MB) |
| `POST_READ_TIMEOUT_SECS` | 30 | Seconds before a slow POST is aborted |
| `SAFE_CONFIG_DIR` | `/etc/cgi-allowlist` | Only directory allowed for allowlist plists |
| `SAFE_CONFIG_PREFIX` | `/etc/cgi-allowlist/` | Prefix used by `isConfigPathSafe()` |
| `DEFAULT_ALLOWLIST_PATH` | `/etc/cgi-allowlist/allowlist.plist` | Fallback when `ALLOWLIST_CONFIG` is unset |

### `g_remote_addr` / `cache_remote_addr()` (syslog helpers)
`g_remote_addr` is a static 64-byte buffer initialised to `"unknown"`. `cache_remote_addr()` copies `REMOTE_ADDR` into it at the start of every request. The buffer is used by both `security_log()` and `alarm_handler()` so that REMOTE_ADDR is available to the signal handler without calling the non-async-signal-safe `getenv()`.

### `security_log()` (static helper)
A `printf`-style wrapper around `syslog(3)`. Prepends `client=<REMOTE_ADDR>` to every message. Called for every detected attack event (unknown/oversized parameters, path injection, bad Content-Type, slow POST, unsupported method, allowlist rejection) using `LOG_WARNING`, and for internal failures using `LOG_ERR`. Messages are emitted to `syslog` facility `LOG_AUTH` and can be forwarded to a remote syslog collector via `/etc/syslog.conf`.

### `respond()` (static helper)
Writes a CGI-formatted HTTP response to stdout: `Status:`,
`Content-Type: text/plain; charset=utf-8`, and ten security headers drawn
from `SECURITY_HEADERS_BLOCK` (see `security_headers.h`).  The `charset=utf-8`
declaration ensures browsers correctly render the localized response body in
any of the 38 supported languages:

| Header | Value |
|---|---|
| `X-Content-Type-Options` | `nosniff` |
| `Cache-Control` | `no-store` |
| `X-Frame-Options` | `DENY` |
| `Content-Security-Policy` | `default-src 'none'` |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` |
| `Referrer-Policy` | `no-referrer` |
| `Permissions-Policy` | *(all sensitive features disabled)* |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cross-Origin-Resource-Policy` | `same-origin` |
| `X-Permitted-Cross-Domain-Policies` | `none` |

### `alarm_handler()` (SIGALRM handler)
Called when `SIGALRM` fires after `POST_READ_TIMEOUT_SECS` seconds of waiting
for stdin.  Uses only async-signal-safe functions: reads `g_remote_addr`
(pre-populated static buffer) and `g_timeout_response` (the pre-built
localized 408 response, also populated before the alarm is armed), calls
`syslog(3)`, writes the pre-built response to `STDOUT_FILENO` with `write(2)`,
then calls `_exit(1)`.  The response buffer includes the ten OWASP security
headers via `SECURITY_HEADERS_BLOCK`, so `respond()` and `alarm_handler()`
can never diverge.

### `isConfigPathSafe()` (static helper)
Returns 1 only when a config path:
1. Is non-empty.
2. Does not contain `..` anywhere.
3. Starts with `SAFE_CONFIG_PREFIX` (`/etc/cgi-allowlist/`).
4. Has at least one character after the trailing slash (i.e. is not just the directory).

### `runValidator()`
1. Opens syslog and caches `REMOTE_ADDR` (`cache_remote_addr()`).
2. **Detects locale**: calls `get_localized_strings(getenv("HTTP_ACCEPT_LANGUAGE"))` to obtain the `LocalizedStrings` pointer for the best-matching language.
3. **Pre-builds the 408 response**: calls `snprintf` to render the localized timeout body into `g_timeout_response` so the signal handler never needs to call non-async-signal-safe functions.
4. **Validates `ALLOWLIST_CONFIG`**: if the env var is set but fails `isConfigPathSafe()`, logs the path injection attempt and returns 400.
5. **OpenBSD hardening** (`#ifdef __OpenBSD__`): calls `unveil(2)` to restrict filesystem access to `SAFE_CONFIG_DIR`, then `pledge(2)` to `"stdio rpath"`. Failure is fatal (500).
6. **POST path**:
   - Rejects requests without `Content-Type: application/x-www-form-urlencoded` (415, logged).
   - Validates `CONTENT_LENGTH` (must be 0–`MAX_BODY_SIZE`; invalid values logged and rejected with 400).
   - Arms `SIGALRM` / `alarm_handler` before reading stdin; disarms it immediately after.
   - Decodes the body as UTF-8 (rejects non-UTF-8 with 400).
7. **GET path**: reads `QUERY_STRING`.
8. **Other methods**: logged and rejected with 405.
9. **Loads the allowlist** via `initWithAllowlistPath:`; failure returns 500.
10. **Parses** with `parseFormBody:rejectionReason:`; a `nil` return (limit exceeded) is logged and returns 400.
11. **Validates** with `validateParams:rejectionReason:`; rejection is logged and returns 403. Success returns 200.

All response bodies passed to `respond()` come from the `LocalizedStrings` struct selected in step 2.

---

## `i18n.h` / `i18n.c` — Multilingual Support

### `LocalizedStrings` struct (`i18n.h`)
A plain C struct with one `const char *` field per user-visible response
message (13 fields total): `ok`, `forbidden`, `request_timeout`,
`missing_request_method`, `invalid_config_path`, `internal_server_error`,
`invalid_content_type`, `missing_content_length`, `invalid_content_length`,
`body_not_utf8`, `method_not_allowed`, `allowlist_load_failed`, and
`request_too_large`.  Every field points to a UTF-8 encoded, NUL-terminated
C string literal in static storage.

### Per-locale tables (`i18n.c`)
One `static const LocalizedStrings` struct is defined for each of the
38 supported languages.  Each struct's fields are UTF-8 string literals
compiled directly into the binary.  All 494 strings (38 × 13) are
self-contained and require no runtime allocation or ICU/gettext dependency.

### Language-tag lookup table (`LANG_TABLE`)
A fixed array of `{ tag, &strings }` pairs maps lowercase BCP 47 tags to
the corresponding struct pointer.  Full subtag entries (e.g. `"zh-hk"`)
appear before their primary-subtag entry (`"zh"`) so that the most specific
match wins.  Multiple entries may point to the same struct (e.g. `"nb"`,
`"nn"`, and `"no"` all point to `NO`).

### `get_localized_strings()` (`i18n.c`)
Parses the `accept_language` string (the value of `HTTP_ACCEPT_LANGUAGE`)
according to the following algorithm:

1. Walk comma-separated language ranges in the order they appear (browsers
   send them highest-priority first).
2. For each range, strip optional `;q=…` quality value and leading/trailing
   ASCII whitespace, then lowercase the tag.
3. **Pass 1** — full tag: scan `LANG_TABLE` for an exact match.
4. **Pass 2** — primary subtag: if the tag contains `'-'`, extract the part
   before the first `'-'` and scan `LANG_TABLE` again.
5. Return the first match found; fall back to US English if no range matches.

The function is pure C, performs no heap allocation, and is safe to call in
any context.

---

## `main()` (in `main.m`)
Creates an `NSAutoreleasePool`, calls `runValidator()`, calls `closelog()`, drains the pool, and exits with `runValidator()`'s return code.
