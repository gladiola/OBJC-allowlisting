# OBJC-allowlisting

An Objective-C CGI program for OpenBSD that allowlists the keys **and** values
of every HTTPS form submission before the request reaches your application.
It is designed to run under OpenBSD's `httpd(8)` (via `slowcgi(8)`) and sits
behind an optional `relayd(8)` TLS relay.

## How it works

1. `httpd` receives a POST (or GET) request and hands it to `request_validator`
   through the CGI interface provided by `slowcgi`.
2. The validator caches the client IP (`REMOTE_ADDR`) for use in all subsequent
   log messages.
3. On OpenBSD, `unveil(2)` restricts filesystem access to `/etc/cgi-allowlist`
   only, and `pledge(2)` drops all syscall capabilities except `stdio` and
   `rpath`.
4. The validator checks the `ALLOWLIST_CONFIG` environment variable.  If set,
   it must point inside `/etc/cgi-allowlist/` and must not contain `..`;
   violations are rejected with 400 and logged.
5. POST requests must declare media type
   `application/x-www-form-urlencoded` (exactly, case-insensitive), with only
   syntactically valid optional parameters (for example `; charset=UTF-8`), or
   the request is rejected with 415 and logged.  A 30-second alarm timer
   ensures a slow or stalled POST client cannot tie up the process indefinitely.
6. The raw body (POST) or query string (GET) is parsed into `key=value` pairs.
   Requests exceeding any of the following hard limits are rejected with 400
   and logged:
   - More than **64 parameters** per request
   - Any parameter key longer than **256 bytes**
   - Any parameter value longer than **4096 bytes**
7. Every submitted key is checked against an allowlist loaded from a plist file.
   Each key has one of two rule types:
   - **`values`** — the submitted value must be one of a fixed list of strings.
   - **`regex`** — the submitted value must fully match a regular expression.
     Patterns are pre-compiled at startup and cached; a value that exceeds the
     size limit is never sent to the regex engine, bounding ReDoS exposure.
   - **`required`** — an optional boolean that, when set to `YES`, causes
     `validateParams:` to reject requests that omit the field entirely.
8. If all keys and values pass, the validator returns `200 OK`; otherwise it
   returns `403 Forbidden`.  Any key not present in the allowlist is rejected.
9. Every detected attack attempt (unknown key, oversized parameter, path
   injection, bad Content-Type, slow POST, unsupported method) is logged,
   including the client IP address.  Standard request-path events use
   `syslog(3)` to facility `LOG_AUTH` at `LOG_WARNING`; the timeout signal path
   emits a fixed, prebuilt line via async-signal-safe `write(2)` to stderr.
   Log-bound text is control-character-sanitized before emission.  Syslog
   messages can be forwarded to a remote collector via `/etc/syslog.conf`.
10. Every response includes security headers: `X-Content-Type-Options: nosniff`,
     `Cache-Control: no-store`, and `X-Frame-Options: DENY`.

## Security review (2026-05-12)

### Scope and method

- Reviewed:
  - `/home/runner/work/OBJC-allowlisting/OBJC-allowlisting/src/main.m`
  - `/home/runner/work/OBJC-allowlisting/OBJC-allowlisting/src/RequestValidator.m`
  - `/home/runner/work/OBJC-allowlisting/OBJC-allowlisting/src/security_headers.h`
  - `/home/runner/work/OBJC-allowlisting/OBJC-allowlisting/src/i18n.c`
  - `/home/runner/work/OBJC-allowlisting/OBJC-allowlisting/config/httpd.conf.example`
  - `/home/runner/work/OBJC-allowlisting/OBJC-allowlisting/config/relayd.conf.example`
- Attempted baseline test run: `make test` (failed in this environment because GNUstep Objective-C toolchain is not installed: missing `gnustep-config` / `cc1obj`).

### Security strengths observed

- Strict allowlist model: unknown keys are rejected and values are constrained by exact-list or full-regex rules.
- Request hardening limits are enforced (parameter count, key/value byte sizes, max POST body size, POST read timeout).
- OpenBSD sandboxing is used (`unveil` + `pledge`) when compiled on OpenBSD.
- Security headers are centrally defined and reused by both normal and timeout response paths.
- Security-relevant events are logged with source IP context.

### Findings

| Severity | Finding | Evidence | Risk |
|---|---|---|---|
| Medium | POST `Content-Type` validation is prefix-based, not exact. | `src/main.m`: `strncasecmp(ct, "application/x-www-form-urlencoded", ...)` | Values like `application/x-www-form-urlencoded-malicious` can pass validation unexpectedly. |
| Medium | `SIGALRM` handler uses `syslog()`, which is not async-signal-safe. | `src/main.m` `alarm_handler()` calls `syslog(...)` | Can cause undefined behavior or deadlock during timeout handling (availability risk). |
| Low | Rejection reasons include user-controlled parameter keys and are logged without newline sanitization. | `src/RequestValidator.m` builds reasons with `'%@'` key; `src/main.m` logs reason text | Crafted keys may enable log-forging/multiline log injection in some logging pipelines. |

### Recommended remediation order

1. Replace prefix-based content-type check with strict media-type parsing (allowing optional parameters like `; charset=UTF-8` safely).
2. Make timeout signal path fully async-signal-safe (remove `syslog()` from signal handler; log outside handler or via safer design).
3. Sanitize log-bound strings (strip/escape CR/LF and other control characters before logging user-derived values).

### Residual risk and operational notes

- Security posture is generally strong for an allowlisting gate, especially with bounded parsing and OpenBSD hardening hooks.
- Final confidence should include running the full test suite in a GNUstep-capable environment and adding regression tests for the findings above once fixed.

### Follow-up security review (post-remediation, 2026-05-12)

| Severity | Original finding | Remediation status | Updated behavior |
|---|---|---|---|
| Medium | Prefix-based POST `Content-Type` check accepted type-like prefixes. | Fixed | Parser now requires exact media type `application/x-www-form-urlencoded` with optional syntactically valid parameters only. |
| Medium | `SIGALRM` handler called `syslog()`, which is not async-signal-safe. | Fixed | Signal handler now uses only async-signal-safe operations (`write(2)`, `_exit(1)`) and emits a prebuilt timeout log line to stderr. |
| Low | User-controlled rejection strings could inject control characters into logs. | Fixed | Central logging path now sanitizes control characters from log-bound text before emission. |

Follow-up conclusion: all findings from the 2026-05-12 review are remediated in code, with no remaining open items from that review.

## Repository layout

```
src/
  RequestValidator.h   — class interface (constants, rule format, method docs)
  RequestValidator.m   — URL-decode, form-parse, validate, regex cache logic
  main.m               — CGI entry point (syslog, path check, alarm, pledge/unveil)
  i18n.h               — LocalizedStrings struct and get_localized_strings() declaration
  i18n.c               — 38-language translation table and Accept-Language detection
  OVERVIEW.md          — detailed per-symbol documentation
config/
  allowlist.plist.example   — annotated allowlist template
  httpd.conf.example        — OpenBSD httpd server block (three locations)
  relayd.conf.example       — relayd TLS relay forwarding to httpd
tests/
  test_validator.m          — standalone test runner (no XCTest required)
  README.md                 — per-test-group documentation
  fixtures/
    test_allowlist.plist    — plist used by the test suite
Makefile
```

## Prerequisites

Install GNUstep on OpenBSD using the package manager (same as
[gladiola/OBJC-codespaces](https://github.com/gladiola/OBJC-codespaces)):

```sh
pkg_add gnustep-make gnustep-base libobjc2
```

## Building

```sh
make
```

This compiles `src/main.m`, `src/RequestValidator.m`, and `src/i18n.c` using
`cc` with the GNUstep and libobjc2 flags and produces the `request_validator`
executable in the repository root.

## Multilingual support

All user-facing response bodies (status messages, error descriptions) are
delivered in the language that best matches the browser's `Accept-Language`
request header.  Thirty-eight languages are supported out of the box:

| Language tag(s) | Language |
|---|---|
| `en` | US English (default / fallback) |
| `de` | German |
| `es` | Spanish |
| `fr` | French |
| `pt` | Portuguese |
| `it` | Italian |
| `zh-HK`, `zh-TW`, `zh-MO` | Hong Kong / Traditional Chinese |
| `zh`, `zh-CN`, `zh-SG` | Mandarin / Simplified Chinese |
| `ko` | Korean |
| `hi` | Hindi |
| `ru` | Russian |
| `ar` | Arabic |
| `sw` | Swahili |
| `ja` | Japanese |
| `ht` | Haitian Creole |
| `haw` | Hawaiian |
| `sm` | Samoan |
| `mi` | Māori |
| `af` | Afrikaans |
| `nl` | Dutch |
| `ha` | Hausa |
| `am` | Amharic |
| `yo` | Yoruba |
| `bn` | Bengali |
| `et` | Estonian |
| `fi` | Finnish |
| `sv` | Swedish |
| `no`, `nb`, `nn` | Norwegian |
| `uk` | Ukrainian |
| `th` | Thai |
| `id` | Bahasa Indonesia |
| `tl` | Tagalog |
| `ms` | Malay |
| `jv` | Javanese |
| `el` | Greek |
| `la` | Latin |
| `he` | Hebrew |
| `ga` | Irish |

Language detection is handled by `src/i18n.c`.  It reads the
`HTTP_ACCEPT_LANGUAGE` CGI environment variable (the browser's
`Accept-Language` header), works through each comma-separated language
range in preference order, and returns the first match.  Both full tags
(`zh-HK`) and primary subtags (`zh`) are tried for each range, so region
variants fall back gracefully to the base language.  US English is used when
no language matches or the header is absent.

All responses are sent with `Content-Type: text/plain; charset=utf-8` to
ensure correct rendering of non-ASCII characters in every supported locale.

## Running the tests

```sh
make test
```

Expected output (all tests passing):

```
PASS: urldecode: '+' becomes space
PASS: urldecode: %69 → 'i'
...
39 passed, 0 failed
```

## Cleaning

```sh
make clean
```

## Configuration

### Allowlist plist

Copy `config/allowlist.plist.example` to
`/etc/cgi-allowlist/<endpoint>.plist` and edit to match your form fields.

```xml
<dict>
    <!-- exact-match rule -->
    <key>action</key>
    <dict>
        <key>type</key>    <string>values</string>
        <key>allowed</key>
        <array>
            <string>login</string>
            <string>logout</string>
        </array>
        <!-- optional: reject submissions that omit this field -->
        <key>required</key> <true/>
    </dict>

    <!-- regex rule (entire value must match) -->
    <key>username</key>
    <dict>
        <key>type</key>    <string>regex</string>
        <key>pattern</key> <string>^[a-zA-Z0-9]{1,32}$</string>
    </dict>
</dict>
```

### Environment variable

| Variable           | Default                              | Description                        |
|--------------------|--------------------------------------|------------------------------------|
| `ALLOWLIST_CONFIG` | `/etc/cgi-allowlist/allowlist.plist` | Path to the allowlist plist file.  Must be absolute, under `/etc/cgi-allowlist/`, and contain no `..` components. |

Set this per-location inside `httpd.conf` using `fastcgi { param … }` so each
endpoint loads its own ruleset (see `config/httpd.conf.example`).

### Remote syslog forwarding

All attack-event log lines are written to `syslog` facility `LOG_AUTH`.  To
forward them to a remote syslog collector, add a rule to `/etc/syslog.conf`:

```
auth.warning    @logs.example.com
```

Then reload syslogd:

```sh
rcctl reload syslogd
```

Each log line includes the client IP address (`client=<REMOTE_ADDR>`) and a
human-readable description of the rejection, for example:

```
request_validator[1234]: client=203.0.113.5 request rejected by allowlist: unknown parameter key 'evil'
request_validator[1235]: client=203.0.113.5 POST with unexpected or missing Content-Type: 'text/html'
request_validator[1236]: client=203.0.113.5 path injection attempt via ALLOWLIST_CONFIG='/etc/passwd'
```

## Installing

```sh
make install   # copies request_validator to /var/www/cgi-bin/
```

Then enable `slowcgi` so httpd can execute CGI programs:

```sh
rcctl enable slowcgi
rcctl start  slowcgi
```

See `config/httpd.conf.example` and `config/relayd.conf.example` for full
server configuration examples.

## Adding a new endpoint

Follow these three steps each time you want to protect a new page/form.

### Step 1 — Create the allowlist plist

Create a new plist file under `/etc/cgi-allowlist/` named after your endpoint.
For example, to protect a contact form at `/contact`:

```sh
cp config/allowlist.plist.example /etc/cgi-allowlist/contact.plist
$EDITOR /etc/cgi-allowlist/contact.plist
```

Edit the file so it lists **only** the fields your form submits.  Delete any
entries you don't need and add new ones.  There are two rule types:

**`values` — exact match against a fixed list**

Use this when a field must be one of a small set of known strings (e.g. a
hidden `action` field or a radio-button choice):

```xml
<key>subject</key>
<dict>
    <key>type</key>
    <string>values</string>
    <key>allowed</key>
    <array>
        <string>sales</string>
        <string>support</string>
        <string>billing</string>
    </array>
</dict>
```

**`regex` — full-string regular expression match**

Use this for free-form text fields.  The pattern must match the **entire**
submitted value (anchoring with `^` and `$` is required):

```xml
<key>email</key>
<dict>
    <key>type</key>
    <string>regex</string>
    <key>pattern</key>
    <string>^[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,255}$</string>
</dict>

<key>message</key>
<dict>
    <key>type</key>
    <string>regex</string>
    <!-- printable ASCII, 1–1000 characters -->
    <key>pattern</key>
    <string>^[ -~]{1,1000}$</string>
</dict>
```

**`required` — make a field mandatory**

Add `<key>required</key> <true/>` to any rule to reject requests that do not
include that field at all:

```xml
<key>action</key>
<dict>
    <key>type</key>    <string>values</string>
    <key>allowed</key>
    <array><string>submit</string></array>
    <key>required</key> <true/>
</dict>
```

> **Important:** every field your HTML form can submit must have an entry in
> the plist.  Any key not listed is automatically rejected with 403 Forbidden.

### Step 2 — Add a `location` block to httpd.conf

Open `/etc/httpd.conf` and add a `location` block for the new path.  Point the
`ALLOWLIST_CONFIG` param at the plist you just created:

```
location "/contact" {
    root    "/cgi-bin"
    fastcgi {
        socket  "/run/slowcgi.sock"
        param   ALLOWLIST_CONFIG "/etc/cgi-allowlist/contact.plist"
    }
}
```

Place this block inside the relevant `server { }` stanza, before any catch-all
`location "/*"` block.

### Step 3 — Reload httpd and verify

```sh
rcctl reload httpd
```

Test a valid submission (should return `200 OK`):

```sh
curl -s -o /dev/null -w "%{http_code}" \
     -X POST https://example.com/contact \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "subject=sales&email=user@example.com&message=Hello"
# → 200
```

Test a rejected submission — unexpected key or bad value (should return
`403 Forbidden`):

```sh
curl -s -o /dev/null -w "%{http_code}" \
     -X POST https://example.com/contact \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "subject=sales&evil=<script>alert(1)</script>"
# → 403
```
