# OBJC-allowlisting

An Objective-C CGI program for OpenBSD that allowlists the keys **and** values
of every HTTPS form submission before the request reaches your application.
It is designed to run under OpenBSD's `httpd(8)` (via `slowcgi(8)`) and sits
behind an optional `relayd(8)` TLS relay.

## How it works

1. `httpd` receives a POST (or GET) request and hands it to `request_validator`
   through the CGI interface provided by `slowcgi`.
2. The validator reads the request body from `stdin` (POST) or `QUERY_STRING`
   (GET) and URL-decodes each `key=value` pair.
3. Every submitted key is checked against an allowlist loaded from a plist file.
   Each key has one of two rule types:
   - **`values`** — the submitted value must be one of a fixed list of strings.
   - **`regex`** — the submitted value must fully match a regular expression.
4. If all keys and values pass, the validator returns `200 OK`; otherwise it
   returns `403 Forbidden`.  Any key not present in the allowlist is rejected.

## Repository layout

```
src/
  RequestValidator.h   — class interface
  RequestValidator.m   — URL-decode, form-parse, and validate logic
  main.m               — CGI entry point (reads env/stdin, calls validator)
config/
  allowlist.plist.example   — annotated allowlist template
  httpd.conf.example        — OpenBSD httpd server block (three locations)
  relayd.conf.example       — relayd TLS relay forwarding to httpd
tests/
  test_validator.m          — standalone test runner (no XCTest required)
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

This compiles `src/main.m` and `src/RequestValidator.m` using `cc` with the
GNUstep and libobjc2 flags and produces the `request_validator` executable in
the repository root.

## Running the tests

```sh
make test
```

Expected output (all tests passing):

```
PASS: urldecode: '+' becomes space
PASS: urldecode: %69 → 'i'
...
20 passed, 0 failed
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
| `ALLOWLIST_CONFIG` | `/etc/cgi-allowlist/allowlist.plist` | Path to the allowlist plist file.  |

Set this per-location inside `httpd.conf` using `fastcgi { param … }` so each
endpoint loads its own ruleset (see `config/httpd.conf.example`).

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
