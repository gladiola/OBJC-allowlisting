# Code Overview

This directory contains a **CGI-based HTTP request allowlisting filter** written in Objective-C (manual retain/release, non-ARC). Its job: accept a web request, parse the URL-encoded parameters, and reject any request that contains an unknown key or a value that doesn't match a pre-configured rule. The allowlist is externally configured via a `.plist` file, making it easy to update rules without recompiling.

---

## `RequestValidator.h` — Interface

Declares the `RequestValidator` class, which validates URL-encoded form submissions against a configuration-driven allowlist. The header documents two allowlist rule types, loaded from a `.plist` file:

- **`values`** — the submitted value must exactly match one entry in a fixed list (e.g., `action` can only be `"login"` or `"logout"`).
- **`regex`** — the submitted value must fully match a regular expression (e.g., `username` must be alphanumeric, 1–32 chars).

Two public methods are declared:
- `parseFormBody:` — parses a URL-encoded string into a key/value dictionary.
- `validateParams:` — checks every key/value against the allowlist rules.

---

## `RequestValidator.m` — Implementation

### Initializers
- `initWithAllowlistPath:` — loads the plist from disk using `NSDictionary dictionaryWithContentsOfFile:`. Returns `nil` on failure.
- `initWithAllowlist:` — accepts a dictionary directly (handy for unit tests).

### `urldecodeComponent:` (private)
Decodes a URL-encoded string component: replaces `+` with space, then calls `stringByRemovingPercentEncoding`.

### `value:matchesRule:` (private)
Dispatches on the rule's `"type"` key:
- `"values"` → checks `[allowed containsObject:value]`
- `"regex"` → compiles the pattern with `NSRegularExpression` and checks that the match covers the *entire* value (not just a substring). Any unknown type returns `NO`.

### `parseFormBody:`
Splits the body on `&`, then for each `key=value` pair splits on the **first** `=` only (so base64 tokens with `=` padding aren't broken), URL-decodes both sides, and stores them in a mutable dictionary. Duplicate keys: last one wins.

### `validateParams:`
Iterates over every submitted key. If any key is absent from the allowlist, or its value fails the rule, the whole request is rejected (`NO`). An empty params dict returns `YES`.

---

## `main.m` — CGI Entry Point

This is a **CGI binary**. It reads the HTTP request from the environment and stdin (as a web server would set them up), then validates the parameters.

### `respond()` (static helper)
Writes a CGI-formatted HTTP response (`Status:`, `Content-Type:`, blank line, body) to stdout.

### `runValidator()`
1. **Reads `REQUEST_METHOD`** from the environment.
2. **POST path**: reads `CONTENT_LENGTH`, caps it at 1 MB (`MAX_BODY_SIZE`), reads that many bytes from stdin, and decodes as UTF-8.
3. **GET path**: reads the form data from `QUERY_STRING`.
4. **Loads the allowlist** from the path in `ALLOWLIST_CONFIG` env var, or falls back to `/etc/cgi-allowlist/allowlist.plist`.
5. **Parses and validates** the params using `RequestValidator`. Returns `200 OK` on success, `403 Forbidden` on rejection.

### `main()`
Standard Objective-C manual-retain-release pattern: creates an `NSAutoreleasePool`, runs `runValidator()`, drains the pool, and exits.
