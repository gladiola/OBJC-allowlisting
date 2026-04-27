# Test Suite Overview

Tests live in `tests/test_validator.m` and exercise `RequestValidator` (declared in `src/RequestValidator.h`).

---

## Test Framework

A minimal custom framework — two global counters (`g_passed`, `g_failed`) and an `ASSERT(desc, expr)` macro that increments the appropriate counter and prints `PASS`/`FAIL` to stdout/stderr.

---

## Shared Setup

Two helpers build consistent test inputs used across most tests:

- **`makeTestAllowlist()`** — constructs an `NSDictionary` allowlist with three rules:
  - `action`: must be one of `login`, `logout`, `submit` (values rule)
  - `username`: must match `^[a-zA-Z0-9]{1,32}$` (regex rule)
  - `token`: must match `^[0-9a-fA-F]{64}$` (regex rule)
- **`makeValidator()`** — creates a `RequestValidator` using the above allowlist.

---

## Test Groups

### 1. `testUrldecode`
Tests URL-decoding behavior inside `parseFormBody:`:
- `+` is decoded as a space (`hello+world` → `hello world`)
- `%XX` sequences are decoded (`%69` → `i`, so `log%69n` → `login`)
- `%2B` is a literal `+`, **not** a space (`a%2Bb` → `a+b`)

### 2. `testParseFormBody`
Tests the form-body parser:
- Single `key=value` pair is parsed correctly
- Multiple `&`-separated pairs are all captured
- A value containing `=` (e.g. base64 padding `abc=def`) is handled — only the **first** `=` splits key from value
- A key with an empty value (`action=`) gives an empty string, not nil
- Empty body → empty dictionary
- `nil` body → empty dictionary

### 3. `testValuesRule`
Tests the `values` rule type on the `action` parameter:
- `login` is accepted (it's in the allowlist)
- `DELETE` is rejected (not in the allowlist)

### 4. `testRegexRule`
Tests the `regex` rule type:
- `alice123` passes the username regex
- A 33-character username fails (max is 32)
- A username with a space fails
- A valid 64-character hex string passes the token regex
- A short hex string (`deadbeef`) fails the token regex

### 5. `testUnknownKey`
Tests that **keys not present in the allowlist are rejected**:
- A parameter named `evil` (not in allowlist) is rejected
- A mix of a valid key (`action=login`) and an unknown key (`evil`) is also rejected

### 6. `testEmptyParams`
An empty parameter dictionary (no keys at all) is **accepted** — nothing to validate, nothing to reject.

### 7. `testAllParamsValid`
A request with all three valid parameters at once (`action=submit`, `username=Bob42`, `token=000...000`) is accepted.

### 8. `testLoadFromFile`
Tests the `initWithAllowlistPath:` initializer using the fixture file at `tests/fixtures/test_allowlist.plist`:
- The validator is created successfully (non-nil)
- `action=login` is accepted
- `action=HACK` is rejected

The fixture file is a GNUstep-format XML plist with the same three rules as `makeTestAllowlist()`.

### 9. `testNilAllowlistPath`
Tests that passing a non-existent path to `initWithAllowlistPath:` returns `nil` — the initializer fails gracefully.

---

## Entry Point

`main()` runs all nine test groups in sequence, then prints a summary (`X passed, Y failed`) and exits with code `1` if any test failed, `0` otherwise.

---

## Fixtures

`tests/fixtures/test_allowlist.plist` — a GNUstep XML plist used by `testLoadFromFile` to verify that allowlists can be loaded from disk. It defines the same `action`, `username`, and `token` rules as the in-memory allowlist.
