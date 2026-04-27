/*
 * OWASP-recommended HTTP security response headers.
 *
 * Defined as a single compile-time string literal so that respond() and
 * alarm_handler() stay in perfect sync (only one definition to update) and
 * so test_validator.m can include this header and assert every required
 * header line is present.
 *
 * Reference:
 *   https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
 */
#ifndef SECURITY_HEADERS_H
#define SECURITY_HEADERS_H

#define SECURITY_HEADERS_BLOCK \
    "X-Content-Type-Options: nosniff\r\n" \
    "Cache-Control: no-store\r\n" \
    "X-Frame-Options: DENY\r\n" \
    "Content-Security-Policy: default-src 'none'\r\n" \
    "Strict-Transport-Security: max-age=63072000; includeSubDomains\r\n" \
    "Referrer-Policy: no-referrer\r\n" \
    "Permissions-Policy: accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), display-capture=(), document-domain=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), usb=(), xr-spatial-tracking=()\r\n" \
    "Cross-Origin-Opener-Policy: same-origin\r\n" \
    "Cross-Origin-Resource-Policy: same-origin\r\n" \
    "X-Permitted-Cross-Domain-Policies: none\r\n"

#endif /* SECURITY_HEADERS_H */
