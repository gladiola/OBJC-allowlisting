/*
 * i18n.h — Multilingual response strings for request_validator.
 *
 * Supports 38 languages detected from the HTTP_ACCEPT_LANGUAGE CGI
 * environment variable (the browser's Accept-Language request header).
 * Falls back to US-English when no supported language matches.
 *
 * Usage:
 *   #include "i18n.h"
 *   const LocalizedStrings *ls =
 *       get_localized_strings(getenv("HTTP_ACCEPT_LANGUAGE"));
 *   respond(200, "OK", ls->ok);
 */

#ifndef I18N_H
#define I18N_H

/*
 * All user-visible response body strings for one locale.
 * Every field is a NUL-terminated, UTF-8 encoded C string.
 */
typedef struct {
    const char *ok;
    const char *forbidden;
    const char *request_timeout;
    const char *missing_request_method;
    const char *invalid_config_path;
    const char *internal_server_error;
    const char *invalid_content_type;
    const char *missing_content_length;
    const char *invalid_content_length;
    const char *body_not_utf8;
    const char *method_not_allowed;
    const char *allowlist_load_failed;
    const char *request_too_large;
} LocalizedStrings;

/*
 * Returns a pointer to a static LocalizedStrings for the best-matching
 * language found in accept_language (the value of the HTTP_ACCEPT_LANGUAGE
 * CGI variable, e.g. "fr-FR,fr;q=0.9,en;q=0.8").
 *
 * Matching is case-insensitive and honours the BCP 47 primary subtag
 * fallback: "zh-HK" matches the zh-HK (Traditional Chinese) entry before
 * falling back to the zh (Simplified Chinese) entry.  If no supported
 * language is found, or if accept_language is NULL, US-English is returned.
 *
 * The returned pointer is always non-NULL and points to static storage;
 * it must not be freed.
 */
const LocalizedStrings *get_localized_strings(const char *accept_language);

#endif /* I18N_H */
