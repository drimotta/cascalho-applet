#include "http.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

static char *dup_range(const char *s, size_t n) {
    char *out = malloc(n + 1);
    if (!out) return NULL;
    memcpy(out, s, n);
    out[n] = '\0';
    return out;
}

static const char *find_crlf(const char *s, const char *end) {
    for (const char *p = s; p + 1 < end; p++)
        if (p[0] == '\r' && p[1] == '\n') return p;
    return NULL;
}

static void trim(const char **start, const char **end) {
    while (*start < *end && (**start == ' ' || **start == '\t')) (*start)++;
    while (*end > *start && ((*end)[-1] == ' ' || (*end)[-1] == '\t')) (*end)--;
}

/* Content-Length: digits only, no sign, no overflow. */
static int parse_length(const char *v, long *out) {
    if (!*v) return 0;
    long n = 0;
    for (; *v; v++) {
        if (!isdigit((unsigned char)*v)) return 0;
        if (n > HTTP_MAX_BODY) return 1; /* already too large; keep it so */
        n = n * 10 + (*v - '0');
    }
    *out = n;
    return 1;
}

void http_request_free(http_request *req) {
    free(req->method);
    free(req->path);
    for (size_t i = 0; i < req->header_count; i++) {
        free(req->headers[i].name);
        free(req->headers[i].value);
    }
    free(req->body);
    memset(req, 0, sizeof *req);
}

const char *http_header(const http_request *req, const char *name) {
    for (size_t i = 0; i < req->header_count; i++)
        if (strcasecmp(req->headers[i].name, name) == 0) return req->headers[i].value;
    return NULL;
}

int http_parse(const char *raw, size_t len, http_request *req) {
    memset(req, 0, sizeof *req);
    const char *end = raw + len;
    const char *head_end = NULL;
    for (const char *p = raw; p + 3 < end; p++)
        if (memcmp(p, "\r\n\r\n", 4) == 0) {
            head_end = p;
            break;
        }
    if (!head_end) return len > HTTP_MAX_HEAD ? HTTP_TOO_LARGE : HTTP_INCOMPLETE;
    if ((size_t)(head_end - raw) > HTTP_MAX_HEAD) return HTTP_TOO_LARGE;

    /* Request line: METHOD SP /path SP HTTP/1.1 */
    const char *line_end = find_crlf(raw, head_end + 2);
    const char *sp1 = memchr(raw, ' ', (size_t)(line_end - raw));
    if (!sp1) return HTTP_BAD;
    const char *sp2 = memchr(sp1 + 1, ' ', (size_t)(line_end - sp1 - 1));
    if (!sp2 || sp1 == raw || sp2 == sp1 + 1 || sp1[1] != '/') return HTTP_BAD;
    if ((size_t)(line_end - sp2 - 1) != 8 || memcmp(sp2 + 1, "HTTP/1.1", 8) != 0) return HTTP_BAD;
    for (const char *p = raw; p < sp1; p++)
        if (!isupper((unsigned char)*p)) return HTTP_BAD;

    int result = HTTP_BAD;
    req->method = dup_range(raw, (size_t)(sp1 - raw));
    req->path = dup_range(sp1 + 1, (size_t)(sp2 - sp1 - 1));
    if (!req->method || !req->path) goto fail;

    long length = 0;
    int have_length = 0;
    const char *p = line_end + 2;
    while (p < head_end + 2) {
        const char *e = find_crlf(p, head_end + 2);
        if (!e || e == p) break;
        const char *colon = memchr(p, ':', (size_t)(e - p));
        if (!colon || colon == p) goto fail;
        if (req->header_count == HTTP_MAX_HEADERS) goto fail;
        const char *vs = colon + 1, *ve = e;
        trim(&vs, &ve);
        http_header_t *h = &req->headers[req->header_count++];
        h->name = dup_range(p, (size_t)(colon - p));
        h->value = dup_range(vs, (size_t)(ve - vs));
        if (!h->name || !h->value) goto fail;
        for (char *c = h->name; *c; c++) {
            if (!isalnum((unsigned char)*c) && *c != '-') goto fail;
            *c = (char)tolower((unsigned char)*c);
        }
        if (strcmp(h->name, "transfer-encoding") == 0) goto fail;
        if (strcmp(h->name, "content-length") == 0) {
            if (have_length || !parse_length(h->value, &length)) goto fail;
            have_length = 1;
        }
        p = e + 2;
    }
    if (length > HTTP_MAX_BODY) {
        result = HTTP_TOO_LARGE;
        goto fail;
    }
    const char *body = head_end + 4;
    if ((size_t)(end - body) < (size_t)length) {
        result = HTTP_INCOMPLETE;
        goto fail;
    }
    req->body = dup_range(body, (size_t)length);
    if (!req->body) goto fail;
    req->body_len = (size_t)length;
    return HTTP_PARSED;

fail:
    http_request_free(req);
    return result;
}

static const char *reason(int status) {
    switch (status) {
    case 200: return "OK";
    case 204: return "No Content";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 409: return "Conflict";
    case 413: return "Payload Too Large";
    case 500: return "Internal Server Error";
    case 502: return "Bad Gateway";
    default: return "Error";
    }
}

size_t http_response(int status, const char *const *extra_headers, const char *content_type,
                     const char *body, size_t body_len, char **out) {
    size_t cap = 256 + body_len + (content_type ? strlen(content_type) : 0);
    for (const char *const *h = extra_headers; h && h[0]; h += 2) cap += strlen(h[0]) + strlen(h[1]) + 4;
    char *buf = malloc(cap);
    if (!buf) {
        *out = NULL;
        return 0;
    }
    int n = snprintf(buf, cap, "HTTP/1.1 %d %s\r\n", status, reason(status));
    for (const char *const *h = extra_headers; h && h[0]; h += 2)
        n += snprintf(buf + n, cap - (size_t)n, "%s: %s\r\n", h[0], h[1]);
    if (content_type) n += snprintf(buf + n, cap - (size_t)n, "Content-Type: %s\r\n", content_type);
    n += snprintf(buf + n, cap - (size_t)n,
                  "Content-Length: %zu\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", body_len);
    if (body_len) memcpy(buf + n, body, body_len);
    buf[(size_t)n + body_len] = '\0';
    *out = buf;
    return (size_t)n + body_len;
}
