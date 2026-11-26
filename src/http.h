/* A small HTTP/1.1 request parser and response writer, enough for one
 * request per connection from a browser on the same machine. */
#ifndef HTTP_H
#define HTTP_H

#include <stddef.h>
#include <stdlib.h>

#define HTTP_MAX_BODY (1024 * 1024)
#define HTTP_MAX_HEAD (16 * 1024)
#define HTTP_MAX_HEADERS 32

enum http_parse_result { HTTP_PARSED, HTTP_INCOMPLETE, HTTP_BAD, HTTP_TOO_LARGE };

typedef struct {
    char *name; /* lower case */
    char *value;
} http_header_t;

typedef struct {
    char *method;
    char *path;
    http_header_t headers[HTTP_MAX_HEADERS];
    size_t header_count;
    char *body; /* NUL-terminated copy */
    size_t body_len;
} http_request;

/* Parses raw[0..len). On HTTP_PARSED the request owns copies of everything;
 * release it with http_request_free(). */
int http_parse(const char *raw, size_t len, http_request *req);
void http_request_free(http_request *req);

/* The value of a header, matched without regard to case, or NULL. */
const char *http_header(const http_request *req, const char *name);

/* Writes a full response to *out (malloc'd, NUL-terminated) and returns its
 * length. extra_headers is a NULL-terminated list of name, value pairs. */
size_t http_response(int status, const char *const *extra_headers, const char *content_type,
                     const char *body, size_t body_len, char **out);

#endif
