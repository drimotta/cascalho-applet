#include "../../src/http.h"
#include "check.h"

int check_failures = 0;

static int parse(const char *raw, http_request *req) {
    return http_parse(raw, strlen(raw), req);
}

static void parses_a_post_with_a_body(void) {
    http_request req;
    const char *raw =
        "POST /v1/login HTTP/1.1\r\n"
        "Host: 127.0.0.1:1917\r\n"
        "Origin: https://cascalho.example\r\n"
        "Authorization: Bearer abc\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 13\r\n"
        "\r\n"
        "{\"a\":\"hello\"}";
    CHECK(parse(raw, &req) == HTTP_PARSED);
    CHECK_STR(req.method, "POST");
    CHECK_STR(req.path, "/v1/login");
    CHECK_STR(http_header(&req, "origin"), "https://cascalho.example");
    CHECK_STR(http_header(&req, "AUTHORIZATION"), "Bearer abc");
    CHECK(req.body_len == 13);
    CHECK(memcmp(req.body, "{\"a\":\"hello\"}", 13) == 0);
    http_request_free(&req);
}

static void waits_for_the_rest_of_the_request(void) {
    http_request req;
    CHECK(parse("GET /v1/status HTTP/1.1\r\nHost: x\r\n", &req) == HTTP_INCOMPLETE);
    CHECK(parse("POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nab", &req) == HTTP_INCOMPLETE);
}

static void refuses_malformed_and_oversized_requests(void) {
    http_request req;
    CHECK(parse("GARBAGE\r\n\r\n", &req) == HTTP_BAD);
    CHECK(parse("GET /x HTTP/1.0\r\n\r\n", &req) == HTTP_BAD);
    CHECK(parse("GET x HTTP/1.1\r\n\r\n", &req) == HTTP_BAD);
    CHECK(parse("POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n", &req) == HTTP_BAD);
    CHECK(parse("POST / HTTP/1.1\r\nContent-Length: 12x\r\n\r\n", &req) == HTTP_BAD);
    CHECK(parse("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", &req) == HTTP_BAD);
    CHECK(parse("POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab", &req) == HTTP_BAD);
    CHECK(parse("GET / HTTP/1.1\r\nNoColon\r\n\r\n", &req) == HTTP_BAD);
    char big[64];
    snprintf(big, sizeof big, "POST / HTTP/1.1\r\nContent-Length: %d\r\n\r\n", HTTP_MAX_BODY + 1);
    CHECK(parse(big, &req) == HTTP_TOO_LARGE);
}

static void a_get_has_an_empty_body(void) {
    http_request req;
    CHECK(parse("GET /v1/status HTTP/1.1\r\nHost: x\r\n\r\n", &req) == HTTP_PARSED);
    CHECK(req.body_len == 0);
    CHECK(http_header(&req, "origin") == NULL);
    http_request_free(&req);
}

static void writes_a_response_with_its_length(void) {
    const char *headers[] = {"Access-Control-Allow-Origin", "https://a.example", NULL};
    char *out = NULL;
    size_t len = http_response(200, headers, "application/json", "{}", 2, &out);
    CHECK(len > 0);
    CHECK(strstr(out, "HTTP/1.1 200 OK\r\n") == out);
    CHECK(strstr(out, "Content-Length: 2\r\n") != NULL);
    CHECK(strstr(out, "Access-Control-Allow-Origin: https://a.example\r\n") != NULL);
    CHECK(strstr(out, "Connection: close\r\n") != NULL);
    CHECK(strcmp(out + len - 6, "\r\n\r\n{}") == 0);
    free(out);
}

int main(void) {
    RUN(parses_a_post_with_a_body);
    RUN(waits_for_the_rest_of_the_request);
    RUN(refuses_malformed_and_oversized_requests);
    RUN(a_get_has_an_empty_body);
    RUN(writes_a_response_with_its_length);
    return check_failures ? 1 : 0;
}
