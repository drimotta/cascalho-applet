#include "../../src/agent.h"
#include "../../src/pairing.h"
#include "check.h"

#include <stdlib.h>
#include <unistd.h>

int check_failures = 0;

static const char *origins[] = {"https://cascalho.example"};
static char store[256];
static agent_config cfg;

static void setup(void) {
    snprintf(store, sizeof store, "/tmp/cascalho-agent-test-%d", getpid());
    unlink(store);
    cfg = (agent_config){.origins = origins, .origin_count = 1, .pairing_store = store,
                         .module = "/nonexistent.so", .port = AGENT_PORT};
    unsetenv("CASCALHO_FAKE_UI");
}

/* Sends raw request text and returns the response text (freed by caller). */
static char *send(const char *raw) {
    http_request req;
    if (http_parse(raw, strlen(raw), &req) != HTTP_PARSED) return strdup("unparsed");
    char *out = NULL;
    agent_handle(&cfg, &req, &out);
    http_request_free(&req);
    return out;
}

static char *request(const char *method, const char *path, const char *origin, const char *token,
                     const char *body) {
    char raw[4096];
    int n = snprintf(raw, sizeof raw, "%s %s HTTP/1.1\r\nHost: 127.0.0.1:1917\r\n", method, path);
    if (origin) n += snprintf(raw + n, sizeof raw - n, "Origin: %s\r\n", origin);
    if (token) n += snprintf(raw + n, sizeof raw - n, "Authorization: Bearer %s\r\n", token);
    body = body ? body : "";
    snprintf(raw + n, sizeof raw - n, "Content-Length: %zu\r\n\r\n%s", strlen(body), body);
    return send(raw);
}

static int status_of(const char *resp) {
    int status = 0;
    sscanf(resp, "HTTP/1.1 %d", &status);
    return status;
}

static void only_the_loopback_host_is_served(void) {
    setup();
    char *r = send("GET /v1/status HTTP/1.1\r\nHost: evil.example:1917\r\nOrigin: https://cascalho.example\r\n\r\n");
    CHECK(status_of(r) == 403);
    free(r);
    r = send("GET /v1/status HTTP/1.1\r\nOrigin: https://cascalho.example\r\n\r\n");
    CHECK(status_of(r) == 403);
    free(r);
    r = send("GET /v1/status HTTP/1.1\r\nHost: localhost:1917\r\nOrigin: https://cascalho.example\r\n\r\n");
    CHECK(status_of(r) == 200);
    free(r);
}

static void other_origins_are_refused_without_cors_headers(void) {
    setup();
    char *r = request("GET", "/v1/status", "https://evil.example", NULL, NULL);
    CHECK(status_of(r) == 403);
    CHECK(strstr(r, "Access-Control-Allow-Origin") == NULL);
    free(r);
    r = request("GET", "/v1/status", NULL, NULL, NULL);
    CHECK(status_of(r) == 403);
    free(r);
}

static void preflight_allows_the_origin_and_the_private_network(void) {
    setup();
    char *r = send("OPTIONS /v1/login HTTP/1.1\r\nHost: 127.0.0.1:1917\r\n"
                   "Origin: https://cascalho.example\r\n"
                   "Access-Control-Request-Method: POST\r\n"
                   "Access-Control-Request-Private-Network: true\r\n\r\n");
    CHECK(status_of(r) == 204);
    CHECK(strstr(r, "Access-Control-Allow-Origin: https://cascalho.example\r\n") != NULL);
    CHECK(strstr(r, "Access-Control-Allow-Private-Network: true\r\n") != NULL);
    CHECK(strstr(r, "Access-Control-Allow-Headers: Authorization, Content-Type\r\n") != NULL);
    CHECK(strstr(r, "Vary: Origin\r\n") != NULL);
    free(r);
}

static void status_says_whether_the_origin_is_paired(void) {
    setup();
    char *r = request("GET", "/v1/status", "https://cascalho.example", NULL, NULL);
    CHECK(status_of(r) == 200);
    CHECK(strstr(r, "\"paired\":false") != NULL);
    CHECK(strstr(r, "\"version\":\"" AGENT_VERSION "\"") != NULL);
    CHECK(strstr(r, "Access-Control-Allow-Origin: https://cascalho.example\r\n") != NULL);
    free(r);
}

static void pairing_needs_the_user_to_confirm(void) {
    setup();
    setenv("CASCALHO_FAKE_UI", "confirm=no", 1);
    char *r = request("POST", "/v1/pair", "https://cascalho.example", NULL, "{}");
    CHECK(status_of(r) == 409);
    CHECK(strstr(r, "\"code\":\"cancelled\"") != NULL);
    free(r);

    setenv("CASCALHO_FAKE_UI", "confirm=yes", 1);
    r = request("POST", "/v1/pair", "https://cascalho.example", NULL, "{}");
    CHECK(status_of(r) == 200);
    char token[PAIRING_TOKEN_LEN + 1] = {0};
    const char *t = strstr(r, "\"token\":\"");
    CHECK(t != NULL);
    if (t) memcpy(token, t + 9, PAIRING_TOKEN_LEN);
    CHECK(pairing_check(store, "https://cascalho.example", token) == 1);
    free(r);

    r = request("GET", "/v1/status", "https://cascalho.example", token, NULL);
    CHECK(strstr(r, "\"paired\":true") != NULL);
    free(r);
    unlink(store);
}

static void token_endpoints_need_the_pairing_token(void) {
    setup();
    const char *paths[][2] = {{"GET", "/v1/certificates"}, {"POST", "/v1/login"}, {"POST", "/v1/issue"}};
    for (size_t i = 0; i < 3; i++) {
        char *r = request(paths[i][0], paths[i][1], "https://cascalho.example", NULL, "{}");
        CHECK(status_of(r) == 401);
        free(r);
        r = request(paths[i][0], paths[i][1], "https://cascalho.example", "0123", "{}");
        CHECK(status_of(r) == 401);
        free(r);
    }
}

static void unknown_paths_and_methods(void) {
    setup();
    char *r = request("GET", "/v2/anything", "https://cascalho.example", NULL, NULL);
    CHECK(status_of(r) == 404);
    free(r);
    r = request("DELETE", "/v1/status", "https://cascalho.example", NULL, NULL);
    CHECK(status_of(r) == 405);
    free(r);
}

static void requests_with_a_paired_token_reach_the_token(void) {
    setup();
    char token[PAIRING_TOKEN_LEN + 1];
    CHECK(pairing_create(store, "https://cascalho.example", token) == 0);
    /* The module does not exist, so the call reaches nfse and fails there. */
    char *r = request("GET", "/v1/certificates", "https://cascalho.example", token, NULL);
    CHECK(status_of(r) == 502);
    CHECK(strstr(r, "\"code\":\"token\"") != NULL);
    free(r);
    r = request("POST", "/v1/login", "https://cascalho.example", token, "not json");
    CHECK(status_of(r) == 400);
    free(r);
    unlink(store);
}

int main(void) {
    RUN(only_the_loopback_host_is_served);
    RUN(other_origins_are_refused_without_cors_headers);
    RUN(preflight_allows_the_origin_and_the_private_network);
    RUN(status_says_whether_the_origin_is_paired);
    RUN(pairing_needs_the_user_to_confirm);
    RUN(token_endpoints_need_the_pairing_token);
    RUN(unknown_paths_and_methods);
    RUN(requests_with_a_paired_token_reach_the_token);
    return check_failures ? 1 : 0;
}
