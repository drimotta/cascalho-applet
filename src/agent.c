#define _DEFAULT_SOURCE
#include "agent.h"

#include "nfse.h"
#include "pairing.h"
#include "ui.h"

#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

typedef struct {
    const agent_config *cfg;
    const http_request *req;
    const char *origin; /* allowed origin, or NULL */
} ctx;

static size_t reply(const ctx *c, int status, cJSON *body, char **out) {
    char *text = body ? cJSON_PrintUnformatted(body) : NULL;
    const char *headers[] = {"Access-Control-Allow-Origin", c->origin, "Vary", "Origin", NULL};
    size_t len = http_response(status, c->origin ? headers : NULL, text ? "application/json" : NULL,
                               text ? text : "", text ? strlen(text) : 0, out);
    free(text);
    cJSON_Delete(body);
    return len;
}

static size_t error(const ctx *c, int status, const char *code, const char *message, char **out) {
    cJSON *body = cJSON_CreateObject();
    cJSON *e = cJSON_AddObjectToObject(body, "error");
    cJSON_AddStringToObject(e, "code", code);
    cJSON_AddStringToObject(e, "message", message);
    return reply(c, status, body, out);
}

/* The HTTP status for an nfse error code. */
static int status_for(int code) {
    switch (code) {
    case NFSE_ERR_INPUT: return 400;
    case NFSE_ERR_PIN:
    case NFSE_ERR_PIN_LOCKED: return 403;
    case NFSE_ERR_REJECTED: return 422;
    default: return 502;
    }
}

/* Calls an nfse function that takes (request, response) and returns the
 * parsed response; *code gets the status. */
static cJSON *nfse_call(int (*f)(const char *, char **), cJSON *request, int *code) {
    char *text = cJSON_PrintUnformatted(request);
    char *response = NULL;
    *code = f(text, &response);
    free(text);
    cJSON *parsed = response ? cJSON_Parse(response) : NULL;
    nfse_free(response);
    return parsed;
}

static cJSON *nfse_session_call(int (*f)(nfse_session *, const char *, char **), nfse_session *s,
                                cJSON *request, int *code) {
    char *text = cJSON_PrintUnformatted(request);
    char *response = NULL;
    *code = f(s, text, &response);
    free(text);
    cJSON *parsed = response ? cJSON_Parse(response) : NULL;
    nfse_free(response);
    return parsed;
}

/* Forwards an nfse error response with the matching HTTP status. */
static size_t nfse_error(const ctx *c, int code, cJSON *response, char **out) {
    if (!response) return error(c, 500, "internal", "no response from nfse", out);
    return reply(c, status_for(code), response, out);
}

static int host_ok(const ctx *c) {
    const char *host = http_header(c->req, "host");
    if (!host) return 0;
    char a[64], b[64];
    snprintf(a, sizeof a, "127.0.0.1:%d", c->cfg->port);
    snprintf(b, sizeof b, "localhost:%d", c->cfg->port);
    return strcmp(host, a) == 0 || strcmp(host, b) == 0;
}

static const char *allowed_origin(const agent_config *cfg, const http_request *req) {
    const char *origin = http_header(req, "origin");
    if (!origin) return NULL;
    for (size_t i = 0; i < cfg->origin_count; i++)
        if (strcmp(origin, cfg->origins[i]) == 0) return cfg->origins[i];
    return NULL;
}

static int paired(const ctx *c) {
    const char *auth = http_header(c->req, "authorization");
    if (!auth || strncmp(auth, "Bearer ", 7) != 0) return 0;
    return pairing_check(c->cfg->pairing_store, c->origin, auth + 7);
}

static size_t preflight(const ctx *c, char **out) {
    const char *pna = http_header(c->req, "access-control-request-private-network");
    const char *headers[] = {
        "Access-Control-Allow-Origin", c->origin,
        "Access-Control-Allow-Methods", "GET, POST",
        "Access-Control-Allow-Headers", "Authorization, Content-Type",
        "Access-Control-Max-Age", "600",
        "Vary", "Origin",
        pna && strcasecmp(pna, "true") == 0 ? "Access-Control-Allow-Private-Network" : NULL, "true",
        NULL};
    return http_response(204, headers, NULL, "", 0, out);
}

static size_t status(const ctx *c, char **out) {
    cJSON *body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "version", AGENT_VERSION);
    cJSON_AddStringToObject(body, "nfse", nfse_version());
    cJSON_AddBoolToObject(body, "paired", paired(c));
    return reply(c, 200, body, out);
}

static size_t pair(const ctx *c, char **out) {
    char detail[1200];
    snprintf(detail, sizeof detail,
             "%s wants to use the certificates on your smartcard. You will still type your PIN "
             "for every signature.",
             c->origin);
    if (!ui_confirm("Allow this site?", detail)) return error(c, 409, "cancelled", "the user said no", out);
    char token[PAIRING_TOKEN_LEN + 1];
    if (pairing_create(c->cfg->pairing_store, c->origin, token) != 0)
        return error(c, 500, "internal", "cannot save the pairing", out);
    cJSON *body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "token", token);
    return reply(c, 200, body, out);
}

static cJSON *list_request(const agent_config *cfg) {
    cJSON *req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "module", cfg->module);
    return req;
}

static size_t certificates(const ctx *c, char **out) {
    cJSON *req = list_request(c->cfg);
    int code;
    cJSON *resp = nfse_call(nfse_list_certificates, req, &code);
    cJSON_Delete(req);
    if (code != NFSE_OK) return nfse_error(c, code, resp, out);
    /* The page only needs what identifies a certificate, not the DER. */
    cJSON *list = cJSON_CreateArray();
    cJSON *token;
    cJSON_ArrayForEach(token, cJSON_GetObjectItem(resp, "tokens")) {
        cJSON *cert;
        cJSON_ArrayForEach(cert, cJSON_GetObjectItem(token, "certificates")) {
            if (!cJSON_IsTrue(cJSON_GetObjectItem(cert, "usable"))) continue;
            cJSON *item = cJSON_CreateObject();
            cJSON_AddItemToObject(item, "token", cJSON_Duplicate(cJSON_GetObjectItem(token, "label"), 0));
            cJSON_AddItemToObject(item, "id", cJSON_Duplicate(cJSON_GetObjectItem(cert, "id"), 0));
            cJSON_AddItemToObject(item, "subject", cJSON_Duplicate(cJSON_GetObjectItem(cert, "subject"), 0));
            cJSON_AddItemToObject(item, "not_after", cJSON_Duplicate(cJSON_GetObjectItem(cert, "not_after"), 0));
            cJSON_AddItemToObject(item, "der_b64", cJSON_Duplicate(cJSON_GetObjectItem(cert, "der_b64"), 0));
            cJSON_AddItemToArray(list, item);
        }
    }
    cJSON_Delete(resp);
    cJSON *body = cJSON_CreateObject();
    cJSON_AddItemToObject(body, "certificates", list);
    return reply(c, 200, body, out);
}

/* Asks the user for a certificate and its PIN and opens a session on it.
 * Returns NULL and writes the response on failure or cancel. */
static nfse_session *open_with_user(const ctx *c, const char *title, const char *detail, char **out,
                                    size_t *out_len) {
    cJSON *req = list_request(c->cfg);
    int code;
    cJSON *resp = nfse_call(nfse_list_certificates, req, &code);
    cJSON_Delete(req);
    if (code != NFSE_OK) {
        *out_len = nfse_error(c, code, resp, out);
        return NULL;
    }
    ui_cert certs[32];
    const char *ids[32];
    size_t n = 0;
    cJSON *token;
    cJSON_ArrayForEach(token, cJSON_GetObjectItem(resp, "tokens")) {
        cJSON *cert;
        cJSON_ArrayForEach(cert, cJSON_GetObjectItem(token, "certificates")) {
            if (n == 32 || !cJSON_IsTrue(cJSON_GetObjectItem(cert, "usable"))) continue;
            certs[n] = (ui_cert){cJSON_GetStringValue(cJSON_GetObjectItem(cert, "subject")),
                                 cJSON_GetStringValue(cJSON_GetObjectItem(cert, "not_after")),
                                 cJSON_GetStringValue(cJSON_GetObjectItem(token, "label"))};
            ids[n++] = cJSON_GetStringValue(cJSON_GetObjectItem(cert, "id"));
        }
    }
    if (n == 0) {
        cJSON_Delete(resp);
        *out_len = error(c, 502, "token", "no usable certificate found (is the card inserted?)", out);
        return NULL;
    }
    size_t chosen = 0;
    char pin[128] = {0};
    if (!ui_pick_certificate(title, detail, certs, n, &chosen, pin, sizeof pin)) {
        cJSON_Delete(resp);
        *out_len = error(c, 409, "cancelled", "the user cancelled", out);
        return NULL;
    }
    cJSON *open = list_request(c->cfg);
    cJSON_AddStringToObject(open, "pin", pin);
    cJSON_AddStringToObject(open, "token_label", certs[chosen].token);
    cJSON_AddStringToObject(open, "key_id", ids[chosen]);
    char *text = cJSON_PrintUnformatted(open);
    cJSON_Delete(resp);
    memset(pin, 0, sizeof pin);
    /* The PIN is in the request JSON: wipe it as soon as it is used. */
    cJSON_Delete(open);
    nfse_session *s = NULL;
    char *response = NULL;
    code = nfse_session_open(text, &s, &response);
    memset(text, 0, strlen(text));
    free(text);
    cJSON *parsed = response ? cJSON_Parse(response) : NULL;
    nfse_free(response);
    if (code != NFSE_OK) {
        *out_len = nfse_error(c, code, parsed, out);
        return NULL;
    }
    cJSON_Delete(parsed);
    return s;
}

static cJSON *parse_body(const ctx *c) {
    return c->req->body_len ? cJSON_ParseWithLength(c->req->body, c->req->body_len) : NULL;
}

static size_t login(const ctx *c, char **out) {
    cJSON *body = parse_body(c);
    const char *challenge = cJSON_GetStringValue(cJSON_GetObjectItem(body, "challenge_b64"));
    if (!challenge) {
        cJSON_Delete(body);
        return error(c, 400, "input", "challenge_b64 is required", out);
    }
    char detail[1200];
    snprintf(detail, sizeof detail, "Sign in to %s with your certificate.", c->origin);
    size_t len = 0;
    nfse_session *s = open_with_user(c, "Sign in", detail, out, &len);
    if (!s) {
        cJSON_Delete(body);
        return len;
    }
    cJSON *req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "challenge_b64", challenge);
    int code;
    cJSON *resp = nfse_session_call(nfse_sign_challenge, s, req, &code);
    nfse_session_close(s);
    cJSON_Delete(req);
    cJSON_Delete(body);
    if (code != NFSE_OK) return nfse_error(c, code, resp, out);
    return reply(c, 200, resp, out);
}

/* Copies the text of the first <tag> after `after` (or anywhere when NULL). */
static void xml_text(const char *xml, const char *after, const char *tag, char *buf, size_t size) {
    buf[0] = '\0';
    const char *from = after ? strstr(xml, after) : xml;
    if (!from) return;
    char open[64], close[64];
    snprintf(open, sizeof open, "<%s>", tag);
    snprintf(close, sizeof close, "</%s>", tag);
    const char *s = strstr(from, open);
    if (!s) return;
    s += strlen(open);
    const char *e = strstr(s, close);
    if (!e) return;
    size_t n = (size_t)(e - s) < size - 1 ? (size_t)(e - s) : size - 1;
    memcpy(buf, s, n);
    buf[n] = '\0';
}

static void add_connection(cJSON *req, const agent_config *cfg, const char *environment) {
    cJSON_AddStringToObject(req, "environment", environment);
    if (cfg->sefin_url) cJSON_AddStringToObject(req, "sefin_url", cfg->sefin_url);
    if (cfg->adn_url) cJSON_AddStringToObject(req, "adn_url", cfg->adn_url);
    if (cfg->ca_bundle) cJSON_AddStringToObject(req, "ca_bundle", cfg->ca_bundle);
    if (cfg->recovery_delays_ms) cJSON_AddItemToObject(req, "recovery_delays_ms", cJSON_Parse(cfg->recovery_delays_ms));
}

static size_t issue(const ctx *c, char **out) {
    cJSON *body = parse_body(c);
    const char *xml = cJSON_GetStringValue(cJSON_GetObjectItem(body, "unsigned_xml"));
    const char *environment = cJSON_GetStringValue(cJSON_GetObjectItem(body, "environment"));
    if (!xml || !environment) {
        cJSON_Delete(body);
        return error(c, 400, "input", "unsigned_xml and environment are required", out);
    }
    /* What the user is about to sign comes from the document itself, never
     * from text the page supplies. */
    char taker[256], amount[64], number[32], detail[1200];
    xml_text(xml, "<toma>", "xNome", taker, sizeof taker);
    xml_text(xml, "<vServPrest>", "vServ", amount, sizeof amount);
    xml_text(xml, NULL, "nDPS", number, sizeof number);
    snprintf(detail, sizeof detail, "Issue NFS-e (DPS %s, %s) for %s, R$ %s, requested by %s.", number,
             environment, taker[0] ? taker : "(no name)", amount[0] ? amount : "?", c->origin);
    size_t len = 0;
    nfse_session *s = open_with_user(c, "Issue NFS-e", detail, out, &len);
    if (!s) {
        cJSON_Delete(body);
        return len;
    }
    int code;
    cJSON *req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "xml", xml);
    cJSON *signed_resp = nfse_session_call(nfse_sign_dps, s, req, &code);
    cJSON_Delete(req);
    if (code != NFSE_OK) {
        nfse_session_close(s);
        cJSON_Delete(body);
        return nfse_error(c, code, signed_resp, out);
    }
    const char *dps_id = cJSON_GetStringValue(cJSON_GetObjectItem(signed_resp, "id"));
    const char *signed_xml = cJSON_GetStringValue(cJSON_GetObjectItem(signed_resp, "xml"));

    req = cJSON_CreateObject();
    add_connection(req, c->cfg, environment);
    cJSON_AddStringToObject(req, "signed_xml", signed_xml);
    cJSON_AddStringToObject(req, "dps_id", dps_id);
    cJSON *issued = nfse_session_call(nfse_submit, s, req, &code);
    cJSON_Delete(req);
    if (code != NFSE_OK) {
        nfse_session_close(s);
        if (!issued) issued = cJSON_CreateObject();
        /* The server keeps the signed DPS to look it up or resend the same
         * bytes; never a new number for an unknown outcome. */
        cJSON_AddStringToObject(issued, "dps_id", dps_id);
        cJSON_AddStringToObject(issued, "signed_xml", signed_xml);
        cJSON_Delete(signed_resp);
        cJSON_Delete(body);
        return reply(c, code == NFSE_ERR_UNKNOWN_OUTCOME ? 504 : status_for(code), issued, out);
    }
    cJSON_AddStringToObject(issued, "dps_id", dps_id);
    cJSON_AddStringToObject(issued, "signed_xml", signed_xml);
    cJSON_Delete(signed_resp);

    /* The PDF is a convenience: the NFS-e exists without it. */
    req = cJSON_CreateObject();
    add_connection(req, c->cfg, environment);
    cJSON_AddItemToObject(req, "chave_acesso", cJSON_Duplicate(cJSON_GetObjectItem(issued, "chave_acesso"), 0));
    cJSON *pdf = nfse_session_call(nfse_fetch_danfe, s, req, &code);
    cJSON_Delete(req);
    nfse_session_close(s);
    cJSON_Delete(body); /* environment points into it */
    if (code == NFSE_OK)
        cJSON_AddItemToObject(issued, "pdf_b64", cJSON_Duplicate(cJSON_GetObjectItem(pdf, "pdf_b64"), 0));
    cJSON_Delete(pdf);
    return reply(c, 200, issued, out);
}

size_t agent_handle(const agent_config *cfg, const http_request *req, char **out) {
    ctx c = {cfg, req, NULL};
    if (!host_ok(&c)) return error(&c, 403, "forbidden", "wrong Host", out);
    c.origin = allowed_origin(cfg, req);
    if (!c.origin) return error(&c, 403, "forbidden", "origin not allowed", out);
    const char *m = req->method, *p = req->path;

    static const struct {
        const char *path, *method;
        int needs_pairing;
        size_t (*handler)(const ctx *, char **);
    } routes[] = {
        {"/v1/status", "GET", 0, status},
        {"/v1/pair", "POST", 0, pair},
        {"/v1/certificates", "GET", 1, certificates},
        {"/v1/login", "POST", 1, login},
        {"/v1/issue", "POST", 1, issue},
    };
    for (size_t i = 0; i < sizeof routes / sizeof routes[0]; i++) {
        if (strcmp(p, routes[i].path) != 0) continue;
        if (strcmp(m, "OPTIONS") == 0) return preflight(&c, out);
        if (strcmp(m, routes[i].method) != 0) return error(&c, 405, "method", "method not allowed", out);
        if (routes[i].needs_pairing && !paired(&c))
            return error(&c, 401, "unpaired", "pair with the agent first", out);
        return routes[i].handler(&c, out);
    }
    return error(&c, 404, "not_found", "no such endpoint", out);
}
