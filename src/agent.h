/* The agent's HTTP API: what a page from an allowed origin may ask. */
#ifndef AGENT_H
#define AGENT_H

#include "http.h"

#define AGENT_VERSION "0.1.0"
#define AGENT_PORT 1917

typedef struct {
    const char *const *origins; /* allowed page origins */
    size_t origin_count;
    const char *pairing_store; /* path of the pairing file */
    const char *module;        /* PKCS#11 module */
    int port;
    /* Optional RFB overrides (tests, staging proxies). */
    const char *sefin_url;
    const char *adn_url;
    const char *ca_bundle;
    const char *recovery_delays_ms; /* JSON array, e.g. "[10]" */
} agent_config;

/* Handles one request and returns the full HTTP response in *out
 * (malloc'd). Returns its length. */
size_t agent_handle(const agent_config *cfg, const http_request *req, char **out);

#endif
