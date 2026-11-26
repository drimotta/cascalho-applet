/* cascalho-agent: lets an allowed web page use the smartcard on this
 * machine, through http://127.0.0.1:1917. */
#define _DEFAULT_SOURCE
#include "agent.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#define MAX_ORIGINS 16

static void usage(void) {
    fprintf(stderr,
            "usage: cascalho-agent --origin https://SITE [--origin ...] [--module PATH]\n"
            "                      [--port N] [--pairing-store PATH]\n"
            "                      [--sefin-url URL --adn-url URL --ca-bundle PEM]\n");
    exit(2);
}

static const char *default_module(void) {
    static const char *candidates[] = {
        "/opt/homebrew/lib/opensc-pkcs11.so", "/usr/local/lib/opensc-pkcs11.so",
        "/Library/OpenSC/lib/opensc-pkcs11.so", "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
        "/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so", "/usr/lib64/opensc-pkcs11.so",
        "/usr/lib/opensc-pkcs11.so", NULL};
    for (const char **c = candidates; *c; c++)
        if (access(*c, R_OK) == 0) return *c;
    return candidates[0];
}

static char *default_store(void) {
    const char *home = getenv("HOME");
    if (!home) return NULL;
    static char path[1024];
#ifdef __APPLE__
    snprintf(path, sizeof path, "%s/Library/Application Support/cascalho-agent", home);
#else
    const char *xdg = getenv("XDG_CONFIG_HOME");
    if (xdg && *xdg) snprintf(path, sizeof path, "%s/cascalho-agent", xdg);
    else snprintf(path, sizeof path, "%s/.config/cascalho-agent", home);
#endif
    mkdir(path, 0700);
    strncat(path, "/pairings", sizeof path - strlen(path) - 1);
    return path;
}

/* Reads one request (10 s, at most the head and body limits). */
static int read_request(int fd, http_request *req) {
    struct timeval tv = {10, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    size_t cap = 8192, len = 0;
    char *buf = malloc(cap);
    int result = HTTP_INCOMPLETE;
    while (buf && result == HTTP_INCOMPLETE) {
        if (len == cap) {
            if (cap >= HTTP_MAX_HEAD + HTTP_MAX_BODY) {
                result = HTTP_TOO_LARGE;
                break;
            }
            cap *= 2;
            char *grown = realloc(buf, cap);
            if (!grown) break;
            buf = grown;
        }
        ssize_t n = recv(fd, buf + len, cap - len, 0);
        if (n <= 0) break;
        len += (size_t)n;
        result = http_parse(buf, len, req);
    }
    free(buf);
    return result;
}

static void write_all(int fd, const char *data, size_t len) {
    while (len) {
        ssize_t n = send(fd, data, len, 0);
        if (n <= 0) return;
        data += n;
        len -= (size_t)n;
    }
}

int main(int argc, char **argv) {
    const char *origins[MAX_ORIGINS];
    agent_config cfg = {.origins = origins, .port = AGENT_PORT};
    for (int i = 1; i < argc; i += 2) {
        const char *a = argv[i];
        const char *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!v) usage();
        if (strcmp(a, "--origin") == 0 && cfg.origin_count < MAX_ORIGINS) origins[cfg.origin_count++] = v;
        else if (strcmp(a, "--module") == 0) cfg.module = v;
        else if (strcmp(a, "--port") == 0) cfg.port = atoi(v);
        else if (strcmp(a, "--pairing-store") == 0) cfg.pairing_store = v;
        else if (strcmp(a, "--sefin-url") == 0) cfg.sefin_url = v;
        else if (strcmp(a, "--adn-url") == 0) cfg.adn_url = v;
        else if (strcmp(a, "--ca-bundle") == 0) cfg.ca_bundle = v;
        else if (strcmp(a, "--recovery-delays-ms") == 0) cfg.recovery_delays_ms = v;
        else usage();
    }
    if (cfg.origin_count == 0 || cfg.port <= 0 || cfg.port > 65535) usage();
    if (!cfg.module) cfg.module = default_module();
    if (!cfg.pairing_store) cfg.pairing_store = default_store();
    if (!cfg.pairing_store) {
        fprintf(stderr, "cascalho-agent: no HOME for the pairing store\n");
        return 1;
    }
    signal(SIGPIPE, SIG_IGN);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons((uint16_t)cfg.port)};
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); /* never another interface */
    if (srv < 0 || bind(srv, (struct sockaddr *)&addr, sizeof addr) != 0 || listen(srv, 8) != 0) {
        fprintf(stderr, "cascalho-agent: cannot listen on 127.0.0.1:%d: %s\n", cfg.port, strerror(errno));
        return 1;
    }
    fprintf(stderr, "cascalho-agent %s listening on 127.0.0.1:%d\n", AGENT_VERSION, cfg.port);

    /* One request at a time: the card and the dialogs are single-user. */
    for (;;) {
        int fd = accept(srv, NULL, NULL);
        if (fd < 0) continue;
        http_request req;
        int parsed = read_request(fd, &req);
        char *out = NULL;
        size_t len;
        if (parsed == HTTP_PARSED) {
            len = agent_handle(&cfg, &req, &out);
            http_request_free(&req);
        } else {
            int status = parsed == HTTP_TOO_LARGE ? 413 : 400;
            len = http_response(status, NULL, NULL, "", 0, &out);
        }
        if (out) write_all(fd, out, len);
        free(out);
        close(fd);
    }
}
