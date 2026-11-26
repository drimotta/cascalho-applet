#define _DEFAULT_SOURCE /* getentropy */
#include "pairing.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <sys/random.h>
#endif

#define LINE_MAX_LEN 4096

static int origin_ok(const char *origin) {
    if (!origin || !*origin || strlen(origin) > 1024) return 0;
    for (const char *p = origin; *p; p++)
        if (*p <= ' ' || *p == 0x7f) return 0;
    return 1;
}

static int same(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    unsigned char diff = (unsigned char)(la != lb);
    for (size_t i = 0; i < la && i < lb; i++) diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0;
}

/* Looks the origin up; copies its token to found when given. */
static int lookup(const char *store, const char *origin, char *found) {
    FILE *f = fopen(store, "r");
    if (!f) return 0;
    char line[LINE_MAX_LEN];
    int hit = 0;
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\n")] = '\0';
        char *space = strrchr(line, ' ');
        if (!space) continue;
        *space = '\0';
        if (strcmp(line, origin) == 0 && strlen(space + 1) == PAIRING_TOKEN_LEN) {
            if (found) memcpy(found, space + 1, PAIRING_TOKEN_LEN + 1);
            hit = 1;
        }
    }
    fclose(f);
    return hit;
}

int pairing_create(const char *store, const char *origin, char *token) {
    if (!origin_ok(origin)) return -1;
    unsigned char random[PAIRING_TOKEN_LEN / 2];
    if (getentropy(random, sizeof random) != 0) return -1;
    for (size_t i = 0; i < sizeof random; i++) snprintf(token + 2 * i, 3, "%02x", random[i]);

    char tmp[1024];
    if (snprintf(tmp, sizeof tmp, "%s.tmp", store) >= (int)sizeof tmp) return -1;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    FILE *out = fdopen(fd, "w");
    if (!out) {
        close(fd);
        return -1;
    }
    FILE *in = fopen(store, "r");
    if (in) {
        char line[LINE_MAX_LEN];
        size_t olen = strlen(origin);
        while (fgets(line, sizeof line, in))
            if (!(strncmp(line, origin, olen) == 0 && line[olen] == ' ')) fputs(line, out);
        fclose(in);
    }
    fprintf(out, "%s %s\n", origin, token);
    int ok = fflush(out) == 0 && fsync(fileno(out)) == 0;
    ok = fclose(out) == 0 && ok;
    if (!ok || chmod(tmp, 0600) != 0 || rename(tmp, store) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

int pairing_check(const char *store, const char *origin, const char *token) {
    if (!origin_ok(origin) || !token) return 0;
    char found[PAIRING_TOKEN_LEN + 1];
    if (!lookup(store, origin, found)) return 0;
    return same(found, token);
}

int pairing_is_paired(const char *store, const char *origin) {
    return origin_ok(origin) && lookup(store, origin, NULL);
}
