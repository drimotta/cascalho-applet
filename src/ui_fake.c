/* Scripted dialogs for tests, driven by CASCALHO_FAKE_UI or by the file
 * named in CASCALHO_FAKE_UI_FILE (read at every dialog, so a running agent
 * can be scripted):
 *   "confirm=yes|no;pick=<index>;pin=<pin>"   or   "cancel"
 * Each dialog's title and detail are appended to CASCALHO_FAKE_UI_LOG when
 * set, so tests can check what the user would have seen. */
#include "ui.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *setting(const char *key, char *buf, size_t size) {
    static char from_file[512];
    const char *spec = getenv("CASCALHO_FAKE_UI");
    const char *file = getenv("CASCALHO_FAKE_UI_FILE");
    if (file) {
        FILE *f = fopen(file, "r");
        if (!f) return NULL;
        size_t n = fread(from_file, 1, sizeof from_file - 1, f);
        fclose(f);
        from_file[n] = '\0';
        from_file[strcspn(from_file, "\n")] = '\0';
        spec = from_file;
    }
    if (!spec) return NULL;
    size_t klen = strlen(key);
    for (const char *p = spec; *p;) {
        const char *end = strchr(p, ';');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (len > klen && strncmp(p, key, klen) == 0 && p[klen] == '=') {
            size_t vlen = len - klen - 1;
            if (vlen >= size) vlen = size - 1;
            memcpy(buf, p + klen + 1, vlen);
            buf[vlen] = '\0';
            return buf;
        }
        p += len + (end ? 1 : 0);
    }
    return NULL;
}

static void log_dialog(const char *kind, const char *title, const char *detail) {
    const char *path = getenv("CASCALHO_FAKE_UI_LOG");
    if (!path) return;
    FILE *f = fopen(path, "a");
    if (!f) return;
    fprintf(f, "%s\t%s\t%s\n", kind, title, detail ? detail : "");
    fclose(f);
}

int ui_confirm(const char *title, const char *detail) {
    log_dialog("confirm", title, detail);
    char v[16];
    return setting("confirm", v, sizeof v) && strcmp(v, "yes") == 0;
}

int ui_pick_certificate(const char *title, const char *detail, const ui_cert *certs, size_t count,
                        size_t *chosen, char *pin, size_t pin_size) {
    (void)certs;
    log_dialog("pick", title, detail);
    char v[64];
    if (!setting("pick", v, sizeof v)) return 0;
    size_t i = (size_t)strtoul(v, NULL, 10);
    if (i >= count || !setting("pin", pin, pin_size)) return 0;
    *chosen = i;
    return 1;
}
