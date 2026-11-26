/* The only dialogs the agent shows: confirm a pairing, and pick a
 * certificate and type its PIN. Each platform implements these
 * (ui_cocoa.m on macOS, ui_gtk.c on Linux; ui_fake.c in tests). */
#ifndef UI_H
#define UI_H

#include <stddef.h>

typedef struct {
    const char *subject;   /* e.g. "CN=NAME:CPF,..." */
    const char *not_after; /* RFC 3339 */
    const char *token;     /* token label */
} ui_cert;

/* Asks the user a yes/no question. 1 = yes, 0 = no or closed. */
int ui_confirm(const char *title, const char *detail);

/* Shows the certificates and a PIN field. On 1 (OK) *chosen and pin are set;
 * 0 means cancelled. pin holds pin_size bytes including the NUL. */
int ui_pick_certificate(const char *title, const char *detail, const ui_cert *certs, size_t count,
                        size_t *chosen, char *pin, size_t pin_size);

#endif
