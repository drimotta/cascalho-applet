/* Pairing tokens: one per allowed origin, kept in a file only the user can
 * read. A page proves it was paired by sending its token. */
#ifndef PAIRING_H
#define PAIRING_H

#define PAIRING_TOKEN_LEN 64 /* hex characters, 32 random bytes */

/* Creates (or replaces) the origin's token and writes it to token, which
 * holds PAIRING_TOKEN_LEN + 1 bytes. Returns 0 on success. */
int pairing_create(const char *store, const char *origin, char *token);

/* 1 when token is the origin's current token, else 0. */
int pairing_check(const char *store, const char *origin, const char *token);

/* 1 when the origin has a token. */
int pairing_is_paired(const char *store, const char *origin);

#endif
