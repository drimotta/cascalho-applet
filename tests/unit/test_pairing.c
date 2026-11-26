#include "../../src/pairing.h"
#include "check.h"

#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int check_failures = 0;

static char path[256];

static void fresh_store(void) {
    snprintf(path, sizeof path, "/tmp/cascalho-pairing-%d", getpid());
    unlink(path);
}

static void a_new_token_is_accepted_for_its_origin_only(void) {
    fresh_store();
    char token[PAIRING_TOKEN_LEN + 1];
    CHECK(pairing_create(path, "https://a.example", token) == 0);
    CHECK(strlen(token) == PAIRING_TOKEN_LEN);
    CHECK(pairing_check(path, "https://a.example", token) == 1);
    CHECK(pairing_check(path, "https://b.example", token) == 0);
    token[0] = token[0] == 'a' ? 'b' : 'a';
    CHECK(pairing_check(path, "https://a.example", token) == 0);
    CHECK(pairing_check(path, "https://a.example", "") == 0);
    CHECK(pairing_check(path, "https://a.example", NULL) == 0);
    unlink(path);
}

static void the_store_is_private_to_the_user(void) {
    fresh_store();
    char token[PAIRING_TOKEN_LEN + 1];
    CHECK(pairing_create(path, "https://a.example", token) == 0);
    struct stat st;
    CHECK(stat(path, &st) == 0);
    CHECK((st.st_mode & 0777) == 0600);
    unlink(path);
}

static void pairing_again_replaces_the_old_token(void) {
    fresh_store();
    char first[PAIRING_TOKEN_LEN + 1], second[PAIRING_TOKEN_LEN + 1], other[PAIRING_TOKEN_LEN + 1];
    CHECK(pairing_create(path, "https://a.example", first) == 0);
    CHECK(pairing_create(path, "https://b.example", other) == 0);
    CHECK(pairing_create(path, "https://a.example", second) == 0);
    CHECK(strcmp(first, second) != 0);
    CHECK(pairing_check(path, "https://a.example", first) == 0);
    CHECK(pairing_check(path, "https://a.example", second) == 1);
    CHECK(pairing_check(path, "https://b.example", other) == 1);
    unlink(path);
}

static void a_missing_store_accepts_nothing(void) {
    fresh_store();
    CHECK(pairing_check(path, "https://a.example", "00") == 0);
    CHECK(pairing_is_paired(path, "https://a.example") == 0);
    char token[PAIRING_TOKEN_LEN + 1];
    CHECK(pairing_create(path, "https://a.example", token) == 0);
    CHECK(pairing_is_paired(path, "https://a.example") == 1);
    unlink(path);
}

static void origins_with_spaces_or_newlines_are_refused(void) {
    fresh_store();
    char token[PAIRING_TOKEN_LEN + 1];
    CHECK(pairing_create(path, "https://a.example x", token) != 0);
    CHECK(pairing_create(path, "https://a.example\nhttps://b.example", token) != 0);
    CHECK(pairing_create(path, "", token) != 0);
}

int main(void) {
    RUN(a_new_token_is_accepted_for_its_origin_only);
    RUN(the_store_is_private_to_the_user);
    RUN(pairing_again_replaces_the_old_token);
    RUN(a_missing_store_accepts_nothing);
    RUN(origins_with_spaces_or_newlines_are_refused);
    return check_failures ? 1 : 0;
}
