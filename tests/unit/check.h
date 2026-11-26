/* A minimal test harness: CHECK records a failure and carries on. */
#ifndef CHECK_H
#define CHECK_H

#include <stdio.h>
#include <string.h>

extern int check_failures;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            check_failures++;                                              \
        }                                                                  \
    } while (0)

#define CHECK_STR(a, b)                                                          \
    do {                                                                         \
        const char *a_ = (a), *b_ = (b);                                         \
        if (!a_ || !b_ || strcmp(a_, b_) != 0) {                                 \
            fprintf(stderr, "FAIL %s:%d: %s == %s (\"%s\" vs \"%s\")\n", __FILE__, \
                    __LINE__, #a, #b, a_ ? a_ : "(null)", b_ ? b_ : "(null)");   \
            check_failures++;                                                    \
        }                                                                        \
    } while (0)

#define RUN(test)                    \
    do {                             \
        fprintf(stderr, "%s\n", #test); \
        test();                      \
    } while (0)

#endif
