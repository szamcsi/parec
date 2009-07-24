/*
 * Copyright (c) Akos FROHNER <akos@frohner.hu> 2009.
 * Licence: Apache2, GPLv2
 *
 * Testing the parec context structure without the functionality.
 */

#include <stdio.h>
#include <stdlib.h>
#include "parec.h"

#define TEST_PRINT(m)  printf("test %02d: " m " -- ", testcount++);
#define TEST_ZERO(c)   if(c) { printf("FAILED\n"); return -1; } printf("OK\n");

int main(int argc, char *argv[]) {
    int testcount = 0;
    parec_ctx   *ctx;

    printf("test %02d: creating context -- ", testcount++);
    if((ctx = parec_new()) == NULL) {
        printf("FAILED\n");
        return -1;
    }
    printf("OK\n");

    TEST_PRINT("add_checksum(md5)")
    TEST_ZERO(parec_add_checksum(ctx, "md5"))

    TEST_PRINT("add_checksum(sha1)")
    TEST_ZERO(parec_add_checksum(ctx, "sha1"))
    
    TEST_PRINT("xattr_prefix(localhost)")
    TEST_ZERO(parec_set_xattr_prefix(ctx, "user.localhost."))

    TEST_PRINT("add_exclude_pattern(*~)")
    TEST_ZERO(parec_add_exclude_pattern(ctx, "*~"))

    TEST_PRINT("add_exclude_pattern(.git)")
    TEST_ZERO(parec_add_exclude_pattern(ctx, ".git"))

    TEST_PRINT("free")
    parec_free(ctx);
    printf("OK\n");
}

