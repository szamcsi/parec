/*
 * Copyright (c) Akos FROHNER <akos@frohner.hu> 2009.
 * Licence: Apache2, GPLv2
 *
 * Testing the parec context structure without the functionality.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "parec.h"

#define TEST_PRINT(m)  printf("test %02d: " m " -- ", testcount++);
#define TEST_ZERO(c)   if(c) { printf("FAILED\n"); return -1; } printf("OK\n");

int main(int argc __attribute__((__unused__)), char *argv[] __attribute__((__unused__))) {
    int testcount = 0;
    parec_ctx   *ctx;
    int  c;
    const char *s;

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

    TEST_PRINT("get_checksum_count()")
    if((c = parec_get_checksum_count(ctx)) < 0 || c != 2) {
        printf("FAILED\n");
        return -1;
    }
    printf("OK\n");

    TEST_PRINT("get_checksum_name(0)")
    if(!(s = parec_get_checksum_name(ctx, 0)) || strcmp(s, "md5")) {
        printf("FAILED\n");
        return -1;
    }
    printf("OK\n");

    TEST_PRINT("get_checksum_name(1)")
    if(!(s = parec_get_checksum_name(ctx, 1)) || strcmp(s, "sha1")) {
        printf("FAILED\n");
        return -1;
    }
    printf("OK\n");
    
    TEST_PRINT("xattr_prefix(localhost)")
    TEST_ZERO(parec_set_xattr_prefix(ctx, "localhost"))

    TEST_PRINT("get_xattr_name(0)")
    if(!(s = parec_get_xattr_name(ctx, 0)) || strcmp(s, "user.localhost.md5")) {
        printf("FAILED\n");
        return -1;
    }
    printf("OK\n");

    TEST_PRINT("get_xattr_name(1)")
    if(!(s = parec_get_xattr_name(ctx, 1)) || strcmp(s, "user.localhost.sha1")) {
        printf("FAILED\n");
        return -1;
    }
    printf("OK\n");

    TEST_PRINT("add_exclude_pattern(*~)")
    TEST_ZERO(parec_add_exclude_pattern(ctx, "*~"))

    TEST_PRINT("add_exclude_pattern(.git)")
    TEST_ZERO(parec_add_exclude_pattern(ctx, ".git"))

    TEST_PRINT("free")
    parec_free(ctx);
    printf("OK\n");
}

