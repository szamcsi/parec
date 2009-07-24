/*
 * parec -- Parallel Recursive Checksums
 * 
 * Calculating multiple checksums in parallel in a directory
 * tree and storing the results into extended attributes.
 * 
 * Checksum of the files is based on their content.
 * Checksum of directories is based on the checksum of the files they contain.
 *
 * Copyright, 2009.
 *   Akos FROHNER <akos@frohner.hu>
 * Licence: Apache2, GPLv2
 */

#include <stdio.h>
#include <string.h>
#include <sys/xattr.h>
#include <parec.h>
#include <getopt.h>

unsigned char x_value[255];
ssize_t x_len;

int main(int argc, char *argv[]) {
    parec_ctx *ctx;

    if(!(ctx = parec_new())) {
        fprintf(stderr, "ERROR: Could not initialize the library.\n");
        return 1;
    }

    if(parec_add_checksum(ctx, "md5") || parec_add_checksum(ctx, "sha1")) {
        fprintf(stderr, "ERROR: %s\n", parec_get_error(ctx));
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        if(parec_file(ctx, argv[i])) {
            fprintf(stderr, "ERROR: %s\n", parec_get_error(ctx));
            return 1;
        }
        for (int a = 0; a < parec_get_checksum_count(ctx); a++) {
            const char *x_name = parec_get_xattr_name(ctx, a);
            const char *a_name = parec_get_checksum_name(ctx, a);
            if((x_len = getxattr(argv[i], x_name, x_value, 255)) < 0) {
                fprintf(stderr, "Getting attribute %s has failed on %s\n", x_name, argv[i]);
                return 1;
            }
            printf("%s(%s) = ", a_name, argv[i]);
            for(int d = 0; d < x_len; d++) {
                printf("%02x", x_value[d]);
            }
            printf("\n");
        }
    }

    parec_free(ctx);
}
