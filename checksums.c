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

static const char    *usage = 
"  -h, --help               Print this help text and exit.\n"
"  -v, --verbose            Print checksums for each file.\n"
"  -a, --algorithm ALG      Calculate checksums using ALG.\n"
"  -p, --prefix XP          Prefix for the extended attributes.\n"
"  -c, --check              Check the already calculated checksums.\n"
"  -f, --force              Force re-calculating the checksums.\n"
"  -w, --wipe               Purge/wipe checksum attributes.\n";

static const char    *short_options = "hva:p:cfw";
static struct option long_options[] = {
    {"help",        no_argument,        NULL, 'h'},
    {"verbose",     no_argument,        NULL, 'v'},
    {"algorithm",   required_argument,  NULL, 'a'},
    {"prefix",      required_argument,  NULL, 'p'},
    {"check",       no_argument,        NULL, 'c'},
    {"force",       no_argument,        NULL, 'f'},
    {"wipe",        no_argument,        NULL, 'w'},
    { NULL,         no_argument,        NULL, 0}
};

int verbose_flag = 0;
int default_checksums_flag = 1;

int main(int argc, char *argv[]) {
    int c;
    int options_index = 0;
    parec_ctx *ctx;
    char *prog_name;

    // determine the program name
    prog_name = strrchr(argv[0], '/');
    if (!prog_name)
        prog_name = argv[0];
    else
        prog_name++;

    if(!(ctx = parec_new())) {
        fprintf(stderr, "ERROR: Could not initialize the library.\n");
        return 1;
    }

    while((c = getopt_long(argc, argv, short_options, long_options, &options_index)) != -1) {
        switch (c) {
            case 'h':
                printf("Usage: %s [options]\n%s", prog_name, usage);
                return 0;
            case 'v':
                verbose_flag++;
                break;
            case 'a':
                if(parec_add_checksum(ctx, optarg)) {
                    fprintf(stderr, "ERROR: %s\n", parec_get_error(ctx));
                    return 1;
                }
                default_checksums_flag = 0;
                break;
            case 'p':
                if(parec_set_xattr_prefix(ctx, optarg)) {
                    fprintf(stderr, "ERROR: %s\n", parec_get_error(ctx));
                    return 1;
                }
                break;
            case 'c':
                if(parec_set_method(ctx, PAREC_METHOD_CHECK)) {
                    fprintf(stderr, "ERROR: %s\n", parec_get_error(ctx));
                    return 1;
                }
                break;
            case 'f':
                if(parec_set_method(ctx, PAREC_METHOD_FORCE)) {
                    fprintf(stderr, "ERROR: %s\n", parec_get_error(ctx));
                    return 1;
                }
                break;
            case 'w':
                if(parec_set_method(ctx, PAREC_METHOD_PURGE)) {
                    fprintf(stderr, "ERROR: %s\n", parec_get_error(ctx));
                    return 1;
                }
                verbose_flag = 0;
                break;
            case ':':
                fprintf(stderr, "ERROR: option argument is missing\n");
                return 1;
            case '?':
                fprintf(stderr, "ERROR: unknown command line option\n");
                return 1;
        }
    }
    argc -= optind;
    argv += optind;
    
    // add the defaults, if nothing else was specified
    if(default_checksums_flag) {
        if(parec_add_checksum(ctx, "md5") || parec_add_checksum(ctx, "sha1")) {
            fprintf(stderr, "ERROR: %s\n", parec_get_error(ctx));
            return 1;
        }
    }

    for (int i = 0; i < argc; i++) {
        if(parec_process(ctx, argv[i])) {
            fprintf(stderr, "ERROR: %s\n", parec_get_error(ctx));
            return 1;
        }
        if (verbose_flag) {
            unsigned char x_value[255];
            ssize_t x_len;
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
    }

    parec_free(ctx);
}
