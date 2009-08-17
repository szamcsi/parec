/*
 * parec -- Parallel Recursive Checksums
 * 
 * Calculating multiple checksums in parallel in a directory
 * tree and storing the results into extended attributes.
 * 
 * Checksum of the files is based on their content.
 * Checksum of directories is based on the checksum of the files they contain.
 *
 * Copyright (c) Akos FROHNER <akos@frohner.hu> 2009.
 * License: GPLv2
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <parec.h>
#include <getopt.h>

static const char    *usage = 
"  -h, --help               Print this help text and exit.\n"
"  -v, --verbose            Print checksums for each file.\n"
"  -a, --algorithm ALG      Calculate checksums using ALG.\n"
"  -p, --prefix XP          Prefix for the extended attributes.\n"
"  -e, --exclude PTN        Exclude checking files matching PTN.\n"
"  -c, --check, --verify    Check the already calculated checksums.\n"
"  -f, --force              Force re-calculating the checksums.\n"
"  -w, --wipe, --purge      Purge/wipe checksum attributes.\n";

static const char    *short_options = "hva:p:cfw";
static struct option long_options[] = {
    {"help",        no_argument,        NULL, 'h'},
    {"verbose",     no_argument,        NULL, 'v'},
    {"algorithm",   required_argument,  NULL, 'a'},
    {"prefix",      required_argument,  NULL, 'p'},
    {"exclude",     required_argument,  NULL, 'e'},
    {"check",       no_argument,        NULL, 'c'},
    {"verify",      no_argument,        NULL, 'c'},
    {"force",       no_argument,        NULL, 'f'},
    {"wipe",        no_argument,        NULL, 'w'},
    {"purge",       no_argument,        NULL, 'w'},
    { NULL,         no_argument,        NULL, 0}
};

int verbose_flag = 0;
int default_checksums_flag = 1;
int purge_flag = 0;

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

    if (!(ctx = parec_new())) {
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
                if (parec_add_checksum(ctx, optarg)) {
                    fprintf(stderr, "ERROR: %s\n", parec_get_error(ctx));
                    return 1;
                }
                default_checksums_flag = 0;
                break;
            case 'p':
                if (parec_set_xattr_prefix(ctx, optarg)) {
                    fprintf(stderr, "ERROR: %s\n", parec_get_error(ctx));
                    return 1;
                }
                break;
            case 'e':
                if (parec_add_exclude_pattern(ctx, optarg)) {
                    fprintf(stderr, "ERROR: %s\n", parec_get_error(ctx));
                    return 1;
                }
                break;
            case 'c':
                if (parec_set_method(ctx, PAREC_METHOD_CHECK)) {
                    fprintf(stderr, "ERROR: %s\n", parec_get_error(ctx));
                    return 1;
                }
                break;
            case 'f':
                if (parec_set_method(ctx, PAREC_METHOD_FORCE)) {
                    fprintf(stderr, "ERROR: %s\n", parec_get_error(ctx));
                    return 1;
                }
                break;
            case 'w':
                purge_flag = 1;
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
    if (default_checksums_flag) {
        if (parec_add_checksum(ctx, "md5") || parec_add_checksum(ctx, "sha1")) {
            fprintf(stderr, "ERROR: %s\n", parec_get_error(ctx));
            return 1;
        }
    }

    for (int i = 0; i < argc; i++) {
        if (purge_flag) {
            if (parec_purge(ctx, argv[i])) {
                fprintf(stderr, "ERROR: %s\n", parec_get_error(ctx));
                return 1;
            }
        }
        else {
            if (parec_process(ctx, argv[i])) {
                fprintf(stderr, "ERROR: %s\n", parec_get_error(ctx));
                return 1;
            }
            if (verbose_flag) {
                for (int a = 0; a < parec_get_checksum_count(ctx); a++) {
                    char *x_value = parec_get_xattr_value(ctx, a, argv[i]);
                    const char *a_name = parec_get_checksum_name(ctx, a);
                    if (!x_value || !a_name) {
                        fprintf(stderr, "ERROR: %s\n", parec_get_error(ctx));
                        return 1;
                    }
                    printf("%s(%s) = %s\n", a_name, argv[i], x_value);
                    free(x_value);
                }
            }
        }
    }

    parec_free(ctx);
}
