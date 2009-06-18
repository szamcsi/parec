/*
 * checksums -- calculating multiple checksums in parallel
 *
 * Copyright, 2009.
 *   Akos FROHNER <akos@frohner.hu>
 * Licence: Apache2, GPLv2
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <sys/xattr.h>

int algorithms = 2;
unsigned char ns_prefix[] = "user.";
unsigned char *algorithm[] = { "sha1", "md5" };
const EVP_MD *evp_algorithm[2];
unsigned char *digest[2];
unsigned int dlen[2];
const unsigned int BUFLEN = 1024 * 1024;

void print_hex(unsigned char *bs, unsigned int n) {
    for(int i = 0; i < n; i++) {
        printf("%02x", bs[i]);
    }
}

int process_file(char *fname) {
    int n,rc;
    unsigned char buffer[BUFLEN];
    EVP_MD_CTX ctx[2];

    FILE *f = fopen(fname, "rb");
    if(!f) {
        perror(fname);
        return 1;
    }

    // processing the file by blocks
    for (int a = 0; a < algorithms; a++) {
        EVP_DigestInit(&ctx[a], evp_algorithm[a]);
    }
    while (feof(f) == 0) {
        n = fread(buffer, sizeof (unsigned char), BUFLEN, f);
        if (n > 0) {
            // processing one block
            for (int a = 0; a < algorithms; a++) {
                EVP_DigestUpdate(&ctx[a], buffer, n);
            }
        }
    }
    for (int a = 0; a < algorithms; a++) {
        EVP_DigestFinal (&ctx[a], digest[a], &(dlen[a]));
    }

    fclose(f);
    for (int a = 0; a < algorithms; a++) {
        printf("%s(%s) = ", algorithm[a], fname);
        print_hex(digest[a], dlen[a]);
        printf("\n");
        strncpy(buffer, ns_prefix, BUFLEN);
        strncpy(buffer + sizeof(ns_prefix) - 1, algorithm[a], BUFLEN - sizeof(ns_prefix)); 
        if(rc = setxattr(fname, buffer, digest[a], dlen[a], XATTR_CREATE)) {
            fprintf(stderr, "Setting attribute %s has failed on %s with %d.\n", buffer, fname, rc);
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    OpenSSL_add_all_digests();
    for (int a = 0; a < algorithms; a++) {
        if(!(evp_algorithm[a] = EVP_get_digestbyname(algorithm[a]))) {
            fprintf(stderr, "Could not load digest: %s\n", algorithm[a]);
            return 1;
        }
        if(!(digest[a] = (unsigned char *) malloc(EVP_MAX_MD_SIZE))) {
            fprintf(stderr, "Could not allocate memory for the digest (%s)\n", algorithm[a]);
            return 1;
        }
    }


    for (int i = 1; i < argc; i++) {
        process_file(argv[i]);
    }
}
