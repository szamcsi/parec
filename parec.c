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

#include <stdarg.h>
#define _GNU_SOURCE
#include <string.h>
#include <openssl/evp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <parec.h>
#include <parec_log4c.h>

struct _parec_ctx {
    int                         algorithms;    // number of algorithms
    int                         alg_len;       // allocation length of the alg arrays
    char                        **algorithm;
    const EVP_MD                **evp_algorithm;
    int                         evp_initialized;
    char                        **exclude;     // exclude patterns
    int                         excludes;      // number of exclude patterns
    int                         excl_len;      // allocation length of the exclude array
    const char                  *xattr_prefix;
    parec_verification_method   verify_method;
    parec_calculation_method    calc_method;
    char                        *error_message;
};

/* Buffer length for file operations. */
static const unsigned int BUFLEN = 1024 * 1024;
static const unsigned int ERRLEN = 300;
static const unsigned int XATTR_NAME_LEN = 255;
static const char default_xattr_prefix[] = "user.";
static const char mtime_xattr[] = "mtime";

static void parec_set_error(parec_ctx *ctx, char *fmt, ...)
{
    va_list ap;
    if (ctx->error_message)
        free(ctx->error_message);
        
    va_start(ap, fmt);
    ctx->error_message = calloc(sizeof(*(ctx->error_message)), ERRLEN);
    vsnprintf(ctx->error_message, ERRLEN, fmt, ap);
    va_end(ap);
}


const char *parec_get_error(parec_ctx *ctx)
{
    if(!ctx)
        return "Out of memory";

    if(!ctx->error_message)
        return "No error";

    return ctx->error_message;
}

parec_ctx *parec_new()
{
    parec_ctx *ctx;

    ctx = calloc(sizeof(*ctx), 1);
    if(!ctx)
        return NULL;
    
    // setting defaults and initializing structures
    ctx->algorithms = 0;
    ctx->alg_len = 10;
    ctx->algorithm = calloc(sizeof(*(ctx->algorithm)), ctx->alg_len);
    if(!ctx->algorithm) {
        parec_set_error(ctx, "parec: out of memory");
        return ctx;
    }
    ctx->evp_algorithm = calloc(sizeof(*(ctx->evp_algorithm)), ctx->alg_len);
    if(!ctx->evp_algorithm) {
        parec_set_error(ctx, "parec: out of memory");
        return ctx;
    }
    ctx->evp_initialized = 0;

    ctx->excludes = 0;
    ctx->excl_len = 10;
    ctx->exclude = calloc(sizeof(*(ctx->exclude)), ctx->excl_len);
    if(!ctx->exclude) {
        parec_set_error(ctx, "parec: out of memory");
        return ctx;
    }

    ctx->xattr_prefix = default_xattr_prefix;

    ctx->verify_method = PAREC_VERIFY_NO;
    ctx->calc_method = PAREC_CALC_DEFAULT;
    
    return ctx;
}

void parec_free(parec_ctx *ctx) 
{
    if(!ctx)
        return;

    for (int a = 0; a < ctx->algorithms; a++) {
        free(ctx->algorithm[a]);
        // do we really need to free this OpenSSL structure?
        //if (ctx->evp_initialized)
            //free(ctx->evp_algorithm[a]);
    }
    free(ctx->algorithm);
    free(ctx->evp_algorithm);

    for (int e = 0; e < ctx->excludes; e++) {
        free(ctx->exclude[e]);
    }
    free(ctx->exclude);

    if (ctx->xattr_prefix != default_xattr_prefix) 
        free((char *)ctx->xattr_prefix);
    
    if(ctx->error_message) 
        free(ctx->error_message);

    free(ctx);
}

static int parec_init_evp(parec_ctx *ctx) 
{
    if(!ctx)
        return -1;

    if (ctx->evp_initialized)
        return 0;

    OpenSSL_add_all_digests();
    for (int a = 0; a < ctx->algorithms; a++) {
        if(!(ctx->evp_algorithm[a] = EVP_get_digestbyname(ctx->algorithm[a]))) {
            parec_set_error(ctx, "Could not load digest: %s", ctx->algorithm[a]);
            return -1;
        }
        parec_log4c_DEBUG("OpenSSL digest %s is initialized", ctx->algorithm[a]);
    }
 
    ctx->evp_initialized = 1;
    return 0;
}

int parec_add_checksum(parec_ctx *ctx, const char *alg)
{
    if(!ctx)
        return -1;

    if (ctx->evp_initialized) {
        parec_set_error(ctx, "parec: checksums are already initialized, cannot add more");
        return -1;
    }

    if(!alg)
        return 0;

    // extending the algorithms array, if necessary
    if(ctx->algorithms == ctx->alg_len) {
        ctx->alg_len *= 2;
        ctx->algorithm = realloc(ctx->algorithm, sizeof(*(ctx->algorithm)) * ctx->alg_len);
        if(!ctx->algorithm) {
            parec_set_error(ctx, "parec: out of memory");
            return -1;
        }
    }

    // actually adding the algorithm name
    if(ctx->algorithms < ctx->alg_len) {
        ctx->algorithm[ctx->algorithms] = strdup(alg);
        if(!(ctx->algorithm[ctx->algorithms])) {
            parec_set_error(ctx, "parec: out of memory");
            return -1;
        }
        ctx->algorithms++;
    }

    return 0;
}

int parec_add_exclude_pattern(parec_ctx *ctx, const char *pattern)
{
    if(!ctx)
        return -1;

    if(!pattern)
        return 0;

    // extending the exclude array, if necessary
    if(ctx->excludes == ctx->alg_len) {
        ctx->excl_len *= 2;
        ctx->exclude = realloc(ctx->exclude, sizeof(*(ctx->exclude)) * ctx->excl_len);
        if(!ctx->exclude) {
            parec_set_error(ctx, "parec: out of memory");
            return -1;
        }
    }

    // actually adding the exclude pattern
    if(ctx->excludes < ctx->excl_len) {
        ctx->exclude[ctx->excludes] = strdup(pattern);
        if(!(ctx->exclude[ctx->excludes])) {
            parec_set_error(ctx, "parec: out of memory");
            return -1;
        }
        ctx->excludes++;
    }

    return 0;
}

int parec_set_xattr_prefix(parec_ctx *ctx, const char *prefix)
{
    if(!ctx)
        return -1;

    // covering the case, when strdup() is not needed
    if (prefix == default_xattr_prefix) {
        ctx->xattr_prefix = default_xattr_prefix;
        return 0;
    }

    // TODO: 
    //  - adding "user.", if missing
    //  - adding "." to the end, if missing
    ctx->xattr_prefix = strdup(prefix);
    if(!ctx->xattr_prefix) {
        parec_set_error(ctx, "parec: out of memory");
        return -1;
    }

    return 0;
}

int parec_set_verification_method(parec_ctx *ctx, parec_verification_method method)
{
    if(!ctx)
        return -1;

    ctx->verify_method = method;

    return 0;
}

int parec_set_calculation_method(parec_ctx *ctx, parec_calculation_method method)
{
    if(!ctx)
        return -1;

    ctx->calc_method = method;

    return 0;
}

int parec_file(parec_ctx *ctx, const char *filename) {
    int a,n,rc;
    unsigned char buffer[BUFLEN];
    char xattr_name[XATTR_NAME_LEN];
    EVP_MD_CTX *md_ctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen;
    time_t   start_mtime, end_mtime;
    struct stat p_stat;

    if((rc = parec_init_evp(ctx))) return rc;

    md_ctx = calloc(sizeof(*md_ctx), ctx->algorithms);
    if(!md_ctx) {
        parec_set_error(ctx, "parec: out of memory");
        return -1;
    }

    parec_log4c_DEBUG("Processing file '%s'", filename);

    // checking the modification time at the beginning
    if((rc = stat(filename, &p_stat))) {
        parec_set_error(ctx, "parec: could not stat %s (%d)", filename, rc);
        return -1;
    }
    start_mtime = p_stat.st_mtime;

    FILE *f = fopen(filename, "rb");
    if(!f) {
        parec_set_error(ctx, "parec: could not open file '%s'", filename);
        return -1;
    }

    // processing the file by blocks
    for (a = 0; a < ctx->algorithms; a++) {
        EVP_DigestInit(&md_ctx[a], ctx->evp_algorithm[a]);
    }
    while (feof(f) == 0) {
        n = fread(buffer, sizeof (unsigned char), BUFLEN, f);
        if (n > 0) {
            // processing one block
            for (a = 0; a < ctx->algorithms; a++) {
                EVP_DigestUpdate(&md_ctx[a], buffer, n);
            }
        }
    }
    // we already have the final block, so the file can be closed
    fclose(f);

    // checking the modification time at the end
    if((rc = stat(filename, &p_stat))) {
        parec_set_error(ctx, "parec: could not stat %s (%d)", filename, rc);
        return -1;
    }
    end_mtime = p_stat.st_mtime;

    if(start_mtime != end_mtime) {
        parec_set_error(ctx, "parec: file %s has been modified while processing", filename);
        return -1;
    }

    // generating the final checksum and storing it in an extended attribute
    for (a = 0; a < ctx->algorithms; a++) {
        EVP_DigestFinal (&md_ctx[a], digest, &dlen);
        // the extended attribute name = xattr_prefix + checksum_name
        strncpy(xattr_name, ctx->xattr_prefix, XATTR_NAME_LEN);
        strncpy(xattr_name + strlen(xattr_name), ctx->algorithm[a], 
            XATTR_NAME_LEN - strlen(xattr_name)); 
        parec_log4c_DEBUG("Storing xattr(%s)", xattr_name);
        if((rc = setxattr(filename, xattr_name, digest, dlen, XATTR_CREATE))) {
            parec_set_error(ctx, "parec: setting attribute %s has failed on %s with %d.\n", xattr_name, filename, rc);
        }
    }
    // storing the mtime, that we know of unchanged during processing
    strncpy(xattr_name, ctx->xattr_prefix, XATTR_NAME_LEN);
    strncpy(xattr_name + strlen(xattr_name), mtime_xattr,
        XATTR_NAME_LEN - strlen(xattr_name)); 
    parec_log4c_DEBUG("Storing xattr(%s)", xattr_name);
    if((rc = setxattr(filename, xattr_name, &start_mtime, sizeof(start_mtime), XATTR_CREATE))) {
        parec_set_error(ctx, "parec: setting attribute %s has failed on %s with %d.\n", xattr_name, filename, rc);
    }


    free(md_ctx);
    parec_log4c_DEBUG("Finished file '%s'", filename);
    return 0;
}


int parec_directory(parec_ctx *ctx, const char *dirname) {
    int rc;

    if((rc = parec_init_evp(ctx))) return rc;

    return 0;
}

