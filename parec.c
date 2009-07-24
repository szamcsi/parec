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
#include <errno.h>
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
    char                        *xattr_prefix;
    char                        *xattr_mtime;
    char                        **xattr_algorithm;
    parec_method                method;
    char                        *error_message;
};

/* Buffer length for file operations. */
static const unsigned int BUFLEN = 1024 * 1024;
static const unsigned int ERRLEN = 300;
static const unsigned int XATTR_NAME_LEN = 230; // with overhead for 'user.' and alg.name
static const char DEFAULT_XATTR_PREFIX[] = "user.";
static const char MTIME_XATTR_NAME[] = "mtime";

static void _parec_set_error(parec_ctx *ctx, char *fmt, ...)
{
    va_list ap;
    if (ctx->error_message)
        free(ctx->error_message);
        
    va_start(ap, fmt);
    ctx->error_message = calloc(sizeof(*(ctx->error_message)), ERRLEN);
    vsnprintf(ctx->error_message, ERRLEN, fmt, ap);
    va_end(ap);
}

#define PAREC_ERROR(ctx, fmt, ...)  _parec_set_error(ctx, fmt,##__VA_ARGS__); \
                                    parec_log4c_ERROR(fmt,##__VA_ARGS__);

#define PAREC_CHECK_CONTEXT(ctx)    if(!ctx) { parec_log4c_ERROR("Context is not initialized"); return -1; }


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
        PAREC_ERROR(ctx, "parec: out of memory");
        return ctx;
    }
    ctx->xattr_algorithm = calloc(sizeof(*(ctx->xattr_algorithm)), ctx->alg_len);
    if(!ctx->xattr_algorithm) {
        PAREC_ERROR(ctx, "parec: out of memory");
        return ctx;
    }
    ctx->evp_algorithm = calloc(sizeof(*(ctx->evp_algorithm)), ctx->alg_len);
    if(!ctx->evp_algorithm) {
        PAREC_ERROR(ctx, "parec: out of memory");
        return ctx;
    }
    ctx->evp_initialized = 0;

    ctx->excludes = 0;
    ctx->excl_len = 10;
    ctx->exclude = calloc(sizeof(*(ctx->exclude)), ctx->excl_len);
    if(!ctx->exclude) {
        PAREC_ERROR(ctx, "parec: out of memory");
        return ctx;
    }

    if(parec_set_method(ctx, PAREC_METHOD_DEFAULT)) {
        parec_free(ctx);
        return NULL;
    }

    if(parec_set_xattr_prefix(ctx, DEFAULT_XATTR_PREFIX)) {
        parec_free(ctx);
        return NULL;
    }
    
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
        free(ctx->xattr_algorithm[a]);
    }
    free(ctx->algorithm);
    free(ctx->evp_algorithm);
    free(ctx->xattr_algorithm);

    for (int e = 0; e < ctx->excludes; e++) {
        free(ctx->exclude[e]);
    }
    free(ctx->exclude);

    free(ctx->xattr_prefix);
    free(ctx->xattr_mtime);
    
    if(ctx->error_message) 
        free(ctx->error_message);

    free(ctx);
}

static int parec_init_evp(parec_ctx *ctx) 
{
    PAREC_CHECK_CONTEXT(ctx)

    if (ctx->evp_initialized)
        return 0;

    OpenSSL_add_all_digests();
    for (int a = 0; a < ctx->algorithms; a++) {
        if(!(ctx->evp_algorithm[a] = EVP_get_digestbyname(ctx->algorithm[a]))) {
            PAREC_ERROR(ctx, "Could not load digest: %s", ctx->algorithm[a]);
            return -1;
        }
        parec_log4c_DEBUG("OpenSSL digest %s is initialized", ctx->algorithm[a]);
    }
 
    ctx->evp_initialized = 1;
    return 0;
}

// we can assume that the context is initialized and xattr_prefix is set
static char *_parec_xattr_name(parec_ctx *ctx, const char *name)
{
    char *x_name;

    x_name = malloc(strlen(ctx->xattr_prefix) + strlen(name) + 1);
    if(!x_name)
        // the calling context will set the proper error message
        return NULL;

    strcpy(x_name, ctx->xattr_prefix);
    strcat(x_name, name);

    return x_name;
}

int parec_add_checksum(parec_ctx *ctx, const char *alg)
{
    PAREC_CHECK_CONTEXT(ctx)

    if (ctx->evp_initialized) {
        PAREC_ERROR(ctx, "parec: checksums are already initialized, cannot add more");
        return -1;
    }

    if(!alg)
        return 0;

    // extending the algorithms array, if necessary
    if(ctx->algorithms == ctx->alg_len) {
        ctx->alg_len *= 2;
        ctx->algorithm = realloc(ctx->algorithm, sizeof(*(ctx->algorithm)) * ctx->alg_len);
        if(!ctx->algorithm) {
            PAREC_ERROR(ctx, "parec: out of memory");
            return -1;
        }
        ctx->xattr_algorithm = realloc(ctx->xattr_algorithm, sizeof(*(ctx->xattr_algorithm)) * ctx->alg_len);
        if(!ctx->xattr_algorithm) {
            PAREC_ERROR(ctx, "parec: out of memory");
            return -1;
        }
    }

    // actually adding the algorithm name
    if(ctx->algorithms < ctx->alg_len) {
        ctx->algorithm[ctx->algorithms] = strdup(alg);
        if(!(ctx->algorithm[ctx->algorithms])) {
            PAREC_ERROR(ctx, "parec: out of memory");
            return -1;
        }
        ctx->xattr_algorithm[ctx->algorithms] = _parec_xattr_name(ctx, alg);
        if(!(ctx->xattr_algorithm[ctx->algorithms])) {
            PAREC_ERROR(ctx, "parec: out of memory");
            return -1;
        }
        ctx->algorithms++;
    }

    return 0;
}

int parec_get_checksum_count(parec_ctx *ctx)
{
    PAREC_CHECK_CONTEXT(ctx)

    return ctx->algorithms;
}

const char *parec_get_checksum_name(parec_ctx *ctx, int idx) 
{
    if(!ctx)
        return NULL;

    if(idx < 0 || idx >= ctx->algorithms) {
        PAREC_ERROR(ctx, "parec: index %d is out of range [0,%d)", idx, ctx->algorithms);
        return NULL;
    }

    return ctx->algorithm[idx];
}

const char *parec_get_xattr_name(parec_ctx *ctx, int idx) 
{
    if(!ctx)
        return NULL;

    if(idx < 0 || idx >= ctx->algorithms) {
        PAREC_ERROR(ctx, "parec: index %d is out of range [0,%d)", idx, ctx->algorithms);
        return NULL;
    }

    return ctx->xattr_algorithm[idx];
}

int parec_add_exclude_pattern(parec_ctx *ctx, const char *pattern)
{
    PAREC_CHECK_CONTEXT(ctx)

    if(!pattern)
        return 0;

    // extending the exclude array, if necessary
    if(ctx->excludes == ctx->alg_len) {
        ctx->excl_len *= 2;
        ctx->exclude = realloc(ctx->exclude, sizeof(*(ctx->exclude)) * ctx->excl_len);
        if(!ctx->exclude) {
            PAREC_ERROR(ctx, "parec: out of memory");
            return -1;
        }
    }

    // actually adding the exclude pattern
    if(ctx->excludes < ctx->excl_len) {
        ctx->exclude[ctx->excludes] = strdup(pattern);
        if(!(ctx->exclude[ctx->excludes])) {
            PAREC_ERROR(ctx, "parec: out of memory");
            return -1;
        }
        ctx->excludes++;
    }

    return 0;
}

int parec_set_xattr_prefix(parec_ctx *ctx, const char *prefix)
{
    int x_len;
    PAREC_CHECK_CONTEXT(ctx)

    // deallocating the allocated structures
    for (int a = 0; a < ctx->algorithms; a++) {
        free(ctx->xattr_algorithm[a]);
    }
    free(ctx->xattr_prefix);
    free(ctx->xattr_mtime);

    // if not specified, use the default
    if(!prefix) 
        prefix = DEFAULT_XATTR_PREFIX;

    if(strlen(prefix) > XATTR_NAME_LEN) {
        PAREC_ERROR(ctx, "parec: xattr prefix is too long (%d > %d): %s", strlen(prefix), XATTR_NAME_LEN, prefix);
        return -1;
    }

    // check, if it starts with "user."
    if(strncmp(DEFAULT_XATTR_PREFIX, prefix, strlen(DEFAULT_XATTR_PREFIX))) {
        ctx->xattr_prefix = malloc(strlen(DEFAULT_XATTR_PREFIX) + strlen(prefix) + 1);
        if(!ctx->xattr_prefix) {
            PAREC_ERROR(ctx, "parec: out of memory");
            return -1;
        }
        strcpy(ctx->xattr_prefix, DEFAULT_XATTR_PREFIX); 
        strcat(ctx->xattr_prefix, prefix);
    }
    else {
        ctx->xattr_prefix = strdup(prefix);
        if(!ctx->xattr_prefix) {
            PAREC_ERROR(ctx, "parec: out of memory");
            return -1;
        }
    }

    // check, if it ends with "."
    x_len = strlen(ctx->xattr_prefix);
    if(ctx->xattr_prefix[x_len - 1] != '.') {
        x_len++;
        ctx->xattr_prefix = realloc(ctx->xattr_prefix, x_len);
        if(!ctx->xattr_prefix) {
            PAREC_ERROR(ctx, "parec: out of memory");
            return -1;
        }
        ctx->xattr_prefix[x_len - 1] = '.';
        ctx->xattr_prefix[x_len] = '\0';
    }

    // setting derived attributes
    for (int a = 0; a < ctx->algorithms; a++) {
        ctx->xattr_algorithm[a] = _parec_xattr_name(ctx, ctx->algorithm[a]);
        if(!(ctx->xattr_algorithm[a])) {
            PAREC_ERROR(ctx, "parec: out of memory");
            return -1;
        }
    }
    ctx->xattr_mtime = _parec_xattr_name(ctx, MTIME_XATTR_NAME);
    if(!ctx->xattr_mtime) {
        PAREC_ERROR(ctx, "parec: out of memory");
        return -1;
    }

    return 0;
}

int parec_set_method(parec_ctx *ctx, parec_method method)
{
    PAREC_CHECK_CONTEXT(ctx)

    ctx->method = method;

    return 0;
}

/* Purging extended attributes */
static int _parec_purge(parec_ctx *ctx, const char *name)
{
    int rc;
    for (int a = 0; a < ctx->algorithms; a++) {
        parec_log4c_DEBUG("Removing xattr(%s)", ctx->xattr_algorithm[a]);
        // sliently ignoring, if the attribute was not set before
        if((rc = removexattr(name, ctx->xattr_algorithm[a])) && (errno != ENODATA)) {
            PAREC_ERROR(ctx, "parec: removing attribute %s has failed on %s with '%s(%d)'.\n", ctx->xattr_algorithm[a], name, strerror(errno), errno);
            return -1;
        }
    }
    parec_log4c_DEBUG("Removing xattr(%s)", ctx->xattr_mtime);
    // sliently ignoring, if the attribute was not set before
    if((rc = removexattr(name, ctx->xattr_mtime)) && (errno != ENODATA)) {
        PAREC_ERROR(ctx, "parec: removing attribute %s has failed on %s with '%s(%d)'.\n", ctx->xattr_mtime, name, strerror(errno), errno);
        return -1;
    }
    return 0;
}

int parec_file(parec_ctx *ctx, const char *filename) {
    int a,n,rc;
    unsigned char buffer[BUFLEN];
    EVP_MD_CTX *md_ctx;
    unsigned char digest[EVP_MAX_MD_SIZE], x_digest[EVP_MAX_MD_SIZE];
    unsigned int dlen;
    time_t   start_mtime, end_mtime, x_mtime = 0;
    struct stat p_stat;

    PAREC_CHECK_CONTEXT(ctx)

    if (ctx->method == PAREC_METHOD_PURGE) {
        return _parec_purge(ctx, filename);
    }

    if (ctx->method == PAREC_METHOD_FORCE) {
        if(_parec_purge(ctx, filename)) {
            return -1;
        }
    }

    parec_log4c_DEBUG("Processing file '%s'", filename);

    // checking the modification time at the beginning
    if((rc = stat(filename, &p_stat))) {
        PAREC_ERROR(ctx, "parec: could not stat %s (%d)", filename, rc);
        return -1;
    }
    start_mtime = p_stat.st_mtime;

    // trying to check, if the file was modified since the last calculation,
    // and skip the rest, if it was not modified
    if (ctx->method != PAREC_METHOD_CHECK) {
        if((rc = getxattr(filename, ctx->xattr_mtime, &x_mtime, sizeof(x_mtime))) < 0 && (errno != ENODATA)) {
            PAREC_ERROR(ctx, "parec: fetching attribute %s has failed on %s with '%s(%d)'.\n", ctx->xattr_mtime, filename, strerror(errno), errno);
            return -1;
        }
        else if (rc == sizeof(x_mtime)) {
            parec_log4c_DEBUG("comparing actual (%d) and stored (%d) mtime", start_mtime, x_mtime);
            if (start_mtime == x_mtime) {
                parec_log4c_INFO("checksums are already calculated, skipping '%s'", filename);
                return 0;
            }
        }
    }

    // the checksums need to be actually calculated
    if((rc = parec_init_evp(ctx))) return rc;

    md_ctx = calloc(sizeof(*md_ctx), ctx->algorithms);
    if(!md_ctx) {
        PAREC_ERROR(ctx, "parec: out of memory");
        return -1;
    }


    FILE *f = fopen(filename, "rb");
    if(!f) {
        PAREC_ERROR(ctx, "parec: could not open file '%s'", filename);
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
        PAREC_ERROR(ctx, "parec: could not stat %s (%d)", filename, rc);
        return -1;
    }
    end_mtime = p_stat.st_mtime;

    if(start_mtime != end_mtime) {
        _parec_purge(ctx, filename);
        PAREC_ERROR(ctx, "parec: file %s has been modified while processing", filename);
        return -1;
    }

    // generating the final checksum and
    //      storing it in an extended attribute or
    //      comparing it with a previous value
    for (a = 0; a < ctx->algorithms; a++) {
        EVP_DigestFinal (&md_ctx[a], digest, &dlen);
        if (ctx->method != PAREC_METHOD_CHECK) {
            parec_log4c_DEBUG("Storing xattr(%s)", ctx->xattr_algorithm[a]);
            if((rc = setxattr(filename, ctx->xattr_algorithm[a], digest, dlen, 0))) {
                PAREC_ERROR(ctx, "parec: setting attribute %s has failed on %s with '%s(%d)'.\n", ctx->xattr_algorithm[a], filename, strerror(errno), errno);
                return -1;
            }
        }
        else {
            parec_log4c_DEBUG("Comparing xattr(%s)", ctx->xattr_algorithm[a]);
            if((rc = getxattr(filename, ctx->xattr_algorithm[a], &x_digest, EVP_MAX_MD_SIZE)) < 0 && (errno != ENODATA)) {
                PAREC_ERROR(ctx, "parec: fetching attribute %s has failed on %s with '%s(%d)'.\n", ctx->xattr_algorithm[a], filename, strerror(errno), errno);
                return -1;
            }
            else if ((rc != dlen) || memcmp(digest, x_digest, dlen)) {
                PAREC_ERROR(ctx, "parec: checksums (%s) do not match", ctx->algorithm[a]);
                return -1;
            }
            else {
                parec_log4c_INFO("parec: checksums (%s) do match", ctx->algorithm[a]);
            }
        }
    }

    // storing the mtime, that we know of unchanged during processing
    if (x_mtime == 0 || ctx->method == PAREC_METHOD_FORCE) {
        parec_log4c_DEBUG("Storing xattr(%s)", ctx->xattr_mtime);
        if((rc = setxattr(filename, ctx->xattr_mtime, &start_mtime, sizeof(start_mtime), 0))) {
            PAREC_ERROR(ctx, "parec: setting attribute %s has failed on %s with '%s(%d)'.\n", ctx->xattr_mtime, filename, strerror(errno), errno);
            return -1;
        }
    }


    free(md_ctx);
    parec_log4c_DEBUG("Finished file '%s'", filename);
    return 0;
}


int parec_directory(parec_ctx *ctx, const char *dirname) {
    int rc;

    PAREC_CHECK_CONTEXT(ctx)

    if (ctx->method == PAREC_METHOD_PURGE) {
        return _parec_purge(ctx, dirname);
    }

    if((rc = parec_init_evp(ctx))) return rc;

    return 0;
}

