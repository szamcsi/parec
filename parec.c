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
#include <stdlib.h>
#include <errno.h>
#include <openssl/evp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
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
static const unsigned int PATHLEN = 1024;
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

static const char *_parec_hex(char *hex, const unsigned char *digest, int len) {
    for (int i = 0; i < len; i++) {
        sprintf(hex + i * 2, "%02x", digest[i]);
    }
    hex[len * 2 + 1] = '\0';
    return hex;
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

static int _parec_file(parec_ctx *ctx, const char *filename, EVP_MD_CTX *md_ctx) {
    int a,n;
    unsigned char buffer[BUFLEN];

    // processing the file by blocks
    FILE *f = fopen(filename, "rb");
    if(!f) {
        PAREC_ERROR(ctx, "parec: could not open file '%s'", filename);
        return -1;
    }
    while (feof(f) == 0) {
        n = fread(buffer, sizeof (unsigned char), BUFLEN, f);
        if (n > 0) {
            // processing one block
            for (a = 0; a < ctx->algorithms; a++) {
                if(EVP_DigestUpdate(&md_ctx[a], buffer, n) != 1) {
                    PAREC_ERROR(ctx, "parec: calculating digest '%s' has failed", ctx->algorithm[a]);
                    return -1;
                }
            }
        }
    }
    // we already have the final block, so the file can be closed
    fclose(f);

    return 0;
}

// filterint the directory entries
static int _parec_filter(parec_ctx *ctx, const char *dname) 
{
    // skip '.' and '..'
    if ((dname[0] == '.') 
        && (dname[1] == '\0' 
            || (dname[1] == '.' && dname[2] == '\0')))
        return -1;
    // TODO: some more filtering
    return 0;
}


// The directory checksum is the checksum of the entry checksums.
// To be independent of the order or name of the entries, the 
// checksums of the entries has to be ordered by the checksums
// themselves.
//
// There are a number of possibilities:
// 1. double scan
//      process each entry and count them
//      allocate checksum arrays
//      fetch the checksums from the extended attributes
//      sort the arrays
//      calculate the directory checksum based on the arrays
// 
// 2. dynamic allocation
//      merge the above two loops into a single loop by dynamically
//      reallocating the checksum arrays, if they are not big enough
// 
// 3. dynamic heap
//      merge the sort step into the loop by maintaining a sorted structure
//
// 2.a returning checksums
//      instead of passing attributes through extended attributes
//      the processing function could return them to the calling
//      context directly

static int _parec_directory(parec_ctx *ctx, const char *dirname, EVP_MD_CTX *md_ctx) {
    int dcount = 0;
    struct dirent *p_dirent;
    char full_name[PATHLEN], full_dirname[PATHLEN], hex[EVP_MAX_MD_SIZE*2+1];
    unsigned char **x_digest, x_digest_tmp[EVP_MAX_MD_SIZE];
    int *x_dlen, x_dlen_tmp, a;
    unsigned int max_name_len;

    DIR *d = opendir(dirname);
    if(!d) {
        PAREC_ERROR(ctx, "parec: could not open directory '%s'", dirname);
        return -1;
    }

    // pre-calculating the directory name
    strncpy(full_dirname, dirname, PATHLEN);
    max_name_len = strlen(full_dirname);
    if (max_name_len == PATHLEN) {
        PAREC_ERROR(ctx, "parec: too long name '%s'", dirname);
        return -1;
    }
    // make sure there is a slash at the end
    if (full_dirname[max_name_len - 1] != '/') {
        max_name_len++;
        full_dirname[max_name_len - 1] = '/';
        full_dirname[max_name_len] = '\0';
    }
    max_name_len = PATHLEN - max_name_len;
    parec_log4c_DEBUG("full_dirname = %s", full_dirname);

    // the array to hold the pointer to the array of digests
    x_digest = calloc(sizeof(*(x_digest)), ctx->algorithms);
    if(!x_digest) {
        PAREC_ERROR(ctx, "parec: out of memory");
        return -1;
    }
    // the array to hold the digest lengths
    x_dlen = calloc(sizeof(*(x_dlen)), ctx->algorithms);
    if(!x_dlen) {
        PAREC_ERROR(ctx, "parec: out of memory");
        return -1;
    }

    while ((p_dirent = readdir(d)) != NULL) {
        if (_parec_filter(ctx, p_dirent->d_name)) continue;
        strncpy(full_name, full_dirname, PATHLEN);
        strncat(full_name, p_dirent->d_name, max_name_len); 
        parec_log4c_DEBUG("1. processing '%s' for directory '%s'", full_name, dirname);
        if (parec_process(ctx, full_name)) return -1;
        dcount++;
    }
    parec_log4c_DEBUG("# processed entries: %d", dcount);

    rewinddir(d);

    int i = 0;
    while ((p_dirent = readdir(d)) != NULL && (i <= dcount)) {
        if (_parec_filter(ctx, p_dirent->d_name)) continue;
        strncpy(full_name, full_dirname, PATHLEN);
        strncat(full_name, p_dirent->d_name, max_name_len); 
        parec_log4c_DEBUG("2. processing '%s' for directory '%s'", full_name, dirname);
        for (a = 0; a < ctx->algorithms; a++) {
            // we have to allocate an array for the digests at the first time
            // we know the exact size of one digest of a particular algorithm
            if (!x_dlen[a]) {
                if((x_dlen[a] = getxattr(full_name, ctx->xattr_algorithm[a], &x_digest_tmp, EVP_MAX_MD_SIZE)) < 0 && (errno != ENODATA)) {
                    PAREC_ERROR(ctx, "parec: fetching attribute %s has failed on %s with '%s(%d)'.\n", ctx->xattr_algorithm[a], full_name, strerror(errno), errno);
                }
                // allocating the array of (dcount * (x_dlen[a] + 1))
                x_digest[a] = calloc(sizeof(**(x_digest)), (x_dlen[a] + 1) * dcount);
                if(!x_digest[a]) {
                    PAREC_ERROR(ctx, "parec: out of memory");
                    return -1;
                }
            }
            // normal case
            if((x_dlen_tmp = getxattr(full_name, ctx->xattr_algorithm[a], x_digest[a] + i * (x_dlen[a] + 1), EVP_MAX_MD_SIZE)) < 0 && (errno != ENODATA)) {
                PAREC_ERROR(ctx, "parec: fetching attribute %s has failed on %s with '%s(%d)'.\n", ctx->xattr_algorithm[a], full_name, strerror(errno), errno);
                return -1;
            }
            if (x_dlen_tmp != x_dlen[a]) {
                PAREC_ERROR(ctx, "parec: fetched an ivalid size (%d) digest entry from file '%s' (expected: %d for %s)", x_dlen_tmp, full_name, x_dlen[a], ctx->xattr_algorithm[a]);
                return -1;
            }
            parec_log4c_DEBUG("%s(%d:%s) = 0x%s", ctx->xattr_algorithm[a], i, full_name, _parec_hex(hex, x_digest[a] + i * (x_dlen[a] + 1), x_dlen[a]));
        }
        i++;
    }

    if (closedir(d)) {
        PAREC_ERROR(ctx, "parec: failed to close directory '%s' with '%s(%d)'.\n", dirname, strerror(errno), errno);
        return -1;
    }

    // sorting the checksums and calculating the digests
    for (a = 0; a < ctx->algorithms; a++) {
        qsort(x_digest[a], dcount, x_dlen[a] + 1, (__compar_fn_t)strcmp);
        for (int i = 0; i < dcount; i++) {
            if(EVP_DigestUpdate(&md_ctx[a], x_digest[a] + i * (x_dlen[a] + 1), x_dlen[a]) != 1) {
                PAREC_ERROR(ctx, "parec: calculating digest '%s' has failed", ctx->algorithm[a]);
                return -1;
            }
            parec_log4c_DEBUG("%s(%d) = 0x%s", ctx->xattr_algorithm[a], i, _parec_hex(hex, x_digest[a] + i * (x_dlen[a] + 1), x_dlen[a]));
        }
        free(x_digest[a]);
    }
    free(x_digest);
    free(x_dlen);

    return 0;
}

int parec_process(parec_ctx *ctx, const char *name) {
    int a,rc;
    EVP_MD_CTX *md_ctx;
    unsigned char digest[EVP_MAX_MD_SIZE], x_digest[EVP_MAX_MD_SIZE];
    unsigned int dlen;
    time_t   start_mtime, end_mtime, x_mtime = 0;
    struct stat p_stat;

    PAREC_CHECK_CONTEXT(ctx)

    if (ctx->method == PAREC_METHOD_PURGE) {
        return _parec_purge(ctx, name);
    }

    if (ctx->method == PAREC_METHOD_FORCE) {
        if(_parec_purge(ctx, name)) {
            return -1;
        }
    }

    parec_log4c_DEBUG("Processing '%s'", name);

    // checking the modification time at the beginning
    if((rc = stat(name, &p_stat))) {
        PAREC_ERROR(ctx, "parec: could not stat %s (%d)", name, rc);
        return -1;
    }
    start_mtime = p_stat.st_mtime;

    // trying to check, if the file was modified since the last calculation,
    // and skip the rest, if it was not modified
    if (ctx->method != PAREC_METHOD_CHECK) {
        if((rc = getxattr(name, ctx->xattr_mtime, &x_mtime, sizeof(x_mtime))) < 0 && (errno != ENODATA)) {
            PAREC_ERROR(ctx, "parec: fetching attribute %s has failed on %s with '%s(%d)'.\n", ctx->xattr_mtime, name, strerror(errno), errno);
            return -1;
        }
        else if (rc == sizeof(x_mtime)) {
            parec_log4c_DEBUG("comparing actual (%d) and stored (%d) mtime", start_mtime, x_mtime);
            if (start_mtime == x_mtime) {
                parec_log4c_INFO("checksums are already calculated, skipping '%s'", name);
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

    for (a = 0; a < ctx->algorithms; a++) {
        if(EVP_DigestInit(&md_ctx[a], ctx->evp_algorithm[a]) != 1) {
            PAREC_ERROR(ctx, "parec: initializing digest '%s' has failed", ctx->algorithm[a]);
            return -1;
        }
    }

    // the processing function can assume that the entry has not been changed,
    // while processing, otherwise it is going to be detected by the calling
    // context
    if (S_ISREG(p_stat.st_mode)) {
        if(_parec_file(ctx, name, md_ctx)) return -1;
    }
    else if (S_ISDIR(p_stat.st_mode)) {
        if(_parec_directory(ctx, name, md_ctx)) return -1;
    }
    else {
        PAREC_ERROR(ctx, "parec: unknown entry type of '%s'", name);
        return -1;
    }

    // checking the modification time at the end
    if((rc = stat(name, &p_stat))) {
        PAREC_ERROR(ctx, "parec: could not stat %s (%d)", name, rc);
        return -1;
    }
    end_mtime = p_stat.st_mtime;

    if(start_mtime != end_mtime) {
        _parec_purge(ctx, name);
        PAREC_ERROR(ctx, "parec: file %s has been modified while processing", name);
        return -1;
    }

    // generating the final checksum and
    //      storing it in an extended attribute or
    //      comparing it with a previous value
    for (a = 0; a < ctx->algorithms; a++) {
        if(EVP_DigestFinal (&md_ctx[a], digest, &dlen) != 1) {
            PAREC_ERROR(ctx, "parec: finalizing digest '%s' has failed", ctx->algorithm[a]);
            return -1;
        }
        if (ctx->method != PAREC_METHOD_CHECK) {
            parec_log4c_DEBUG("Storing xattr(%s)", ctx->xattr_algorithm[a]);
            if((rc = setxattr(name, ctx->xattr_algorithm[a], digest, dlen, 0))) {
                PAREC_ERROR(ctx, "parec: setting attribute %s has failed on %s with '%s(%d)'.\n", ctx->xattr_algorithm[a], name, strerror(errno), errno);
                return -1;
            }
        }
        else {
            parec_log4c_DEBUG("Comparing xattr(%s)", ctx->xattr_algorithm[a]);
            if((rc = getxattr(name, ctx->xattr_algorithm[a], &x_digest, EVP_MAX_MD_SIZE)) < 0 && (errno != ENODATA)) {
                PAREC_ERROR(ctx, "parec: fetching attribute %s has failed on %s with '%s(%d)'.\n", ctx->xattr_algorithm[a], name, strerror(errno), errno);
                return -1;
            }
            else if ((rc != (int)dlen) || memcmp(digest, x_digest, dlen)) {
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
        if((rc = setxattr(name, ctx->xattr_mtime, &start_mtime, sizeof(start_mtime), 0))) {
            PAREC_ERROR(ctx, "parec: setting attribute %s has failed on %s with '%s(%d)'.\n", ctx->xattr_mtime, name, strerror(errno), errno);
            return -1;
        }
    }


    free(md_ctx);
    parec_log4c_DEBUG("Finished '%s'", name);
    return 0;
}

