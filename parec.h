/**
 * Copyright (c) Akos FROHNER <akos@frohner.hu> 2009.
 * Licence: Apache2, GPLv2
 *
 * parec -- Parallel Recursive Checksums
 *
 */

#ifndef _PAREC_H
#define _PAREC_H

#ifdef __cplusplus
extern "C" {
#endif

/**********************************************************************
 * General guidelines:
 * - Functions that return a pointer return NULL when there is an error.
 * - Functions that return 'int' return 0 when successful and -1 in case
 *   of an error.
 * - Any objects returned by a function is owned by the caller and has to
 *   be deallocated by the caller.
 */

/**
 * Verification levels:
 * - NO, do not compare calculated checksums to already stored values
 * - MTIME, compare if there is already a stored value and mtime
 *          is later than the stored value
 * - IF_EXISTS, compare, if there is already a stored value
 * - STRICT, fail comparison, if there was no stored value
 */
typedef enum {
    PAREC_VERIFY_NO,
    PAREC_VERIFY_MTIME,
    PAREC_VERIFY_IF_EXISTS,
    PAREC_VERIFY_STRICT
} parec_verification_method;

/**
 * Calculation modes:
 * - DEFAULT, calculate new checksums, if they do not exists yet
 * - FORCE, calculate new cheksums, regarless of any stored value
 * - PURGE, delete checksums, instead of storing them
 */
typedef enum {
    PAREC_CALC_DEFAULT,
    PAREC_CALC_FORCE,
    PAREC_CALC_PURGE
} parec_calculation_method;


/* Opaque data structure used by the library. */
typedef struct _parec_ctx   parec_ctx;

/**
 * Allocates a new parec context.
 * @return      The context or NULL if memory allocation has failed.
 */
parec_ctx *parec_new(void);

/**
 * Free the context.
 * @param ctx   The parec context to be disposed.
 */
void parec_free(parec_ctx *ctx);

/**
 * Add a new checksum algorithm to be used during calculations.
 * @param ctx   The parec context.
 * @param alg   The name of the algorithm.
 * @return 0 when successful and -1 in case of an error.
 */
int parec_add_checksum(parec_ctx *ctx, const char *alg);

/**
 * Set verification method.
 * @param ctx       The parec context.
 * @param method    The verification method.
 * @return 0 when successful and -1 in case of an error.
 */
int parec_set_verification_method(parec_ctx *ctx, parec_verification_method method);

/**
 * Set calculation method.
 * @param ctx       The parec context.
 * @param method    The calculation method.
 * @return 0 when successful and -1 in case of an error.
 */
int parec_set_calculation_method(parec_ctx *ctx, parec_calculation_method method);

/**
 * Set the name prefix of the extended attributes.
 * The default name for an SHA1 checksum is "user.sha1".
 * If the prefix is set to "se1", then the full name of
 * the extended attribute becomes "user.se1.sha1".
 * @param ctx       The parec context.
 * @param prefix    The extended attribute name prefix.
 * @return 0 when successful and -1 in case of an error.
 */
int parec_set_xattr_prefix(parec_ctx *ctx, const char *prefix);

/**
 * Add an exclude pattern for the directory operations.
 * The directory checksum calculation will skip files, 
 * which match with any of the added glob(3) patterns.
 * For example "*~" will skip all filenames ending with '~'.
 * @param ctx       The parec context.
 * @param pattern   The glob pattern to be added.
 * @return 0 when successful and -1 in case of an error.
 */
int parec_add_exclude_pattern(parec_ctx *ctx, const char *pattern);

/**
 * Returns the error message for the last failed operation.
 * The returned pointer is valid only until the next call
 * to any of the library's functions with the same context.
 * @param ctx   The parec context.
 * @return  The error message string.
 */
const char *parec_get_error(parec_ctx *ctx);

/**
 * Process a file.
 * The checksum values are set in extended attributes.
 * @param ctx       The parec context.
 * @param filename  The file name.
 * @return 0 when successful and -1 in case of an error.
 */
int parec_file(parec_ctx *ctx, const char *filename);

/**
 * Process a directory.
 * The checksum values are set in the extended attributes.
 * @param ctx       The parex context.
 * @param dirname   The directory name.
 * @return 0 when successful and -1 in case of an error.
 */
int parec_directory(parec_ctx *ctx, const char *dirname);

#ifdef __cplusplus
}
#endif

#endif /* _PAREC_H */