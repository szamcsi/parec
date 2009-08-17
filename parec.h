/**
 * parec -- Parallel Recursive Checksums
 *
 * Copyright (c) Akos FROHNER <akos@frohner.hu> 2009.
 * License: LGPLv2.1
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
 * Processing methods:
 * - DEFAULT, calculate new checksums, if they do not exists yet,
 *            or the file has changed since the last calculation
 * - CHECK, calculate new checksums, but only compare them with
 *          already stored values
 * - FORCE, calculate new cheksums, regarless of any stored value
 */
typedef enum {
    PAREC_METHOD_DEFAULT,
    PAREC_METHOD_CHECK,
    PAREC_METHOD_FORCE,
} parec_method;


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
 * Get the number of checksums in the context.
 * @param ctx   The parec context.
 * @return the number of checksum algorithms and -1 in case of an error.
 */
int parec_get_checksum_count(parec_ctx *ctx);

/**
 * Get the name of a given checksum.
 * @param ctx   The parec context.
 * @param idx   The index of the checksum.
 * @return the name of the checksum and NULL in case of an error.
 * The caller should not deallocate the returned string.
 */
const char *parec_get_checksum_name(parec_ctx *ctx, int idx);

/**
 * Get the name of the extended attribute for a given checksum algorithm.
 * @param ctx   The parec context.
 * @param idx   The index of the checksum.
 * @return the name of extended attribute for the checksum and NULL in case of an error.
 * The caller should not deallocate the returned string.
 */
const char *parec_get_xattr_name(parec_ctx *ctx, int idx);

/**
 * Get the value of the extended attribute for a given checksum algorithm.
 * @param ctx   The parec context.
 * @param idx   The index of the checksum.
 * @param name      The file or directory name.
 * @return the value of the checksum in hexadecimal encoding and NULL in case of an error.
 * The caller should deallocate the returned string.
 */
char *parec_get_xattr_value(parec_ctx *ctx, int idx, const char *name);

/**
 * Set processing method.
 * @param ctx       The parec context.
 * @param method    The calculation method.
 * @return 0 when successful and -1 in case of an error.
 */
int parec_set_method(parec_ctx *ctx, parec_method method);

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
 * Get the number of exclude patterns in the context.
 * @param ctx   The parec context.
 * @return the number of exclude patterns and -1 in case of an error.
 */
int parec_get_exclude_count(parec_ctx *ctx);

/**
 * Get the given exclude pattern.
 * @param ctx   The parec context.
 * @param idx   The index of the exclude pattern.
 * @return the exclude pattern and NULL in case of an error.
 * The caller should not deallocate the returned string.
 */
const char *parec_get_exclude_pattern(parec_ctx *ctx, int idx);

/**
 * Returns the error message for the last failed operation.
 * The returned pointer is valid only until the next call
 * to any of the library's functions with the same context.
 * @param ctx   The parec context.
 * @return  The error message string.
 */
const char *parec_get_error(parec_ctx *ctx);

/**
 * Process a file or directory.
 * The checksum values are set in extended attributes.
 * @param ctx       The parec context.
 * @param name      The file or directory name.
 * @return 0 when successful and -1 in case of an error.
 */
int parec_process(parec_ctx *ctx, const char *name);

/**
 * Purge a file or directory.
 * The checksum values are remove from the extended attributes recursively.
 * @param ctx       The parec context.
 * @param name      The file or directory name.
 * @return 0 when successful and -1 in case of an error.
 */
int parec_purge(parec_ctx *ctx, const char *name);

#ifdef __cplusplus
}
#endif

#endif /* _PAREC_H */
