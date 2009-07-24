/**
 * Copyright (c) Akos FROHNER <akos@frohner.hu> 2009.
 * Licence: Apache2, GPLv2
 *
 * log4c -- simple logging library for C
 *
 */

#ifndef _PAREC_LOG4C_H
#define _PAREC_LOG4C_H

#ifdef __cplusplus
extern "C" {
#endif

/* Name of the environment variable holding the log level. */
#define PAREC_LOG_LEVEL "PAREC_LOG_LEVEL"
/* Name of the environment variable holding the log filename. */
#define PAREC_LOG_FILE  "PAREC_LOG_FILE"

/** 
 * The parec_log4c_init() function initializes the common logging facility.
 *
 * PAREC_LOG_LEVEL environmental variable sets the log level,
 * if left empty, then no logging is performed. Acceptable values
 * are: DEBUG, INFO, WARN, ERROR
 *
 * PAREC_LOG_FILE may specify a file, where the logs are written.
 * If not set, then they are written to stdout.
 */
void parec_log4c_init();
/**
 * The parec_log4c_done() function destroys the context of the
 * common logging facility, closing open file handles, etc.
 */
void parec_log4c_done();

/*
 * Log levels for the parec_log4c_printf() function, however
 * it is recommended to use the provided macros!
 */
typedef enum {
    PAREC_LOG4C_DEBUG,
    PAREC_LOG4C_INFO,
    PAREC_LOG4C_WARN,
    PAREC_LOG4C_ERROR,
    PAREC_LOG4C_NONE,
    PAREC_LOG4C_UNKNOWN
} parec_log4c_log_level;

void parec_log4c_printf(parec_log4c_log_level loglevel, 
    const char *file, const char *function, const int line,
    const char *format, ...);

#define parec_log4c_DEBUG(fmt, ...) parec_log4c_printf(PAREC_LOG4C_DEBUG, __FILE__, __func__, __LINE__, fmt,##__VA_ARGS__)
#define parec_log4c_INFO(fmt, ...) parec_log4c_printf(PAREC_LOG4C_INFO, __FILE__, __func__, __LINE__, fmt,##__VA_ARGS__)
#define parec_log4c_WARN(fmt, ...) parec_log4c_printf(PAREC_LOG4C_WARN, __FILE__, __func__, __LINE__, fmt,##__VA_ARGS__)
#define parec_log4c_ERROR(fmt, ...) parec_log4c_printf(PAREC_LOG4C_ERROR, __FILE__, __func__, __LINE__, fmt,##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* _PAREC_LOG4C_H */
