/*
 * log4c -- simple logging library for C
 *
 * Copyright (c) Akos FROHNER <akos@frohner.hu> 2009.
 * License: LGPLv2.1
 */

#include <stdio.h>                  /* for NULL */
#include <stdlib.h>                 /* for free() */
#include <string.h>                 /* for strcmpy() and strlen() */
#include <strings.h>                /* for rindex() */
#include <stdarg.h>                 /* for va_list */
#include <time.h>                   /* for time/localtime/strftime */

#include "parec_log4c.h"

static parec_log4c_log_level parec_log4c_current_loglevel = PAREC_LOG4C_UNKNOWN;
static FILE *parec_log4c_current_logfile = NULL;

static char *parec_log4c_loglevel_names[] = {
    "DEBUG",
    "INFO",
    "WARN",
    "ERROR"
};

#ifndef __GNUC__
#define __attribute__(x)
#endif
void parec_log4c_init(void) __attribute__((__constructor__));
void parec_log4c_done(void) __attribute__((__destructor__));

void parec_log4c_init(void) {
    char *envar;

    parec_log4c_current_loglevel = PAREC_LOG4C_NONE;

    envar = getenv(PAREC_LOG_LEVEL);
    if (envar != NULL) {
        if(strncmp(envar, parec_log4c_loglevel_names[PAREC_LOG4C_DEBUG], 
                   strlen(parec_log4c_loglevel_names[PAREC_LOG4C_DEBUG])) == 0) {
            parec_log4c_current_loglevel = PAREC_LOG4C_DEBUG;
        }
        else if(strncmp(envar, parec_log4c_loglevel_names[PAREC_LOG4C_INFO], 
                        strlen(parec_log4c_loglevel_names[PAREC_LOG4C_INFO])) == 0) {
            parec_log4c_current_loglevel = PAREC_LOG4C_INFO;
        }
        else if(strncmp(envar, parec_log4c_loglevel_names[PAREC_LOG4C_WARN], 
                        strlen(parec_log4c_loglevel_names[PAREC_LOG4C_WARN])) == 0) {
            parec_log4c_current_loglevel = PAREC_LOG4C_WARN;
        }
        else if(strncmp(envar, parec_log4c_loglevel_names[PAREC_LOG4C_ERROR], 
                        strlen(parec_log4c_loglevel_names[PAREC_LOG4C_ERROR])) == 0) {
            parec_log4c_current_loglevel = PAREC_LOG4C_ERROR;
        }
        else {
            parec_log4c_current_loglevel = PAREC_LOG4C_NONE;
        }
    }

    if (parec_log4c_current_loglevel < PAREC_LOG4C_NONE) {
        envar = getenv(PAREC_LOG_FILE);
        if (envar != NULL) {
            parec_log4c_current_logfile = fopen(envar, "a+");
            // returns NULL on error, in which case we will
            // log to the stderr anyway
        }
    }
}

void parec_log4c_done(void) {
    if (parec_log4c_current_logfile != NULL) {
        fclose(parec_log4c_current_logfile);
        parec_log4c_current_logfile = NULL;
    }
}

/* The goal: 2009-07-27 10:40:01,655 */
#define PAREC_LOG4C_TIME_FORMAT "%F %T"
#define PAREC_LOG4C_TIME_LENGTH 25
static char parec_log4c_time[PAREC_LOG4C_TIME_LENGTH];

void parec_log4c_printf(parec_log4c_log_level loglevel, 
    const char *file, const char *function, const int line,
    const char *format, ...) 
{
    if (loglevel > PAREC_LOG4C_ERROR) return;
    if (parec_log4c_current_loglevel > loglevel) return;

    va_list ap;
    FILE *logfile = parec_log4c_current_logfile;
    time_t logt;
    struct tm *logtm;
    const char *basename;

    if (NULL == logfile) logfile = stderr;
    
    logt = time(NULL);
    logtm = localtime(&logt);
    if (logtm == NULL) {
        parec_log4c_time[0] = '\0';
    }
    else if(strftime(parec_log4c_time, sizeof(parec_log4c_time), PAREC_LOG4C_TIME_FORMAT, logtm) == 0) {
        parec_log4c_time[0] = '\0';
    }
    
    basename = rindex(file, '/');
    if (NULL != basename) {
        basename++; // skip to after the slash
    }
    else {
        basename = file;
    }

	va_start(ap, format);
    fprintf(logfile, "%s %s - ", parec_log4c_time, parec_log4c_loglevel_names[loglevel]);
    vfprintf(logfile, format, ap);
    fprintf(logfile, " - %s#%s:%d\n", basename, function, line);
    fflush(logfile);
	va_end(ap);
}

/* End of file. */
