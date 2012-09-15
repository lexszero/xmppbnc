#ifndef COMMON_H
#define COMMON_H

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <glib.h>
#include <loudmouth/loudmouth.h>

#include "config.h"

#define _LOGF(fmt, args...) printf("%s:%i %s(): " fmt "\n", __FILE__, __LINE__, __func__,  ##args)
#if DEBUG_LEVEL >= 1
#define LOGFD(...) _LOGF(__VA_ARGS__)
#else
#define LOGFD(...)
#endif
#define LOGF(...) _LOGF(__VA_ARGS__)

#endif /* COMMON_H */
