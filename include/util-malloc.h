
#ifndef UTIL_MALLOC_H
#define UTIL_MALLOC_H
#include <stdio.h>
#include <stdlib.h>

void *
REALLOCARRAY(void *p, size_t count, size_t size);

void *
CALLOC(size_t count, size_t size);

void *
MALLOC(size_t size);

void *
REALLOC(void *p, size_t size);

char *
STRDUP(const char *str);



#endif
