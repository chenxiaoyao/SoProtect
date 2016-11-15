#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef _UTILS_H_
#define _UTILS_H_

#define MAX_NAME_LENGTH 256
#define MEMORY_ONLY "[memory]"

typedef struct {
    char name[MAX_NAME_LENGTH];
    unsigned long start, end; // memory address start/end of components
} MemoryMap;

#ifdef __cplusplus
extern "C" {
#endif

    int loadMemoryMap(pid_t pid, MemoryMap *map, int *count);

#ifdef __cplusplus
}
#endif

#endif
