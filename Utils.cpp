#include <sys/types.h>
#include <fcntl.h>

#include "Utils.h"
#include "Log.h"

#define MAX_SEGMENT_INTERVAL 10 * 4096  // 10 pages

int loadMemoryMap(pid_t pid, MemoryMap *map, int *count) {
#ifdef __LP64__
    char raw[64000];
#else
    char raw[8000];
#endif
    char name[MAX_NAME_LENGTH];
    char *p;
    unsigned long start, end;
    MemoryMap *m;
    int itemCount = 0, fd, returnValue;

    sprintf(raw, "/proc/%d/maps", pid);
    fd = open(raw, O_RDONLY);
    if (fd < 0) {
        GLogError("Utils", "Open process map file failed. ");
        return -1;
    }

    memset(raw, 0, sizeof(raw));
    p = raw;
    while(true) {
        returnValue = read(fd, p, sizeof(raw) - (p - raw));
        if (returnValue < 0) {
            GLogError("Utils", "Read process map file failed. ");
                return -1;
        }
        if (returnValue == 0) {
            break;
        }
        p += returnValue;
        if (p > raw + sizeof(raw)) {
            GLogError("Utils", "Read map file data overflow. ");
            return -1;
        }
    }
    close(fd);

    p = strtok(raw, "\n");
    m = map;
    while (p) {
        GLogInfo("Utils", "-------maps: %s, current count: %d", p, itemCount);
#ifdef __LP64__
        returnValue = sscanf(p, "%012lx-%012lx %*s %*s %*s %*s %s\n", &start, &end, name);
#else
        returnValue = sscanf(p, "%08lx-%08lx %*s %*s %*s %*s %s\n", &start, &end, name);
#endif
        p = strtok(NULL, "\n");
        if (returnValue == 2) {
            m = map + itemCount++;
            m->start = start;
            m->end = end;
            strcpy(m->name, MEMORY_ONLY);
            continue;
        }

        int i = 0;
        for (i = itemCount - 1; i >= 0; i--) {
            m = map + i;
            if (!strcmp(m->name, name)) {
                break;
            }
        }

        if (i >= 0) {
#ifdef __LP64__
            // if the interval between two segments map of the same loadable module is too large,
            // we ignore the first segment map
            if (start - m->start > MAX_SEGMENT_INTERVAL) {
                m->start = start;
                m->end = end;
                continue;
            }
#endif
            if (start < m->start) {
                m->start = start;
            }
            if (end > m->end) {
                m->end = end;
            }
        } else {
            m = map + itemCount++;
            m->start = start;
            m->end = end;
            strcpy(m->name, name);
        }
    }

    *count = itemCount;
    return 0;
}

