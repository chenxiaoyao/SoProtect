#ifndef __GDLFCN_H__
#define __GDLFCN_H__

#include <sys/cdefs.h>
#include <dlfcn.h>

#ifdef __cplusplus
extern "C" {
#endif

void*        gdlopen(const char*  filename, int flag, unsigned long offset);
int          gdlclose(void*  handle);
const char*  gdlerror(void);
void*        gdlsym(void*  handle, const char*  symbol);
int          gdladdr(const void* addr, Dl_info *info);

#ifdef __cplusplus
}
#endif

#define RTLD_DEFAULT  ((void*) 0xffffffff)
#define RTLD_NEXT     ((void*) 0xfffffffe)


#endif /* __DLFCN_H */


