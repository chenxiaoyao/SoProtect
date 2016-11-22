#ifndef __GDLFCN_H__
#define __GDLFCN_H__

#define __DLFCN_H__

#include <sys/cdefs.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *dli_fname;  /* Pathname of shared object that
                               contains address */
    void       *dli_fbase;  /* Address at which shared object
                               is loaded */
    const char *dli_sname;  /* Name of nearest symbol with address
                               lower than addr */
    void       *dli_saddr;  /* Exact address of symbol named
                               in dli_sname */
} Dl_info;

void*        gdlopen(const char*  filename, int flag, unsigned long offset);
int          gdlclose(void*  handle);
const char*  gdlerror(void);
void*        gdlsym(void*  handle, const char*  symbol);
int          gdladdr(const void* addr, Dl_info *info);

// declare standard dl function
void*        dlopen(const char*  filename, int flag);
int          dlclose(void*  handle);
const char*  dlerror(void);
void*        dlsym(void*  handle, const char*  symbol);
int          dladdr(const void* addr, Dl_info *info);

#ifdef __cplusplus
}
#endif

enum {
#if defined(__LP64__)
  RTLD_NOW  = 2,
#else
  RTLD_NOW  = 0,
#endif
  RTLD_LAZY = 1,

  RTLD_LOCAL  = 0,
#if defined(__LP64__)
  RTLD_GLOBAL = 0x00100,
#else
  RTLD_GLOBAL = 2,
#endif
  RTLD_NOLOAD = 4,
};

#if defined (__LP64__)
#define RTLD_DEFAULT  ((void*) 0)
#define RTLD_NEXT     ((void*) -1L)
#else
#define RTLD_DEFAULT  ((void*) 0xffffffff)
#define RTLD_NEXT     ((void*) 0xfffffffe)
#endif

#endif /* __DLFCN_H */


